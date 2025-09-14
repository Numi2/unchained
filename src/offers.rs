use anyhow::Result;
use bytes::Bytes;
use hyper::{Body, Request as HRequest, Response as HResponse, StatusCode, Method};
use hyper::service::{make_service_fn, service_fn};
use std::sync::Arc;
use crate::storage::Store;
use crate::network::NetHandle;

#[derive(Clone)]
pub struct OffersService {
    db: Arc<Store>,
    cfg: crate::config::Offers,
    net: NetHandle,
}

impl OffersService {
    pub fn new(db: Arc<Store>, cfg: crate::config::Offers, net: NetHandle) -> Self {
        Self { db, cfg, net }
    }
}

/// SSE stream of verified offers stored under CF `offers` with key prefix ts||hash.
/// Streams JSON Lines of OfferDocV1. Optional redaction via `?redact_sig=1`.
pub async fn serve(cfg: crate::config::Offers, db: Arc<Store>, net: NetHandle) -> Result<()> {
    let svc = Arc::new(OffersService::new(db, cfg, net));
    use std::net::TcpListener as StdTcpListener;
    let bind_addr = svc.cfg.bind.clone();
    tokio::spawn(async move {
        let listener = match StdTcpListener::bind(&bind_addr) { Ok(l) => l, Err(e) => { eprintln!("offers api bind error: {}", e); return; } };
        listener.set_nonblocking(true).ok();
        let make = make_service_fn(move |_conn| {
            let svc = svc.clone();
            async move {
                Ok::<_, std::convert::Infallible>(service_fn(move |req: HRequest<Body>| {
                    let svc = svc.clone();
                    async move {
                        let method = req.method().clone();
                        let path = req.uri().path().to_string();
                        let resp = match (method, path.as_str()) {
                            (Method::GET, "/offers") => {
                                let q = req.uri().query().unwrap_or("");
                                if q.contains("stream=1") { sse_offers(&svc, req).await } else { get_offers(&svc, req).await }
                            },
                            _ => not_found(),
                        };
                        Ok::<_, std::convert::Infallible>(resp)
                    }
                }))
            }
        });
        if let Err(e) = hyper::Server::from_tcp(listener).unwrap().serve(make).await { eprintln!("offers api serve error: {}", e); }
    });
    Ok(())
}

async fn sse_offers(svc: &Arc<OffersService>, req: HRequest<Body>) -> HResponse<Body> {
    fn now_millis() -> u128 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
    }

    // Options
    let params = parse_query(req.uri().query().unwrap_or(""));
    let redact_sig = params.get("redact_sig").map(|v| v == "1").unwrap_or(false);
    // Resume cursor: since=... or Last-Event-ID header
    let mut since_millis: u128 = params.get("since").and_then(|s| s.parse::<u128>().ok()).unwrap_or(0);
    if since_millis == 0 {
        if let Some(h) = req.headers().get("last-event-id").or_else(|| req.headers().get("Last-Event-ID")) {
            if let Ok(s) = h.to_str() { since_millis = s.parse::<u128>().unwrap_or(0); }
        }
    }

    let (mut tx, body) = Body::channel();

    // Build initial snapshot: either replay from since (bounded), or recent tail
    let initial_pairs: Vec<(u128, Vec<u8>)> = {
        let cf = if let Some(cf) = svc.db.db.cf_handle("offers") { cf } else { return err_response("offers CF missing", 500) };
        if since_millis > 0 {
            // Replay forward from since (inclusive), cap to a reasonable burst
            let mut ro = rocksdb::ReadOptions::default();
            let lower = since_millis.to_le_bytes().to_vec();
            ro.set_iterate_lower_bound(lower.clone());
            let it = svc.db.db.iterator_cf_opt(cf, ro, rocksdb::IteratorMode::From(&since_millis.to_le_bytes(), rocksdb::Direction::Forward));
            let mut out = Vec::new();
            for item in it.take(1000) {
                if let Ok((k, v)) = item {
                    if k.len() >= 16 {
                        let mut ts_arr = [0u8;16]; ts_arr.copy_from_slice(&k[0..16]);
                        let ts = u128::from_le_bytes(ts_arr);
                        out.push((ts, v.to_vec()));
                    }
                }
            }
            out
        } else {
            // Tail snapshot: last 200
            let iter = svc.db.db.iterator_cf(cf, rocksdb::IteratorMode::End);
            let mut tmp: Vec<(u128, Vec<u8>)> = Vec::new();
            for item in iter.take(200) {
                if let Ok((k, v)) = item {
                    if k.len() >= 16 {
                        let mut ts_arr = [0u8;16]; ts_arr.copy_from_slice(&k[0..16]);
                        let ts = u128::from_le_bytes(ts_arr);
                        tmp.push((ts, v.to_vec()));
                    }
                }
            }
            tmp.reverse();
            tmp
        }
    };

    // Spawn a task to stream snapshot then live updates + keep-alives
    let mut rx = svc.net.offers_subscribe();
    tokio::spawn(async move {
        // Send initial snapshot
        for (ts, v) in initial_pairs {
            if let Ok(mut offer) = bincode::deserialize::<crate::wallet::OfferDocV1>(&v) {
                if redact_sig { offer.sig = Vec::new(); }
                if let Ok(js) = serde_json::to_vec(&offer) {
                    let mut buf = String::new();
                    buf.push_str(&format!("id: {}\n", ts));
                    buf.push_str("data: ");
                    buf.push_str(&String::from_utf8_lossy(&js));
                    buf.push_str("\n\n");
                    if tx.send_data(Bytes::from(buf)).await.is_err() { return; }
                }
            }
        }

        // Periodic keep-alives
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // Send SSE comment to keep connection alive
                    if tx.send_data(Bytes::from(":keep-alive\n\n")).await.is_err() { break; }
                }
                recv = rx.recv() => {
                    match recv {
                        Ok(mut offer) => {
                            if redact_sig { offer.sig = Vec::new(); }
                            let id_ts = now_millis();
                            if let Ok(js) = serde_json::to_vec(&offer) {
                                let mut buf = String::new();
                                buf.push_str(&format!("id: {}\n", id_ts));
                                buf.push_str("data: ");
                                buf.push_str(&String::from_utf8_lossy(&js));
                                buf.push_str("\n\n");
                                if tx.send_data(Bytes::from(buf)).await.is_err() { break; }
                            }
                        }
                        Err(_) => { break; }
                    }
                }
            }
        }
    });

    let mut resp = HResponse::new(body);
    let headers = resp.headers_mut();
    headers.insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("text/event-stream"));
    headers.insert(hyper::header::CACHE_CONTROL, hyper::header::HeaderValue::from_static("no-cache"));
    headers.insert(hyper::header::CONNECTION, hyper::header::HeaderValue::from_static("keep-alive"));
    headers.insert(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN, hyper::header::HeaderValue::from_static("*"));
    resp
}

async fn get_offers(svc: &Arc<OffersService>, req: HRequest<Body>) -> HResponse<Body> {
    // Query params: limit (u64), since (millis, inclusive), redact_sig=1
    let q = req.uri().query().unwrap_or("");
    let params = parse_query(q);
    let limit = params.get("limit").and_then(|s| s.parse::<u64>().ok()).unwrap_or(100);
    let since = params.get("since").and_then(|s| s.parse::<u128>().ok()).unwrap_or(0);
    let redact_sig = params.get("redact_sig").map(|v| v == "1").unwrap_or(false);
    let cf = match svc.db.db.cf_handle("offers") { Some(cf) => cf, None => return err_response("offers CF missing", 500) };

    // Constant-time pagination using prefix-ordered keys ts||hash
    let mut ro = rocksdb::ReadOptions::default();
    ro.set_iterate_lower_bound(since.to_le_bytes().to_vec());
    let it = svc.db.db.iterator_cf_opt(cf, ro, rocksdb::IteratorMode::From(&since.to_le_bytes(), rocksdb::Direction::Forward));
    let mut out: Vec<serde_json::Value> = Vec::new();
    for item in it.take(limit as usize) {
        if let Ok((_k, v)) = item {
            if let Ok(mut offer) = bincode::deserialize::<crate::wallet::OfferDocV1>(&v) {
                if redact_sig { offer.sig = Vec::new(); }
                out.push(serde_json::to_value(offer).unwrap_or_else(|_| serde_json::json!({})));
            }
        }
    }
    json_response(&out, 200)
}

fn json_response<T: serde::Serialize>(val: &T, status: u16) -> HResponse<Body> {
    let body = serde_json::to_vec(val).unwrap_or_else(|_| b"[]".to_vec());
    let mut resp = HResponse::new(Body::from(body));
    *resp.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
    resp.headers_mut().insert(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN, hyper::header::HeaderValue::from_static("*"));
    resp
}

fn err_response(msg: &str, status: u16) -> HResponse<Body> { json_response(&serde_json::json!({"error": msg}), status) }
fn not_found() -> HResponse<Body> { err_response("not found", 404) }

fn parse_query(q: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for part in q.split('&') {
        if part.is_empty() { continue; }
        if let Some((k,v)) = part.split_once('=') { map.insert(k.to_string(), v.to_string()); } else { map.insert(part.to_string(), String::new()); }
    }
    map
}


