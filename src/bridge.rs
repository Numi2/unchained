// bridge.rs
// Unchained ↔ Sui bridge: state, types, RPC, and basic flows.

use serde::{Serialize, Deserialize};
use std::sync::{Arc, Mutex};
use anyhow::{Result, anyhow, Context};
use crate::{storage::Store, crypto::Address};
use crate::{wallet::Wallet, network::NetHandle};
use blake3;
use std::collections::VecDeque;
use rocksdb;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeOutTransaction {
    pub from: Address,
    pub amount: u64,
    pub sui_recipient: String,
    pub bridge_fee: u64,
    pub nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeInTransaction {
    pub to: Address,
    pub amount: u64,
    pub sui_tx_hash: String,
    pub sui_burn_proof: Vec<u8>,
    pub nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PendingStatus { Submitted, ConfirmedOnSui, Failed(String) }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingBridgeOp {
    pub id: String,
    pub from: Address,
    pub amount: u64,
    pub sui_recipient: String,
    pub created_at: u64,
    pub nonce: u64,
    pub status: PendingStatus,
    /// Last attempt timestamp (secs since epoch) for retry backoff
    #[serde(default)]
    pub last_attempt: u64,
    /// Number of retry attempts so far
    #[serde(default)]
    pub retry_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeState {
    pub total_locked: u64,
    pub total_unlocked: u64,
    pub bridge_enabled: bool,
    pub min_bridge_amount: u64,
    pub max_bridge_amount: u64,
    pub bridge_fee_basis_points: u64,
    #[serde(default)]
    pub epoch_global_volume: u64,
    #[serde(default)]
    pub epoch_number: u64,
    /// Rolling per-address 24h window (address hex -> deque of (ts, amount))
    #[serde(default)]
    pub per_addr_window: std::collections::HashMap<String, VecDeque<(u64, u64)>>,
    /// Rolling global 24h window of (ts, amount)
    #[serde(default)]
    pub global_window: VecDeque<(u64, u64)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BridgeEvent {
    TokensLocked { amount: u64, sui_recipient: String, tx_hash: String, op_id: String },
    TokensUnlocked { amount: u64, recipient: Address, sui_tx_hash: String },
    BridgeError { error: String, context: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeStatus {
    pub total_locked: u64,
    pub total_unlocked: u64,
    pub bridge_enabled: bool,
    pub pending_count: u64,
    pub min_amount: u64,
    pub max_amount: u64,
    pub fee_basis_points: u64,
}

pub struct BridgeService {
    db: Arc<Store>,
    cfg: crate::config::BridgeConfig,
    state: Mutex<BridgeState>,
    wallet: Arc<Wallet>,
    net: NetHandle,
}

impl BridgeService {
    pub fn new(db: Arc<Store>, cfg: crate::config::BridgeConfig, wallet: Arc<Wallet>, net: NetHandle) -> Self {
        // Load from DB or init defaults
        let mut state = BridgeState {
            total_locked: 0,
            total_unlocked: 0,
            bridge_enabled: cfg.bridge_enabled,
            min_bridge_amount: cfg.min_amount,
            max_bridge_amount: cfg.max_amount,
            bridge_fee_basis_points: cfg.fee_basis_points,
            epoch_global_volume: 0,
            epoch_number: 0,
            per_addr_window: std::collections::HashMap::new(),
            global_window: VecDeque::new(),
        };
        if let Ok(Some(persisted)) = db.get::<BridgeState>("bridge_state", b"state") {
            state = persisted;
        }
        Self { db, cfg, state: Mutex::new(state), wallet, net }
    }

    fn persist_state(&self) -> Result<()> { self.db.put("bridge_state", b"state", &self.state.lock().unwrap().clone()) }

    pub fn get_status(&self) -> Result<BridgeStatus> {
        let st = self.state.lock().unwrap().clone();
        // Count pendings
        let pending_cf = self.db.db.cf_handle("bridge_pending").ok_or_else(|| anyhow!("bridge_pending CF missing"))?;
        let iter = self.db.db.iterator_cf(pending_cf, rocksdb::IteratorMode::Start);
        let mut cnt = 0u64;
        for item in iter {
            if let Ok((_k, v)) = item {
                if let Ok(op) = bincode::deserialize::<PendingBridgeOp>(&v) {
                    if matches!(op.status, PendingStatus::Submitted) { cnt = cnt.saturating_add(1); }
                }
            }
        }
        crate::metrics::BRIDGE_PENDING_OPS.set(cnt as i64);
        Ok(BridgeStatus {
            total_locked: st.total_locked,
            total_unlocked: st.total_unlocked,
            bridge_enabled: st.bridge_enabled,
            pending_count: cnt,
            min_amount: st.min_bridge_amount,
            max_amount: st.max_bridge_amount,
            fee_basis_points: st.bridge_fee_basis_points,
        })
    }

    pub fn list_pending(&self) -> Result<Vec<PendingBridgeOp>> {
        let cf = self.db.db.cf_handle("bridge_pending").ok_or_else(|| anyhow!("bridge_pending CF missing"))?;
        let iter = self.db.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut v = Vec::new();
        for item in iter { let (_k, val) = item?; if let Ok(op) = bincode::deserialize::<PendingBridgeOp>(&val) { v.push(op); } }
        Ok(v)
    }

    pub fn is_sui_tx_processed(&self, sui_tx_hash: &str) -> Result<bool> {
        let cf = self.db.db.cf_handle("bridge_processed_sui").ok_or_else(|| anyhow!("bridge_processed_sui CF missing"))?;
        Ok(self.db.db.get_cf(cf, sui_tx_hash.as_bytes())?.is_some())
    }
}

// --- Minimal HTTP RPC (JSON) ---

#[derive(Deserialize)]
struct BridgeOutReq { amount: u64, sui_recipient: String }

#[derive(Serialize)]
struct SubmitResp { tx_hash: String }

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status")]
pub enum BridgeOutResult {
    Locked { tx_hash: String },
    Pending { op_id: String },
}

// Direct submission helper for CLI: perform bridge_out without HTTP
pub async fn submit_bridge_out_direct(
    cfg: crate::config::BridgeConfig,
    db: Arc<Store>,
    wallet: Arc<Wallet>,
    net: NetHandle,
    amount: u64,
    sui_recipient: String,
)
-> Result<BridgeOutResult> {
    let svc = Arc::new(BridgeService::new(db, cfg, wallet, net));
    let req = BridgeOutReq { amount, sui_recipient };
    bridge_out_submit(&svc, req).await
}

pub async fn serve(cfg: crate::config::BridgeConfig, db: Arc<Store>, wallet: Arc<Wallet>, net: NetHandle) -> Result<()> {
    use hyper::{Server, Request, Body, Method};
    use hyper::service::{make_service_fn, service_fn};
    let svc = Arc::new(BridgeService::new(db.clone(), cfg.clone(), wallet, net));

    let svc_http = svc.clone();
    let make = make_service_fn(move |_conn| {
        let svc = svc_http.clone();
        async move {
            Ok::<_, std::convert::Infallible>(service_fn(move |req: Request<Body>| {
                let svc = svc.clone();
                async move {
                    let path = req.uri().path().to_string();
                    let method = req.method().clone();
                    let authorized = authorize_admin(&svc.cfg, &req);
                    let resp = match (method, path.as_str()) {
                        (Method::POST, "/admin/bridge_pause") => {
                            if !authorized { return Ok::<_, std::convert::Infallible>(err_response("unauthorized", 401)); }
                            set_bridge_paused(&svc, true);
                            json_response(&serde_json::json!({"ok": true}), 200)
                        },
                        (Method::POST, "/admin/bridge_unpause") => {
                            if !authorized { return Ok::<_, std::convert::Infallible>(err_response("unauthorized", 401)); }
                            set_bridge_paused(&svc, false);
                            json_response(&serde_json::json!({"ok": true}), 200)
                        },
                        (Method::GET, "/bridge_events") => {
                            match read_events(&svc.db, 200) {
                                Ok(ev) => json_response(&ev, 200),
                                Err(e) => err_response(&format!("{}", e), 500),
                            }
                        },
                        (Method::POST, "/admin/bridge_set_params") => {
                            if !authorized { return Ok::<_, std::convert::Infallible>(err_response("unauthorized", 401)); }
                            let body = hyper::body::to_bytes(req.into_body()).await.unwrap_or_default();
                            #[derive(Deserialize)]
                            struct Params { min_amount: Option<u64>, max_amount: Option<u64>, fee_basis_points: Option<u64>, per_address_daily_cap: Option<u64>, global_daily_cap: Option<u64> }
                            match serde_json::from_slice::<Params>(&body) {
                                Ok(p) => {
                                    let mut st = svc.state.lock().unwrap();
                                    if let Some(v) = p.min_amount { st.min_bridge_amount = v; }
                                    if let Some(v) = p.max_amount { st.max_bridge_amount = v; }
                                    if let Some(v) = p.fee_basis_points { st.bridge_fee_basis_points = v; }
                                    // Acknowledge caps fields to avoid dead_code warnings (not applied dynamically yet)
                                    let _ = p.per_address_daily_cap;
                                    let _ = p.global_daily_cap;
                                    // persist
                                    let _ = svc.persist_state();
                                    json_response(&serde_json::json!({"ok": true}), 200)
                                },
                                Err(e) => err_response(&format!("bad request: {}", e), 400),
                            }
                        },
                        (Method::POST, "/admin/bridge_reset_rates") => {
                            if !authorized { return Ok::<_, std::convert::Infallible>(err_response("unauthorized", 401)); }
                            {
                                let mut st = svc.state.lock().unwrap();
                                st.per_addr_window.clear();
                                st.global_window.clear();
                                let _ = svc.persist_state();
                            }
                            json_response(&serde_json::json!({"ok": true}), 200)
                        },
                        (Method::POST, p) if p.starts_with("/admin/bridge_pending_requeue/") => {
                            if !authorized { return Ok::<_, std::convert::Infallible>(err_response("unauthorized", 401)); }
                            let id = p.trim_start_matches("/admin/bridge_pending_requeue/");
                            let cf = if let Some(cf) = svc.db.db.cf_handle("bridge_pending") { cf } else { return Ok::<_, std::convert::Infallible>(err_response("bridge_pending CF missing", 500)); };
                            match svc.db.db.get_cf(cf, id.as_bytes()) {
                                Ok(Some(bytes)) => {
                                    if let Ok(mut op) = bincode::deserialize::<PendingBridgeOp>(&bytes) {
                                        op.status = PendingStatus::Submitted;
                                        op.last_attempt = 0;
                                        op.retry_count = 0;
                                        if let Ok(ser) = bincode::serialize(&op) { let _ = svc.db.db.put_cf(cf, id.as_bytes(), &ser); }
                                        json_response(&serde_json::json!({"ok": true}), 200)
                                    } else { err_response("malformed pending op", 500) }
                                },
                                Ok(None) => err_response("not found", 404),
                                Err(e) => err_response(&format!("{}", e), 500),
                            }
                        },
                        (Method::POST, p) if p.starts_with("/admin/bridge_pending_confirm/") => {
                            if !authorized { return Ok::<_, std::convert::Infallible>(err_response("unauthorized", 401)); }
                            let id = p.trim_start_matches("/admin/bridge_pending_confirm/");
                            let cf = if let Some(cf) = svc.db.db.cf_handle("bridge_pending") { cf } else { return Ok::<_, std::convert::Infallible>(err_response("bridge_pending CF missing", 500)); };
                            match svc.db.db.get_cf(cf, id.as_bytes()) {
                                Ok(Some(bytes)) => {
                                    if let Ok(mut op) = bincode::deserialize::<PendingBridgeOp>(&bytes) {
                                        op.status = PendingStatus::ConfirmedOnSui;
                                        if let Ok(ser) = bincode::serialize(&op) { let _ = svc.db.db.put_cf(cf, id.as_bytes(), &ser); }
                                        crate::metrics::BRIDGE_PENDING_CONFIRMED.inc();
                                        json_response(&serde_json::json!({"ok": true}), 200)
                                    } else { err_response("malformed pending op", 500) }
                                },
                                Ok(None) => err_response("not found", 404),
                                Err(e) => err_response(&format!("{}", e), 500),
                            }
                        },
                        (Method::POST, p) if p.starts_with("/admin/bridge_pending_fail/") => {
                            if !authorized { return Ok::<_, std::convert::Infallible>(err_response("unauthorized", 401)); }
                            let id = p.trim_start_matches("/admin/bridge_pending_fail/");
                            let reason = "failed";
                            let cf = if let Some(cf) = svc.db.db.cf_handle("bridge_pending") { cf } else { return Ok::<_, std::convert::Infallible>(err_response("bridge_pending CF missing", 500)); };
                            match svc.db.db.get_cf(cf, id.as_bytes()) {
                                Ok(Some(bytes)) => {
                                    if let Ok(mut op) = bincode::deserialize::<PendingBridgeOp>(&bytes) {
                                        op.status = PendingStatus::Failed(reason.to_string());
                                        if let Ok(ser) = bincode::serialize(&op) { let _ = svc.db.db.put_cf(cf, id.as_bytes(), &ser); }
                                        crate::metrics::BRIDGE_PENDING_FAILED.inc();
                                        json_response(&serde_json::json!({"ok": true}), 200)
                                    } else { err_response("malformed pending op", 500) }
                                },
                                Ok(None) => err_response("not found", 404),
                                Err(e) => err_response(&format!("{}", e), 500),
                            }
                        },
                        (Method::GET, "/get_bridge_status") => {
                            match svc.get_status() {
                                Ok(st) => json_response(&st, 200),
                                Err(e) => err_response(&format!("{}", e), 500),
                            }
                        },
                        (Method::GET, "/get_pending_bridge_ops") => {
                            match svc.list_pending() {
                                Ok(v) => json_response(&v, 200),
                                Err(e) => err_response(&format!("{}", e), 500),
                            }
                        },
                        (Method::GET, p) if p.starts_with("/is_sui_tx_processed/") => {
                            let h = p.trim_start_matches("/is_sui_tx_processed/");
                            match svc.is_sui_tx_processed(h) {
                                Ok(b) => json_response(&serde_json::json!({"processed": b}), 200),
                                Err(e) => err_response(&format!("{}", e), 500),
                            }
                        },
                        (Method::POST, "/bridge_out") => {
                            let whole = hyper::body::to_bytes(req.into_body()).await.unwrap_or_default();
                            crate::metrics::BRIDGE_OUT_REQUESTS.inc();
                            match serde_json::from_slice::<BridgeOutReq>(&whole) {
                                Ok(reqo) => {
                                    match bridge_out_submit(&svc, reqo).await {
                                        Ok(BridgeOutResult::Locked { tx_hash }) => json_response(&SubmitResp { tx_hash }, 200),
                                        Ok(BridgeOutResult::Pending { op_id }) => json_response(&serde_json::json!({"pending": true, "op_id": op_id}), 200),
                                        Err(e) => err_response(&format!("{}", e), 400),
                                    }
                                },
                                Err(e) => err_response(&format!("bad request: {}", e), 400),
                            }
                        },
                        (Method::POST, "/bridge_in_verify") => {
                            let body = hyper::body::to_bytes(req.into_body()).await.unwrap_or_default();
                            match verify_sui_burn_proof(&svc, &body).await {
                                Ok(_) => json_response(&serde_json::json!({"ok": true}), 200),
                                Err(e) => err_response(&format!("{}", e), 400),
                            }
                        },
                        (Method::POST, "/bridge_in") => {
                            let body = hyper::body::to_bytes(req.into_body()).await.unwrap_or_default();
                            match bridge_in_submit(&svc, &body).await {
                                Ok(txh) => json_response(&serde_json::json!({"tx_hash": txh}), 200),
                                Err(e) => err_response(&format!("{}", e), 400),
                            }
                        },
                        _ => err_response("not found", 404),
                    };
                    Ok::<_, std::convert::Infallible>(resp)
                }
            }))
        }
    });

    let addr: std::net::SocketAddr = cfg.rpc_bind.parse().context("bridge rpc bind parse")?;
    tokio::spawn(async move {
        if let Err(e) = Server::bind(&addr).serve(make).await { eprintln!("bridge rpc serve error: {}", e); }
    });
    // Background processor: retry Submitted ops automatically and expire long-lived ones
    {
        let svc_h = svc.clone();
        let cfg_h = cfg.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(15)).await; // drive retries promptly
                // Open fresh CF handles inside each loop iteration and avoid holding them across awaits
                if let Some(cf_name) = Some("bridge_pending") {
                    let cf = match svc_h.db.db.cf_handle(cf_name) { Some(c) => c, None => continue };
                    let iter = svc_h.db.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
                    let cutoff = now.saturating_sub(cfg_h.rate_window_secs);
                    for item in iter {
                        if let Ok((k, v)) = item {
                            if let Ok(mut op) = bincode::deserialize::<PendingBridgeOp>(&v) {
                                // Expire too old Submitted ops (skip if already finalized via op->coins mapping)
                                if matches!(op.status, PendingStatus::Submitted) && op.created_at < cutoff {
                                    if let Some(cf_oc) = svc_h.db.db.cf_handle("bridge_op_coins") {
                                        if svc_h.db.db.get_cf(cf_oc, &k).ok().flatten().is_some() { continue; }
                                    }
                                    op.status = PendingStatus::Failed("expired".to_string());
                                    if let Some(cf2) = svc_h.db.db.cf_handle("bridge_pending") {
                                        if let Ok(ser) = bincode::serialize(&op) { let _ = svc_h.db.db.put_cf(cf2, &k, &ser); }
                                    }
                                    crate::metrics::BRIDGE_PENDING_EXPIRED.inc();
                                    continue;
                                }
                                // Retry Submitted ops with exponential backoff
                                if matches!(op.status, PendingStatus::Submitted) {
                                    // Skip if already processed (has coins mapping)
                                    if let Some(cf_oc) = svc_h.db.db.cf_handle("bridge_op_coins") {
                                        if svc_h.db.db.get_cf(cf_oc, &k).ok().flatten().is_some() { continue; }
                                    }
                                    let attempts = op.retry_count;
                                    let backoff_secs = u64::min(600, 5 * (1u64 << attempts.min(10)));
                                    let last = op.last_attempt;
                                    if last == 0 || now.saturating_sub(last) >= backoff_secs {
                                        // Reattempt the wallet send to vault
                                        // Proactively nudge network to fetch latest headers and nearby leaves/selected
                                        let _ = svc_h.net.request_latest_epoch().await;
                                        if let Ok(Some(latest_anchor)) = svc_h.db.get::<crate::epoch::Anchor>("epoch", b"latest") {
                                            let start = latest_anchor.num.saturating_sub(8);
                                            for n in start..=latest_anchor.num {
                                                svc_h.net.request_epoch_leaves(n).await;
                                                svc_h.net.request_epoch_selected(n).await;
                                            }
                                        }
                                        let vault_paycode = svc_h.cfg.vault_paycode.clone().unwrap_or_else(|| svc_h.wallet.export_stealth_address());
                                        let mut note = [0u8;32];
                                        let h = blake3::hash(std::str::from_utf8(&k).unwrap_or("").as_bytes());
                                        note.copy_from_slice(&h.as_bytes()[..32]);
                                        match svc_h.wallet.send_with_paycode_and_note(&vault_paycode, op.amount, &svc_h.net, &note).await {
                                            Ok(outcome) => {
                                                // Success: write mappings/state/events mirroring bridge_out_submit
                                                let tx_hash = combine_spend_hashes(&outcome.spends);
                                                let mut batch = rocksdb::WriteBatch::default();
                                                if let Some(cf_oc) = svc_h.db.db.cf_handle("bridge_op_coins") {
                                                    let coins: Vec<[u8;32]> = outcome.spends.iter().map(|s| s.coin_id).collect();
                                                    let ser = bincode::serialize(&coins).unwrap_or_default();
                                                    batch.put_cf(&cf_oc, &k, &ser);
                                                }
                                                if let Some(cf_bl) = svc_h.db.db.cf_handle("bridge_locked") {
                                                    for c in outcome.spends.iter() { batch.put_cf(&cf_bl, &c.coin_id, &k); }
                                                }
                                                // Update totals and persist state
                                                if let Ok(mut st) = svc_h.state.lock() {
                                                    st.total_locked = st.total_locked.saturating_add(op.amount);
                                                    if let Ok(state_ser) = bincode::serialize(&*st) {
                                                        if let Some(cf_st) = svc_h.db.db.cf_handle("bridge_state") { batch.put_cf(&cf_st, b"state", &state_ser); }
                                                    }
                                                }
                                                if let Some(cf_ev) = svc_h.db.db.cf_handle("bridge_events") {
                                                    let ev = BridgeEvent::TokensLocked { amount: op.amount, sui_recipient: op.sui_recipient.clone(), tx_hash: hex::encode(tx_hash), op_id: String::from_utf8_lossy(&k).to_string() };
                                                    let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0) as u64;
                                                    let rand = rand::random::<u64>().to_le_bytes();
                                                    let mut key = Vec::with_capacity(16);
                                                    key.extend_from_slice(&now_ms.to_le_bytes());
                                                    key.extend_from_slice(&rand);
                                                    let ser = bincode::serialize(&ev).unwrap_or_default();
                                                    batch.put_cf(&cf_ev, &key, &ser);
                                                }
                                                // Remove pending on success
                                                if let Some(cf_p) = svc_h.db.db.cf_handle("bridge_pending") { batch.delete_cf(&cf_p, &k); }
                                                let _ = svc_h.db.db.write(batch);
                                            }
                                            Err(e) => {
                                                let is_timeout = format!("{}", e).contains("Timed out waiting for valid coin proof");
                                                op.last_attempt = now;
                                                op.retry_count = op.retry_count.saturating_add(1);
                                                if !is_timeout { op.status = PendingStatus::Failed(format!("{}", e)); }
                                                if let Some(cf3) = svc_h.db.db.cf_handle("bridge_pending") { let _ = svc_h.db.db.put_cf(cf3, &k, &bincode::serialize(&op).unwrap_or_default()); }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
    }
    Ok(())
}

fn json_response<T: serde::Serialize>(val: &T, status: u16) -> hyper::Response<hyper::Body> {
    let body = serde_json::to_vec(val).unwrap_or_else(|_| b"{}".to_vec());
    let mut resp = hyper::Response::new(hyper::Body::from(body));
    *resp.status_mut() = hyper::StatusCode::from_u16(status).unwrap_or(hyper::StatusCode::OK);
    resp.headers_mut().insert(hyper::header::CONTENT_TYPE, hyper::header::HeaderValue::from_static("application/json"));
    resp
}

fn err_response(msg: &str, status: u16) -> hyper::Response<hyper::Body> {
    json_response(&serde_json::json!({"error": msg}), status)
}

fn authorize_admin(cfg: &crate::config::BridgeConfig, req: &hyper::Request<hyper::Body>) -> bool {
    if let Some(token) = &cfg.admin_token {
        if let Some(h) = req.headers().get("x-admin-token") {
            return h.to_str().ok().map(|s| s == token).unwrap_or(false);
        }
        return false;
    }
    // No token configured: disable admin APIs for safety
    false
}

async fn bridge_out_submit(svc: &Arc<BridgeService>, req: BridgeOutReq) -> Result<BridgeOutResult> {
    // Basic validation and rate-limit snapshot (copy fields out to avoid holding mutex across await)
    let (enabled, min_amt, max_amt, fee_bps, rate_window_secs, per_cap, global_cap, from_addr_hex) = {
        let st = svc.state.lock().unwrap();
        let addr_hex = hex::encode(svc.wallet.address());
        (
            st.bridge_enabled,
            st.min_bridge_amount,
            st.max_bridge_amount,
            st.bridge_fee_basis_points,
            svc.cfg.rate_window_secs,
            svc.cfg.per_address_daily_cap,
            svc.cfg.global_daily_cap,
            addr_hex,
        )
    };
    if !enabled { return Err(anyhow!("bridge disabled")); }
    if req.amount < min_amt || req.amount > max_amt { return Err(anyhow!("amount out of bounds")); }
    if !valid_sui_addr(&req.sui_recipient) { return Err(anyhow!("invalid sui recipient address")); }
    let _fee = req.amount.saturating_mul(fee_bps).saturating_div(10_000);

    // Check per-address and global rate limits against a rolling 24h window, without mutating yet
    {
        let mut st = svc.state.lock().unwrap();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let window_start = now.saturating_sub(rate_window_secs);
        let q = st.per_addr_window.entry(from_addr_hex.clone()).or_insert_with(VecDeque::new);
        while let Some(&(ts, _)) = q.front() { if ts < window_start { q.pop_front(); } else { break; } }
        let addr_sum: u64 = q.iter().map(|&(_, a)| a).sum();
        if addr_sum.saturating_add(req.amount) > per_cap { return Err(anyhow!("rate limited: per-address daily cap")); }
        while let Some(&(ts, _)) = st.global_window.front() { if ts < window_start { st.global_window.pop_front(); } else { break; } }
        let global_sum: u64 = st.global_window.iter().map(|&(_, a)| a).sum();
        if global_sum.saturating_add(req.amount) > global_cap { return Err(anyhow!("rate limited: global daily cap")); }
    }

    // Record pending operation only (locking/UTXO move is integrated later in block processing)
    let op_id = format!("{}", hex::encode(crate::crypto::blake3_hash(format!("{}:{}:{}", req.amount, &req.sui_recipient, std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis()).as_bytes())));
    let from_addr = svc.wallet.address();
    let op = PendingBridgeOp {
        id: op_id.clone(),
        from: from_addr,
        amount: req.amount,
        sui_recipient: req.sui_recipient,
        created_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
        nonce: 0,
        status: PendingStatus::Submitted,
        last_attempt: 0,
        retry_count: 0,
    };
    // Write pending op (do not hold CF across awaits)
    {
        let cf = svc.db.db.cf_handle("bridge_pending").ok_or_else(|| anyhow!("bridge_pending CF missing"))?;
        let ser = bincode::serialize(&op)?;
        svc.db.db.put_cf(cf, op_id.as_bytes(), &ser)?;
    }

    // Execute lock by sending spends to vault paycode
    let vault_paycode = svc.cfg.vault_paycode.clone().unwrap_or_else(|| svc.wallet.export_stealth_address());
    // Deterministic note from op_id to bind s_next and aid correlation
    let mut note = [0u8;32];
    let h = blake3::hash(op_id.as_bytes());
    note.copy_from_slice(&h.as_bytes()[..32]);
    let outcome_res = svc.wallet.send_with_paycode_and_note(&vault_paycode, op.amount, &svc.net, &note).await;
    let outcome = match outcome_res {
        Ok(o) => o,
        Err(e) => {
            // If proof timeout, keep as Submitted and schedule retry; otherwise mark Failed
            let is_timeout = format!("{}", e).contains("Timed out waiting for valid coin proof")
                || format!("{}", e).contains("Timed out waiting for valid coin proof");
            if let Some(cf2) = svc.db.db.cf_handle("bridge_pending") {
                match svc.db.db.get_cf(cf2, op_id.as_bytes()) {
                    Ok(Some(bytes)) => {
                        if let Ok(mut po) = bincode::deserialize::<PendingBridgeOp>(&bytes) {
                            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
                            if is_timeout {
                                po.status = PendingStatus::Submitted;
                                po.last_attempt = now;
                                po.retry_count = po.retry_count.saturating_add(1);
                            } else {
                                po.status = PendingStatus::Failed(format!("{}", e));
                                crate::metrics::BRIDGE_PENDING_FAILED.inc();
                            }
                            let _ = svc.db.db.put_cf(cf2, op_id.as_bytes(), &bincode::serialize(&po).unwrap_or_default());
                        }
                    },
                    _ => {}
                }
            }
            if is_timeout { return Ok(BridgeOutResult::Pending { op_id: op_id.clone() }); }
            return Err(anyhow!("wallet send to vault failed: {}", e));
        }
    };
    let tx_hash = combine_spend_hashes(&outcome.spends);
    // On success: wire CFs for op -> coins and coin -> op, update totals and rate windows atomically
    {
        let mut batch = rocksdb::WriteBatch::default();
        // bridge_op_coins: op_id -> Vec<coin_id>
        if let Some(cf_oc) = svc.db.db.cf_handle("bridge_op_coins") {
            let coins: Vec<[u8;32]> = outcome.spends.iter().map(|s| s.coin_id).collect();
            let ser = bincode::serialize(&coins).unwrap_or_default();
            batch.put_cf(&cf_oc, op_id.as_bytes(), &ser);
        }
        // bridge_locked: coin_id -> op_id
        if let Some(cf_bl) = svc.db.db.cf_handle("bridge_locked") {
            for c in outcome.spends.iter() {
                batch.put_cf(&cf_bl, &c.coin_id, op_id.as_bytes());
            }
        }
        // Remove pending on success
        if let Some(cf_p) = svc.db.db.cf_handle("bridge_pending") {
            batch.delete_cf(&cf_p, op_id.as_bytes());
        }
        // Update state: totals and rate windows
        {
            let mut st = svc.state.lock().unwrap();
            st.total_locked = st.total_locked.saturating_add(req.amount);
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
            let window_start = now.saturating_sub(rate_window_secs);
            let q = st.per_addr_window.entry(from_addr_hex.clone()).or_insert_with(VecDeque::new);
            while let Some(&(ts, _)) = q.front() { if ts < window_start { q.pop_front(); } else { break; } }
            q.push_back((now, req.amount));
            while let Some(&(ts, _)) = st.global_window.front() { if ts < window_start { st.global_window.pop_front(); } else { break; } }
            st.global_window.push_back((now, req.amount));
            // Persist state via batch
            if let Ok(state_ser) = bincode::serialize(&*st) {
                if let Some(cf_st) = svc.db.db.cf_handle("bridge_state") {
                    batch.put_cf(&cf_st, b"state", &state_ser);
                }
            }
        }
        // Append event
        if let Some(cf_ev) = svc.db.db.cf_handle("bridge_events") {
            let ev = BridgeEvent::TokensLocked { amount: op.amount, sui_recipient: op.sui_recipient.clone(), tx_hash: hex::encode(tx_hash), op_id: op_id.clone() };
            let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0) as u64;
            let rand = rand::random::<u64>().to_le_bytes();
            let mut key = Vec::with_capacity(16);
            key.extend_from_slice(&now_ms.to_le_bytes());
            key.extend_from_slice(&rand);
            let ser = bincode::serialize(&ev).unwrap_or_default();
            batch.put_cf(&cf_ev, &key, &ser);
        }
        svc.db.write_batch(batch)?;
    }
    crate::metrics::BRIDGE_OUT_LOCKED_COINS.inc_by(req.amount);

    Ok(BridgeOutResult::Locked { tx_hash: hex::encode(tx_hash) })
}

fn valid_sui_addr(s: &str) -> bool {
    let s = s.trim();
    if !s.starts_with("0x") { return false; }
    let hex_part = &s[2..];
    let len = hex_part.len();
    if len == 0 || len > 64 || (len % 2) != 0 { return false; }
    // Enforce lowercase hex for Sui addresses
    if hex_part.chars().any(|c| !c.is_ascii_hexdigit() || c.is_ascii_uppercase()) { return false; }
    true
}

fn combine_spend_hashes(spends: &Vec<crate::transfer::Spend>) -> [u8;32] {
    let mut h = blake3::Hasher::new();
    for sp in spends.iter() {
        h.update(&sp.root);
        h.update(&sp.nullifier);
        h.update(&sp.commitment);
        h.update(&sp.to.canonical_bytes());
    }
    *h.finalize().as_bytes()
}

// removed unused record_event

fn read_events(db: &Arc<Store>, limit: usize) -> Result<Vec<BridgeEvent>> {
    let cf = db.db.cf_handle("bridge_events").ok_or_else(|| anyhow!("bridge_events CF missing"))?;
    let iter = db.db.iterator_cf(cf, rocksdb::IteratorMode::End);
    let mut out: Vec<BridgeEvent> = Vec::new();
    for item in iter.take(limit) {
        let (_k, v) = item?;
        if let Ok(ev) = bincode::deserialize::<BridgeEvent>(&v) { out.push(ev); }
    }
    Ok(out)
}

fn set_bridge_paused(svc: &Arc<BridgeService>, paused: bool) {
    let mut st = svc.state.lock().unwrap();
    st.bridge_enabled = !paused;
    let _ = svc.db.put("bridge_state", b"state", &*st);
}

// --- Sui RPC proof verification (stronger checks) ---
#[derive(Debug, Clone)]
struct VerifiedSuiBurn { digest: String, amount: u64, #[allow(dead_code)] coin_type: Option<String>, #[allow(dead_code)] event_type: String }

async fn verify_sui_burn_proof(svc: &Arc<BridgeService>, proof_bytes: &[u8]) -> Result<VerifiedSuiBurn> {
    // Expect JSON: { "txDigest": "0x.." }
    #[derive(Deserialize)]
    struct Req { #[serde(rename = "txDigest")] tx_digest: String }
    let req: Req = serde_json::from_slice(proof_bytes).context("invalid proof payload")?;
    if !req.tx_digest.starts_with("0x") { return Err(anyhow!("invalid Sui digest")); }

    // Compose expected event type prefix
    let package = svc.cfg.sui_package_id.trim();
    let module = svc.cfg.sui_bridge_module.trim();
    let event_name = svc.cfg.sui_burn_event.trim();
    let expected_event_prefix = format!("{}::{}::{}", package, module, event_name);

    // Call Sui RPC getTransactionBlock to fetch effects and events
    #[derive(Serialize)]
    struct RpcReq { jsonrpc: &'static str, id: u32, method: &'static str, params: Vec<serde_json::Value> }
    let rpc = RpcReq {
        jsonrpc: "2.0",
        id: 1,
        method: "sui_getTransactionBlock",
        params: vec![serde_json::Value::String(req.tx_digest.clone()), serde_json::json!({"showEffects": true, "showEvents": true})],
    };
    let cli = reqwest::Client::new();
    let resp = cli.post(&svc.cfg.sui_rpc_url).json(&rpc).send().await.context("sui rpc http")?;
    let json: serde_json::Value = resp.json().await.context("sui rpc decode")?;
    let result = json.get("result").ok_or_else(|| anyhow!("missing result"))?;
    // Require success effects
    if let Some(effects) = result.get("effects") {
        if let Some(status) = effects.get("status").and_then(|s| s.get("status")).and_then(|s| s.as_str()) { if status != "success" { crate::metrics::BRIDGE_VERIFY_FAIL.inc(); return Err(anyhow!("sui tx not successful")); } }
    }
    // Require checkpoint presence to ensure finalization
    if result.get("checkpoint").is_none() { crate::metrics::BRIDGE_VERIFY_FAIL.inc(); return Err(anyhow!("sui tx not finalized (no checkpoint)")); }

    // Events array
    let events = result.get("events").and_then(|v| v.as_array()).or_else(|| result.get("eventsData").and_then(|v| v.as_array())).ok_or_else(|| anyhow!("missing events"))?;
    let mut found: Option<VerifiedSuiBurn> = None;
    for ev in events {
        let typ = ev.get("type").and_then(|t| t.as_str()).unwrap_or("");
        if !typ.starts_with(&expected_event_prefix) { continue; }
        // Prefer parsedJson; fallback to untyped fields
        let mut amount: Option<u64> = None;
        let mut coin_type: Option<String> = None;
        if let Some(fields) = ev.get("parsedJson") {
            amount = fields.get("amount").and_then(|x| x.as_u64());
            coin_type = fields.get("coin_type").and_then(|x| x.as_str().map(|s| s.to_string()));
        }
        if amount.unwrap_or(0) == 0 { continue; }
        // Enforce coin_type match if configured
        if let Some(expected_coin) = &svc.cfg.sui_coin_type {
            if let Some(ct) = &coin_type { if ct != expected_coin { continue; } } else { continue; }
        }
        found = Some(VerifiedSuiBurn { digest: req.tx_digest.clone(), amount: amount.unwrap_or(0), coin_type, event_type: typ.to_string() });
        break;
    }
    match found {
        Some(v) => { crate::metrics::BRIDGE_VERIFY_OK.inc(); Ok(v) },
        None => { crate::metrics::BRIDGE_VERIFY_FAIL.inc(); Err(anyhow!("no matching bridge burn event")) },
    }
}

// Bridge-in submit: verify proof, check replay set, unlock by sending from vault wallet to recipient paycode
async fn bridge_in_submit(svc: &Arc<BridgeService>, body: &[u8]) -> Result<String> {
    #[derive(Deserialize)]
    struct InReq { amount: u64, to_paycode: String, sui_tx_hash: String, sui_burn_proof: serde_json::Value }
    let r: InReq = serde_json::from_slice(body).context("invalid bridge_in request")?;
    if r.amount == 0 { return Err(anyhow!("amount must be > 0")); }
    // Verify proof and cross-check digest
    let proof_bytes = serde_json::to_vec(&r.sui_burn_proof)?;
    let verified = verify_sui_burn_proof(svc, &proof_bytes).await?;
    if !verified.digest.eq_ignore_ascii_case(&r.sui_tx_hash) { return Err(anyhow!("sui_tx_hash mismatch")); }
    // Enforce amount matches burn
    if verified.amount != r.amount { return Err(anyhow!("amount mismatch vs Sui burn")); }
    // Two-phase replay protection: check if already processed or pending
    if svc.is_sui_tx_processed(&verified.digest)? { crate::metrics::BRIDGE_REPLAY_ATTEMPTS.inc(); return Err(anyhow!("sui tx already processed")); }
    
    // Phase 1: Mark as pending to prevent concurrent processing
    let pending_key = format!("pending:{}", verified.digest);
    if let Some(cf) = svc.db.db.cf_handle("bridge_processed_sui") {
        // Check if already pending
        if svc.db.db.get_cf(cf, pending_key.as_bytes())?.is_some() {
            crate::metrics::BRIDGE_REPLAY_ATTEMPTS.inc();
            return Err(anyhow!("sui tx already being processed"));
        }
        // Mark as pending
        svc.db.db.put_cf(cf, pending_key.as_bytes(), &[0u8])?;
    }
    // Unlock: send from wallet (vault) to recipient paycode; deterministic note from digest
    let mut note = [0u8;32];
    let h = blake3::hash(verified.digest.as_bytes());
    note.copy_from_slice(&h.as_bytes()[..32]);
    let outcome = svc.wallet.send_with_paycode_and_note(&r.to_paycode, r.amount, &svc.net, &note).await;
    
    // Handle wallet send result and complete two-phase commit
    let tx_hash = match outcome {
        Ok(outcome) => {
            let tx_hash = combine_spend_hashes(&outcome.spends);
            tx_hash
        }
        Err(e) => {
            // Rollback: remove pending marker on failure
            if let Some(cf) = svc.db.db.cf_handle("bridge_processed_sui") {
                let _ = svc.db.db.delete_cf(cf, pending_key.as_bytes());
            }
            return Err(anyhow!("wallet send for bridge_in failed: {}", e));
        }
    };
    
    // Complete the atomic update
    {
        let mut batch = rocksdb::WriteBatch::default();
        if let Some(cf) = svc.db.db.cf_handle("bridge_processed_sui") { 
            batch.put_cf(&cf, verified.digest.as_bytes(), &[1u8]); // Mark as processed
            batch.delete_cf(&cf, pending_key.as_bytes()); // Clean up pending marker
        }
        {
            let mut st = svc.state.lock().unwrap();
            st.total_unlocked = st.total_unlocked.saturating_add(r.amount);
            if let Ok(state_ser) = bincode::serialize(&*st) { if let Some(cf_st) = svc.db.db.cf_handle("bridge_state") { batch.put_cf(&cf_st, b"state", &state_ser); } }
        }
        if let Some(cf_ev) = svc.db.db.cf_handle("bridge_events") {
            let recipient_addr = match crate::wallet::Wallet::parse_stealth_address(&r.to_paycode) {
                Ok((addr, _)) => addr,
                Err(_) => svc.wallet.address(),
            };
            let ev = BridgeEvent::TokensUnlocked { amount: r.amount, recipient: recipient_addr, sui_tx_hash: verified.digest.clone() };
            let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0) as u64;
            let rand = rand::random::<u64>().to_le_bytes();
            let mut key = Vec::with_capacity(16);
            key.extend_from_slice(&now_ms.to_le_bytes());
            key.extend_from_slice(&rand);
            let ser = bincode::serialize(&ev).unwrap_or_default();
            batch.put_cf(&cf_ev, &key, &ser);
        }
        svc.db.write_batch(batch)?;
    }
    crate::metrics::BRIDGE_IN_UNLOCKED_COINS.inc_by(r.amount);
    Ok(hex::encode(tx_hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn status_defaults() {
        // Create an in-memory-ish store by opening a temp dir
        let tmp = tempfile::tempdir().unwrap();
        let db = Store::open(&tmp.path().to_string_lossy()).unwrap();
        let cfg = crate::config::BridgeConfig::default();
        // Dummy wallet/net cannot be constructed easily here; skip RPC path; test state accessors
        let svc = BridgeService::new(Arc::new(db), cfg, Arc::new(dummy_wallet()), dummy_net());
        let st = svc.get_status().unwrap();
        assert!(st.bridge_enabled);
        assert_eq!(st.min_amount, 1);
        assert_eq!(st.max_amount, 1_000_000);
        assert_eq!(st.fee_basis_points, 10);
    }

    fn dummy_wallet() -> crate::wallet::Wallet { panic!("not used in this unit test") }
    fn dummy_net() -> crate::network::NetHandle { panic!("not used in this unit test") }
}


