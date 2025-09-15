use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use serde::{Deserialize, Serialize};

pub const VERSION: &str = "x402-unchained-v1";
pub const HEADER_X_PAYMENT: &str = "X-PAYMENT";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402Method {
    pub chain: String,
    pub chain_id: String,
    pub recipient: String,
    pub amount: u64,
    pub expiry_ms: u64,
    pub note_binding_b64: String,
    pub min_confs: u32,
    // Optional EVM/x402 facilitator method fields
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub facilitator_url: Option<String>,
    #[serde(default)]
    pub recipient_evm: Option<String>,
    #[serde(default)]
    pub price_usd_micros: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402Challenge {
    pub version: String,
    pub invoice_id: String,
    pub methods: Vec<X402Method>,
    pub resource: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct X402Receipt {
    pub invoice_id: String,
    pub spend_hashes: Vec<String>,
    pub amount: u64,
    pub binding_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum X402AnyReceipt {
    Unchained {
        invoice_id: String,
        spend_hashes: Vec<String>,
        amount: u64,
        binding_b64: String,
    },
    Evm {
        invoice_id: String,
        network: String,
        facilitator_url: String,
        proof: serde_json::Value,
    },
}

pub fn compute_binding(invoice_id: &str, resource: &str, amount: u64) -> [u8; 32] {
    let mut data = Vec::with_capacity(32 + invoice_id.len() + resource.len());
    data.extend_from_slice(b"x402-binding.v1");
    data.extend_from_slice(invoice_id.as_bytes());
    data.extend_from_slice(&amount.to_le_bytes());
    data.extend_from_slice(resource.as_bytes());
    crate::crypto::blake3_hash(&data)
}

pub fn build_challenge(
    invoice_id: String,
    chain_id_hex: String,
    recipient: String,
    amount: u64,
    expiry_ms: u64,
    min_confs: u32,
    resource: Option<String>,
) -> X402Challenge {
    let binding = compute_binding(&invoice_id, resource.as_deref().unwrap_or(""), amount);
    let method = X402Method {
        chain: "unchained".to_string(),
        chain_id: chain_id_hex,
        recipient,
        amount,
        expiry_ms,
        note_binding_b64: B64.encode(binding),
        min_confs,
        network: None,
        facilitator_url: None,
        recipient_evm: None,
        price_usd_micros: None,
    };
    X402Challenge { version: VERSION.to_string(), invoice_id, methods: vec![method], resource }
}

pub fn encode_receipt_header(r: &X402Receipt) -> Result<String> {
    let json = serde_json::to_vec(r)?;
    Ok(B64.encode(json))
}

pub fn decode_receipt_header(s: &str) -> Result<X402Receipt> {
    let bytes = B64
        .decode(s.as_bytes())
        .map_err(|e| anyhow!("base64 decode: {}", e))?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn decode_any_receipt_header(s: &str) -> Result<X402AnyReceipt> {
    let bytes = B64
        .decode(s.as_bytes())
        .map_err(|e| anyhow!("base64 decode: {}", e))?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn binding_bytes_from_b64(b64: &str) -> Result<[u8; 32]> {
    let raw = B64
        .decode(b64.as_bytes())
        .map_err(|e| anyhow!("base64 decode: {}", e))?;
    if raw.len() != 32 {
        return Err(anyhow!("binding length must be 32"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_roundtrip() {
        let r = X402Receipt {
            invoice_id: "inv-1".into(),
            spend_hashes: vec!["abcd".into()],
            amount: 1,
            binding_b64: B64.encode([9u8; 32]),
        };
        let enc = encode_receipt_header(&r).unwrap();
        let dec = decode_receipt_header(&enc).unwrap();
        assert_eq!(dec.invoice_id, r.invoice_id);
        assert_eq!(dec.amount, r.amount);
        assert_eq!(dec.binding_b64, r.binding_b64);
    }

    #[test]
    fn challenge_builds() {
        let ch = build_challenge(
            "inv-1".into(),
            "00".repeat(32),
            "paycode".into(),
            1,
            123,
            0,
            Some("/paid/x".into()),
        );
        assert_eq!(ch.version, VERSION);
        assert_eq!(ch.methods.len(), 1);
        assert_eq!(ch.methods[0].chain, "unchained");
    }
}


