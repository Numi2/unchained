use serde::{Serialize, Deserialize};
use crate::crypto::{Address, DILITHIUM3_PK_BYTES, DILITHIUM3_SIG_BYTES};

use serde_big_array::BigArray;

/// A coin transfer, which includes the sender's full public key to enable
/// verification, and a signature over the content. This forms a spendable UTXO.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Transfer {
    pub coin_id: [u8; 32],
    // The sender's full public key is required for stateless signature verification.
    #[serde(with = "BigArray")]
    pub sender_pk: [u8; DILITHIUM3_PK_BYTES],
    // The address of the new owner.
    pub to: Address,
    // The hash of the previous transaction, forming a per-coin chain.
    pub prev_tx_hash: [u8; 32],
    // A Dilithium3 signature from the sender.
    #[serde(with = "BigArray")]
    pub sig: [u8; DILITHIUM3_SIG_BYTES],
}

impl Transfer {
    /// Canonical bytes-to-sign: coin_id ‖ sender_pk ‖ to ‖ prev_tx_hash.
    /// This deterministic serialization prevents replay/tamper attacks and is
    /// independent of any serde/bincode representation.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(32 + DILITHIUM3_PK_BYTES + 32 + 32);
        v.extend_from_slice(&self.coin_id);
        v.extend_from_slice(&self.sender_pk);
        v.extend_from_slice(&self.to);
        v.extend_from_slice(&self.prev_tx_hash);
        v
    }

    /// Backwards-compat alias used by old code paths – now forwards to signing_bytes().
    #[deprecated(note = "Use signing_bytes() instead")]    
    pub fn content_bytes(&self) -> Vec<u8> {
        self.signing_bytes()
    }

    /// Deterministic hash over the canonical signing bytes (not over serde encoding).
    pub fn hash(&self) -> [u8; 32] {
        crate::crypto::blake3_hash(&self.signing_bytes())
    }
}