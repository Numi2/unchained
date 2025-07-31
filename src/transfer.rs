use serde::{Serialize, Deserialize};
use crate::crypto;
use pqcrypto_dilithium::dilithium3::{PublicKey, DetachedSignature};
use pqcrypto_traits::sign::DetachedSignature as DetachedSignatureTrait;

/// A coin transfer signed by its current owner
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transfer {
    pub coin_id: [u8; 32],
    pub to: [u8; 32],             // receiver pubkey hash
    pub prev_tx_hash: [u8; 32],   // for per-coin micro-chain
    pub sig: Vec<u8>,             // Dilithium3 signature
}

impl Transfer {
    /// Returns the message that was signed
    pub fn signed_content(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.coin_id);
        data.extend_from_slice(&self.to);
        data.extend_from_slice(&self.prev_tx_hash);
        data
    }

    /// Returns the BLAKE3 hash of the transfer (used as new head)
    pub fn tx_hash(&self) -> [u8; 32] {
        crypto::blake3_hash(&self.signed_content())
    }

    /// Verifies the signature against the sender pubkey
    pub fn verify(&self, sender_pk: &PublicKey) -> bool {
        if let Ok(sig) = DetachedSignature::from_bytes(&self.sig) {
            crypto::verify(&self.signed_content(), &sig, sender_pk)
        } else {
            false
        }
    }
}