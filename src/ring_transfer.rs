use serde::{Serialize, Deserialize};
use anyhow::{Result, anyhow};
use crate::ringsig::{RingPublicKey, RingSignatureBlob, LinkTag, RingSignatureScheme};
use crate::crypto::Address;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RingOutput {
    pub id: [u8; 32],
    pub pubkey: RingPublicKey,
    pub epoch_num: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RingTransfer {
    pub ring_members: Vec<RingPublicKey>,
    pub recipient_one_time: RingPublicKey,
    pub to: Address,
    pub signature: RingSignatureBlob,
    pub link_tag: LinkTag,
}

impl RingTransfer {
    pub fn hash(&self) -> [u8; 32] {
        let bytes = bincode::serialize(self).expect("serialize ring transfer");
        crate::crypto::blake3_hash(&bytes)
    }

    pub fn verify<S: RingSignatureScheme>(&self, scheme: &S) -> Result<()> {
        // Enforce ring size bounds to avoid trivial rings and DoS
        let cfg = crate::config::load("config.toml").ok();
        if let Some(cfg) = cfg {
            if self.ring_members.len() < cfg.epoch.min_ring_size || self.ring_members.len() > cfg.epoch.max_ring_size {
                return Err(anyhow!("ring size out of bounds"));
            }
        }
        let msg = self.binding_message();
        if !scheme.verify(&msg, &self.ring_members, &self.signature, &self.link_tag)? {
            return Err(anyhow!("invalid ring signature"));
        }
        Ok(())
    }

    pub fn binding_message(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.to);
        let mut concat = Vec::new();
        for m in &self.ring_members { concat.extend_from_slice(&m.0); }
        let ring_root = crate::crypto::blake3_hash(&concat);
        v.extend_from_slice(b"ring_tx");
        v.extend_from_slice(&ring_root);
        v.extend_from_slice(&self.recipient_one_time.0);
        v
    }
}


