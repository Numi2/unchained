// transfer.rs
// Copyright 2025 The Unchained Authors
// SPDX-License-Identifier: Apache-2.0

//! Stealth transfer implementation (V3 hashlock only).

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use subtle::ConstantTimeEq;

use crate::crypto::{
    address_from_pk, commitment_id_v1, commitment_of_stealth_ct, derive_next_lock_secret_with_note,
    ml_kem_768_decapsulate, stealth_seed_v3, Address, MlKem768SecretKey, TaggedSigningPublicKey,
    ML_KEM_768_CT_BYTES as KEM_CT_BYTES, OTP_PK_BYTES,
};

// ------------ Stealth Output ------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StealthOutput {
    // One-time public bytes (opaque, used for recipient addressing).
    #[serde(with = "BigArray")]
    pub one_time_pk: [u8; OTP_PK_BYTES],
    // ML-KEM-768 ciphertext so the recipient can derive the shared secret.
    #[serde(with = "BigArray")]
    pub kem_ct: [u8; KEM_CT_BYTES],
    // Amount (little-endian on wire as u64).
    pub amount_le: u64,
    /// Optional 1-byte view tag for cheap receiver-side filtering.
    #[serde(default)]
    pub view_tag: Option<u8>,
}

impl StealthOutput {
    /// Deterministic bytes used inside commitments.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(OTP_PK_BYTES + KEM_CT_BYTES + 8 + 1);
        v.extend_from_slice(&self.one_time_pk);
        v.extend_from_slice(&self.kem_ct);
        v.extend_from_slice(&self.amount_le.to_le_bytes());
        if let Some(vt) = self.view_tag {
            v.push(vt);
        }
        v
    }

    /// Check if this output is intended for the receiver by reproducing the
    /// ML-KEM-bound one-time public bytes using deterministic hashing.
    pub fn is_for_receiver(
        &self,
        kem_sk: &MlKem768SecretKey,
        receiver_signing_pk: &TaggedSigningPublicKey,
        chain_id32: &[u8; 32],
    ) -> Result<()> {
        let shared = ml_kem_768_decapsulate(kem_sk, &self.kem_ct)?;
        if let Some(vt) = self.view_tag {
            if crate::crypto::view_tag(&shared) != vt {
                return Err(anyhow!("View tag mismatch"));
            }
        }
        let value_tag = self.amount_le.to_le_bytes();
        let receiver_addr = address_from_pk(receiver_signing_pk);
        let seed_addr = stealth_seed_v3(
            &shared,
            &receiver_addr,
            &self.kem_ct,
            &value_tag,
            chain_id32,
        );
        let pk_bytes_addr = crate::crypto::derive_one_time_pk_bytes(seed_addr);
        if pk_bytes_addr
            .as_slice()
            .ct_eq(&self.one_time_pk[..])
            .unwrap_u8()
            == 1
        {
            return Ok(());
        }
        Err(anyhow!("Derived OTP bytes mismatch"))
    }

    /// Recipient derives the lock secret for next-hop ownership using ML-KEM shared secret and context.
    pub fn derive_lock_secret(
        &self,
        kem_sk: &MlKem768SecretKey,
        coin_id: &[u8; 32],
        chain_id32: &[u8; 32],
        note_s: &[u8],
    ) -> Result<[u8; 32]> {
        let shared = ml_kem_768_decapsulate(kem_sk, &self.kem_ct)?;
        Ok(derive_next_lock_secret_with_note(
            &shared,
            &self.kem_ct,
            self.amount_le,
            coin_id,
            chain_id32,
            note_s,
        ))
    }

    /// Compute the recipient Address-like hash from the opaque one-time public bytes.
    pub fn recipient_address(&self) -> Result<Address> {
        Ok(crate::crypto::blake3_hash(&self.one_time_pk))
    }
}

// ------------ V3 Hashlock Spend ------------

/// Receiver-supplied lock commitment for V3 hashlock spends.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiverLockCommitment {
    #[serde(with = "BigArray")]
    pub one_time_pk: [u8; OTP_PK_BYTES],
    #[serde(with = "BigArray")]
    pub kem_ct: [u8; KEM_CT_BYTES],
    pub next_lock_hash: [u8; 32],
    pub commitment_id: [u8; 32],
    pub amount_le: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Spend {
    /// The spent coin id.
    pub coin_id: [u8; 32],
    /// Merkle root of the epoch that committed this coin.
    pub root: [u8; 32],
    /// Inclusion proof path for the coin id's leaf.
    pub proof: Vec<([u8; 32], bool)>,
    /// Stealth output commitment for the new recipient.
    pub commitment: [u8; 32],
    /// Nullifier.
    pub nullifier: [u8; 32],
    /// The actual stealth output (one-time pk + enc payload).
    pub to: StealthOutput,
    /// Hashlock unlock preimage.
    #[serde(default)]
    pub unlock_preimage: Option<[u8; 32]>,
    /// Next-hop lock hash, computed from ML-KEM shared secret and context.
    #[serde(default)]
    pub next_lock_hash: Option<[u8; 32]>,
    /// Optional HTLC timeout epoch (epoch number T). If set, previous lock must be HTLC.
    #[serde(default)]
    pub htlc_timeout_epoch: Option<u64>,
    /// Commitment hash for claim path: ch_claim = CH(chain_id, coin_id, s_claim).
    #[serde(default)]
    pub htlc_ch_claim: Option<[u8; 32]>,
    /// Commitment hash for refund path: ch_refund = CH(chain_id, coin_id, s_refund).
    #[serde(default)]
    pub htlc_ch_refund: Option<[u8; 32]>,
}

impl Spend {
    /// Construct a signatureless hashlock-based spend (V3) using a receiver-supplied commitment.
    pub fn create_hashlock(
        coin_id: [u8; 32],
        anchor: &crate::epoch::Anchor,
        proof: Vec<([u8; 32], bool)>,
        unlock_preimage: [u8; 32],
        receiver_commitment: &ReceiverLockCommitment,
        amount: u64,
        chain_id32: &[u8; 32],
    ) -> Result<Self> {
        if receiver_commitment.amount_le != amount {
            return Err(anyhow!("Receiver commitment amount mismatch"));
        }
        let computed_cid = commitment_id_v1(
            &receiver_commitment.one_time_pk,
            &receiver_commitment.kem_ct,
            &receiver_commitment.next_lock_hash,
            &coin_id,
            amount,
            chain_id32,
        );
        if computed_cid != receiver_commitment.commitment_id {
            return Err(anyhow!("Receiver commitment_id mismatch"));
        }
        let commitment = commitment_of_stealth_ct(&receiver_commitment.kem_ct);
        let mut to = StealthOutput {
            one_time_pk: [0u8; OTP_PK_BYTES],
            kem_ct: [0u8; KEM_CT_BYTES],
            amount_le: amount,
            view_tag: None,
        };
        to.one_time_pk
            .copy_from_slice(&receiver_commitment.one_time_pk);
        to.kem_ct.copy_from_slice(&receiver_commitment.kem_ct);

        let nullifier =
            crate::crypto::nullifier_from_preimage(chain_id32, &coin_id, &unlock_preimage);
        let next_lock_hash = receiver_commitment.next_lock_hash;

        Ok(Spend {
            coin_id,
            root: anchor.merkle_root,
            proof,
            commitment,
            nullifier,
            to,
            unlock_preimage: Some(unlock_preimage),
            next_lock_hash: Some(next_lock_hash),
            htlc_timeout_epoch: None,
            htlc_ch_claim: None,
            htlc_ch_refund: None,
        })
    }

    /// Construct a signatureless HTLC-based spend (claim or refund path), with epoch timeout.
    pub fn create_htlc_hashlock(
        coin_id: [u8; 32],
        anchor: &crate::epoch::Anchor,
        proof: Vec<([u8; 32], bool)>,
        unlock_preimage: [u8; 32],
        receiver_commitment: &ReceiverLockCommitment,
        amount: u64,
        chain_id32: &[u8; 32],
        timeout_epoch: u64,
        ch_claim: [u8; 32],
        ch_refund: [u8; 32],
    ) -> Result<Self> {
        if receiver_commitment.amount_le != amount {
            return Err(anyhow!("Receiver commitment amount mismatch"));
        }
        let computed_cid = commitment_id_v1(
            &receiver_commitment.one_time_pk,
            &receiver_commitment.kem_ct,
            &receiver_commitment.next_lock_hash,
            &coin_id,
            amount,
            chain_id32,
        );
        if computed_cid != receiver_commitment.commitment_id {
            return Err(anyhow!("Receiver commitment_id mismatch"));
        }
        let commitment = commitment_of_stealth_ct(&receiver_commitment.kem_ct);
        let mut to = StealthOutput {
            one_time_pk: [0u8; OTP_PK_BYTES],
            kem_ct: [0u8; KEM_CT_BYTES],
            amount_le: amount,
            view_tag: None,
        };
        to.one_time_pk
            .copy_from_slice(&receiver_commitment.one_time_pk);
        to.kem_ct.copy_from_slice(&receiver_commitment.kem_ct);

        let nullifier =
            crate::crypto::nullifier_from_preimage(chain_id32, &coin_id, &unlock_preimage);
        let next_lock_hash = receiver_commitment.next_lock_hash;

        Ok(Spend {
            coin_id,
            root: anchor.merkle_root,
            proof,
            commitment,
            nullifier,
            to,
            unlock_preimage: Some(unlock_preimage),
            next_lock_hash: Some(next_lock_hash),
            htlc_timeout_epoch: Some(timeout_epoch),
            htlc_ch_claim: Some(ch_claim),
            htlc_ch_refund: Some(ch_refund),
        })
    }

    /// Validate spend statelessly + against DB: proof, uniqueness, hashlock, commitment, nullifier.
    pub fn validate(&self, db: &crate::storage::Store) -> Result<()> {
        let coin: crate::coin::Coin = db
            .get_coin(&self.coin_id)?
            .ok_or_else(|| anyhow!("Referenced coin does not exist"))?;

        let commit_epoch = db
            .get_epoch_for_coin(&self.coin_id)?
            .ok_or_else(|| anyhow!("Missing coin->epoch index"))?;
        let anchor: crate::epoch::Anchor = db
            .get("epoch", &commit_epoch.to_le_bytes())?
            .ok_or_else(|| anyhow!("Committing anchor not found"))?;
        if anchor.merkle_root != self.root {
            return Err(anyhow!("Merkle root mismatch"));
        }
        let leaf = crate::coin::Coin::id_to_leaf_hash(&coin.id);
        if !crate::epoch::MerkleTree::verify_proof(&leaf, &self.proof, &anchor.merkle_root) {
            return Err(anyhow!("Invalid Merkle inclusion proof"));
        }

        let expected_commitment = crate::crypto::commitment_of_stealth_ct(&self.to.kem_ct);
        if expected_commitment != self.commitment {
            return Err(anyhow!("Commitment mismatch"));
        }
        if self.to.amount_le != coin.value {
            return Err(anyhow!("Amount mismatch with coin value"));
        }

        let preimage = self
            .unlock_preimage
            .ok_or_else(|| anyhow!("V3 hashlock preimage required"))?;
        let expected_lock_hash = if let Some(prev_spend) = db.get_spend(&self.coin_id)? {
            prev_spend
                .next_lock_hash
                .ok_or_else(|| anyhow!("Previous spend missing next_lock_hash"))?
        } else {
            coin.lock_hash
        };
        let chain_id = db.get_chain_id()?;
        if let (Some(t), Some(ch_claim), Some(ch_refund)) = (
            self.htlc_timeout_epoch,
            self.htlc_ch_claim,
            self.htlc_ch_refund,
        ) {
            let current_epoch = db
                .get::<crate::epoch::Anchor>("epoch", b"latest")
                .ok()
                .flatten()
                .map(|a| a.num)
                .unwrap_or(0);
            let ch_of_pre =
                crate::crypto::commitment_hash_from_preimage(&chain_id, &self.coin_id, &preimage);
            if current_epoch < t {
                if ch_of_pre != ch_claim {
                    return Err(anyhow!("HTLC claim path CH mismatch before timeout"));
                }
            } else if ch_of_pre != ch_refund {
                return Err(anyhow!("HTLC refund path CH mismatch at/after timeout"));
            }
            let expected_htlc =
                crate::crypto::htlc_lock_hash(&chain_id, &self.coin_id, t, &ch_claim, &ch_refund);
            if expected_lock_hash != expected_htlc {
                return Err(anyhow!("HTLC composite lock mismatch"));
            }
        } else if expected_lock_hash != [0u8; 32] {
            let lh_new =
                crate::crypto::lock_hash_from_preimage(&chain_id, &self.coin_id, &preimage);
            if lh_new != expected_lock_hash {
                return Err(anyhow!("Invalid hashlock preimage"));
            }
        }
        let exp_nf_new =
            crate::crypto::nullifier_from_preimage(&chain_id, &self.coin_id, &preimage);
        if exp_nf_new != self.nullifier {
            return Err(anyhow!("Nullifier mismatch"));
        }
        let next_lock = self
            .next_lock_hash
            .ok_or_else(|| anyhow!("Missing next_lock_hash in V3 spend"))?;
        let cid = commitment_id_v1(
            &self.to.one_time_pk,
            &self.to.kem_ct,
            &next_lock,
            &self.coin_id,
            self.to.amount_le,
            &chain_id,
        );
        if db.get::<[u8; 1]>("commitment_used", &cid)?.is_some() {
            return Err(anyhow!("Receiver commitment already used"));
        }

        if self.to.one_time_pk.len() != OTP_PK_BYTES {
            return Err(anyhow!("Invalid one-time pk length"));
        }
        if self.to.kem_ct.len() != KEM_CT_BYTES {
            return Err(anyhow!("Invalid ML-KEM ciphertext length"));
        }

        Ok(())
    }

    pub fn apply(&self, db: &crate::storage::Store) -> Result<()> {
        let mut batch = rocksdb::WriteBatch::default();
        self.apply_to_batch(db, &mut batch)?;
        db.write_batch(batch)?;
        Ok(())
    }

    pub fn apply_to_batch(
        &self,
        db: &crate::storage::Store,
        batch: &mut rocksdb::WriteBatch,
    ) -> Result<()> {
        let Some(sp_cf) = db.db.cf_handle("spend") else {
            return Err(anyhow!("Column family missing"));
        };
        let cid_cf = db.db.cf_handle("commitment_used");
        let bytes = bincode::serialize(self)?;
        batch.put_cf(sp_cf, &self.coin_id, &bytes);
        if self.unlock_preimage.is_some() {
            if let Some(cf) = cid_cf {
                let chain_id = db.get_chain_id()?;
                let next_lock = self
                    .next_lock_hash
                    .ok_or_else(|| anyhow!("Missing next_lock_hash in V3 spend"))?;
                let cid = commitment_id_v1(
                    &self.to.one_time_pk,
                    &self.to.kem_ct,
                    &next_lock,
                    &self.coin_id,
                    self.to.amount_le,
                    &chain_id,
                );
                batch.put_cf(cf, &cid, &[1u8; 1]);
            }
        }
        Ok(())
    }
}
