// transfer.rs
// Copyright 2025 The Unchained Authors
// SPDX-License-Identifier: Apache-2.0

//! Stealth transfer implementation (V3 hashlock only).

use serde::{Serialize, Deserialize};
use serde_big_array::BigArray;
use anyhow::{Result, Context, anyhow};

use crate::crypto::{
    Address, address_from_pk,
    OTP_PK_BYTES,
    KYBER768_CT_BYTES as KYBER_CT_BYTES,
    commitment_of_stealth_ct, stealth_seed_v1, stealth_seed_v3,
    derive_next_lock_secret_with_note, commitment_id_v1,
};
use pqcrypto_dilithium::dilithium3::{
    PublicKey as DiliPk,
};
use pqcrypto_traits::sign::PublicKey as _;

use pqcrypto_kyber::kyber768::{
    SecretKey as KyberSk, Ciphertext as KyberCt,
    decapsulate,
};
use pqcrypto_traits::kem::{Ciphertext as KyberCtTrait, SharedSecret as KyberSharedSecretTrait};

use subtle::ConstantTimeEq;

// ------------ Stealth Output ------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StealthOutput {
    // One-time public bytes (opaque, used for recipient addressing). Do not parse as Dilithium key.
    #[serde(with = "BigArray")]
    pub one_time_pk: [u8; OTP_PK_BYTES],
    // Kyber768 ciphertext so recipient can derive the shared secret
    #[serde(with = "BigArray")]
    pub kyber_ct: [u8; KYBER_CT_BYTES],
    // Amount (little-endian on wire as u64)
    pub amount_le: u64,
    /// Optional 1-byte view tag for cheap receiver-side filtering
    #[serde(default)]
    pub view_tag: Option<u8>,
}

impl StealthOutput {
    /// Deterministic bytes used inside commitments.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(OTP_PK_BYTES + KYBER_CT_BYTES + 8 + 1);
        v.extend_from_slice(&self.one_time_pk);
        v.extend_from_slice(&self.kyber_ct);
        v.extend_from_slice(&self.amount_le.to_le_bytes());
        if let Some(vt) = self.view_tag { v.push(vt); }
        v
    }

    /// Check if this output is intended for the receiver by reproducing the
    /// Kyber-bound one-time public bytes using deterministic hashing.
    /// Tries address-bound seed first (new), then falls back to legacy PK-bound seed for compatibility.
    pub fn is_for_receiver(&self, kyber_sk: &KyberSk, receiver_dili_pk: &DiliPk, chain_id32: &[u8;32]) -> Result<()> {
        let ct = KyberCt::from_bytes(&self.kyber_ct)
            .context("Invalid Kyber ciphertext")?;
        let shared = decapsulate(&ct, kyber_sk);
        // View tag check if present (cheap early filter)
        if let Some(vt) = self.view_tag {
            if crate::crypto::view_tag(shared.as_bytes()) != vt { return Err(anyhow!("View tag mismatch")); }
        }
        let value_tag = self.amount_le.to_le_bytes();
        // Bind stealth seed to receiver address (stable identity) using V3 tag
        let receiver_addr = address_from_pk(receiver_dili_pk);
        let seed_addr = stealth_seed_v3(shared.as_bytes(), &receiver_addr, ct.as_bytes(), &value_tag, chain_id32);
        let pk_bytes_addr = crate::crypto::derive_one_time_pk_bytes(seed_addr);
        if pk_bytes_addr.as_slice().ct_eq(&self.one_time_pk[..]).unwrap_u8() == 1 { return Ok(()); }
        // Legacy fallback: derive using receiver Dilithium PK bytes
        let seed_legacy = stealth_seed_v1(shared.as_bytes(), receiver_dili_pk.as_bytes(), ct.as_bytes(), &value_tag, chain_id32);
        let pk_bytes_legacy = crate::crypto::derive_one_time_pk_bytes(seed_legacy);
        if pk_bytes_legacy.as_slice().ct_eq(&self.one_time_pk[..]).unwrap_u8() == 1 { return Ok(()); }
        Err(anyhow!("Derived OTP bytes mismatch"))
    }

    /// Recipient derives the lock secret for next-hop ownership using Kyber shared secret and context.
    pub fn derive_lock_secret(&self, kyber_sk: &KyberSk, coin_id: &[u8;32], chain_id32: &[u8;32], note_s: &[u8]) -> Result<[u8;32]> {
        let ct = KyberCt::from_bytes(&self.kyber_ct)
            .context("Invalid Kyber ciphertext")?;
        let shared = decapsulate(&ct, kyber_sk);
        Ok(derive_next_lock_secret_with_note(shared.as_bytes(), ct.as_bytes(), self.amount_le, coin_id, chain_id32, note_s))
    }

    

    /// Compute the recipient Address-like hash from the opaque one-time public bytes.
    /// Uses blake3_hash over the one-time public bytes; does not parse as a Dilithium key.
    pub fn recipient_address(&self) -> Result<Address> {
        Ok(crate::crypto::blake3_hash(&self.one_time_pk))
    }
}
// (Legacy V1 transfer has been fully removed.)

// ------------ V3 Hashlock Spend ------------

/// Receiver-supplied lock commitment for V3 hashlock spends.
/// The receiver generates `kyber_ct` (encapsulated to their own Kyber PK), decapsulates to get
/// the shared secret, derives the one-time public bytes deterministically using `stealth_seed_v1`,
/// and computes the next-hop lock preimage `s_next` using `derive_next_lock_secret`.
/// The receiver shares only commitment values: `one_time_pk`, `kyber_ct`, `next_lock_hash`, and
/// the bound `amount_le`. The sender never learns `s_next`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiverLockCommitment {
    #[serde(with = "BigArray")]
    pub one_time_pk: [u8; OTP_PK_BYTES],
    #[serde(with = "BigArray")]
    pub kyber_ct: [u8; KYBER_CT_BYTES],
    pub next_lock_hash: [u8; 32],
    pub commitment_id: [u8; 32],
    pub amount_le: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Spend {
    /// The spent coin id
    pub coin_id: [u8; 32],
    /// Merkle root of the epoch that committed this coin
    pub root: [u8; 32],
    /// Inclusion proof path for the coin id's leaf
    pub proof: Vec<([u8; 32], bool)>,
    /// Stealth output commitment for the new recipient
    pub commitment: [u8; 32],
    /// Nullifier (V3: H("unchained.nullifier.v3" || coin_id || unlock_preimage))
    pub nullifier: [u8; 32],
    /// The actual stealth output (one-time pk + enc payload)
    pub to: StealthOutput,
    /// Hashlock unlock preimage (V3). When present, enables signatureless spends.
    #[serde(default)]
    pub unlock_preimage: Option<[u8; 32]>,
    /// Next-hop lock hash (V3), computed from Kyber shared secret and context.
    #[serde(default)]
    pub next_lock_hash: Option<[u8; 32]>,
    /// Optional HTLC timeout epoch (epoch number T). If set, previous lock must be HTLC.
    #[serde(default)]
    pub htlc_timeout_epoch: Option<u64>,
    /// Commitment hash for claim path: ch_claim = CH(chain_id, coin_id, s_claim)
    #[serde(default)]
    pub htlc_ch_claim: Option<[u8;32]>,
    /// Commitment hash for refund path: ch_refund = CH(chain_id, coin_id, s_refund)
    #[serde(default)]
    pub htlc_ch_refund: Option<[u8;32]>,
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
        // Enforce amount binding to receiver commitment to avoid OTP/key mismatch
        if receiver_commitment.amount_le != amount {
            return Err(anyhow!("Receiver commitment amount mismatch"));
        }
        // Cross-check commitment_id integrity deterministically
        let computed_cid = commitment_id_v1(
            &receiver_commitment.one_time_pk,
            &receiver_commitment.kyber_ct,
            &receiver_commitment.next_lock_hash,
            &coin_id,
            amount,
            chain_id32,
        );
        if computed_cid != receiver_commitment.commitment_id {
            return Err(anyhow!("Receiver commitment_id mismatch"));
        }
        let commitment = commitment_of_stealth_ct(&receiver_commitment.kyber_ct);
        let mut to = StealthOutput {
            one_time_pk: [0u8; OTP_PK_BYTES],
            kyber_ct: [0u8; KYBER_CT_BYTES],
            amount_le: amount,
            view_tag: None,
        };
        to.one_time_pk.copy_from_slice(&receiver_commitment.one_time_pk);
        to.kyber_ct.copy_from_slice(&receiver_commitment.kyber_ct);

        // Nullifier (V3 updated): nf = BLAKE3("nf" || chain_id || coin_id || p)
        let nullifier = crate::crypto::nullifier_from_preimage(chain_id32, &coin_id, &unlock_preimage);
        // Next-hop lock hash provided by receiver
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
    /// - Claim path valid if current_epoch < T and CH(p) == ch_claim
    /// - Refund path valid if current_epoch >= T and CH(p) == ch_refund
    pub fn create_htlc_hashlock(
        coin_id: [u8; 32],
        anchor: &crate::epoch::Anchor,
        proof: Vec<([u8; 32], bool)>,
        unlock_preimage: [u8; 32],
        receiver_commitment: &ReceiverLockCommitment,
        amount: u64,
        chain_id32: &[u8; 32],
        timeout_epoch: u64,
        ch_claim: [u8;32],
        ch_refund: [u8;32],
    ) -> Result<Self> {
        // Enforce amount binding to receiver commitment
        if receiver_commitment.amount_le != amount {
            return Err(anyhow!("Receiver commitment amount mismatch"));
        }
        // Cross-check commitment_id integrity deterministically
        let computed_cid = commitment_id_v1(
            &receiver_commitment.one_time_pk,
            &receiver_commitment.kyber_ct,
            &receiver_commitment.next_lock_hash,
            &coin_id,
            amount,
            chain_id32,
        );
        if computed_cid != receiver_commitment.commitment_id {
            return Err(anyhow!("Receiver commitment_id mismatch"));
        }
        let commitment = commitment_of_stealth_ct(&receiver_commitment.kyber_ct);
        let mut to = StealthOutput { one_time_pk: [0u8; OTP_PK_BYTES], kyber_ct: [0u8; KYBER_CT_BYTES], amount_le: amount, view_tag: None };
        to.one_time_pk.copy_from_slice(&receiver_commitment.one_time_pk);
        to.kyber_ct.copy_from_slice(&receiver_commitment.kyber_ct);

        // Nullifier
        let nullifier = crate::crypto::nullifier_from_preimage(chain_id32, &coin_id, &unlock_preimage);
        // Next-hop lock hash provided by receiver (not HTLC for next hop by default)
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
    /// Note: A spend is chainable. The presence of a prior spend means the last owner
    /// is defined by that spend's one-time key or hashlock state.
    pub fn validate(&self, db: &crate::storage::Store) -> Result<()> {

        // 1) Coin exists (use tolerant decoder for legacy formats)
        let coin: crate::coin::Coin = db
            .get_coin(&self.coin_id)
            .context("Failed to query coin")?
            .ok_or_else(|| anyhow!("Referenced coin does not exist"))?;

        // 2) Genesis anchor required in this mode and empty proof
        let anchor: crate::epoch::Anchor = db
            .get("epoch", &0u64.to_le_bytes())
            .context("Failed to query genesis anchor")?
            .ok_or_else(|| anyhow!("Anchor not found for genesis"))?;
        if anchor.num != 0 { return Err(anyhow!("Non-genesis anchor in genesis-only validation")); }
        if anchor.merkle_root != self.root { return Err(anyhow!("Merkle root mismatch")); }
        if !self.proof.is_empty() { return Err(anyhow!("Expected empty proof for genesis")); }

        // 4) Commitment check – must be H(kyber_ct)
        let expected_commitment = crate::crypto::commitment_of_stealth_ct(&self.to.kyber_ct);
        if expected_commitment != self.commitment { return Err(anyhow!("Commitment mismatch")); }
        // 4b) Amount must match the committed coin value (no splits/merges in spend path)
        if self.to.amount_le != coin.value { return Err(anyhow!("Amount mismatch with coin value")); }

        // 5) Nullifier unseen (DB collision check)
        if db.get::<[u8; 1]>("nullifier", &self.nullifier)
            .context("Failed to query nullifier")?
            .is_some() {
            return Err(anyhow!("Nullifier already seen (double spend)"));
        }

        // 6) Authorization: require V3 hashlock, potentially HTLC-gated by epoch
        let preimage = self.unlock_preimage.ok_or_else(|| anyhow!("V3 hashlock preimage required"))?;
        // Determine expected previous lock hash
        let expected_lock_hash = if let Some(prev_spend) = db.get_spend_tolerant(&self.coin_id)? {
            prev_spend.next_lock_hash.ok_or_else(|| anyhow!("Previous spend missing next_lock_hash"))?
        } else {
            // Genesis lock hash stored in coin
            coin.lock_hash
        };
        let chain_id = db.get_chain_id()?;
        // If HTLC params present, enforce HTLC epoch gating and composite lock
        if let (Some(t), Some(ch_claim), Some(ch_refund)) = (self.htlc_timeout_epoch, self.htlc_ch_claim, self.htlc_ch_refund) {
            // Current epoch number
            let current_epoch = db.get::<crate::epoch::Anchor>("epoch", b"latest")
                .ok().flatten().map(|a| a.num).unwrap_or(0);
            let ch_of_pre = crate::crypto::commitment_hash_from_preimage(&chain_id, &self.coin_id, &preimage);
            if current_epoch < t {
                if ch_of_pre != ch_claim { return Err(anyhow!("HTLC claim path CH mismatch before timeout")); }
            } else {
                if ch_of_pre != ch_refund { return Err(anyhow!("HTLC refund path CH mismatch at/after timeout")); }
            }
            // Verify composite HTLC lock equals expected previous lock
            let expected_htlc = crate::crypto::htlc_lock_hash(&chain_id, &self.coin_id, t, &ch_claim, &ch_refund);
            if expected_lock_hash != expected_htlc { return Err(anyhow!("HTLC composite lock mismatch")); }
        } else {
            // Standard single-path hashlock: Check preimage matches (new scheme first, then legacy fallback). If no lock was committed (legacy), skip.
            if expected_lock_hash != [0u8; 32] {
                let lh_new = crate::crypto::lock_hash_from_preimage(&chain_id, &self.coin_id, &preimage);
                if lh_new != expected_lock_hash {
                    let lh_legacy = crate::crypto::lock_hash(&preimage);
                    if lh_legacy != expected_lock_hash {
                        return Err(anyhow!("Invalid hashlock preimage"));
                    }
                }
            }
        }
        // Recompute nullifier from preimage (accept both new and legacy schemes)
        let exp_nf_new = crate::crypto::nullifier_from_preimage(&chain_id, &self.coin_id, &preimage);
        if exp_nf_new != self.nullifier {
            let exp_nf_legacy = crate::crypto::compute_nullifier_legacy(&preimage, &self.coin_id, &chain_id);
            if exp_nf_legacy != self.nullifier {
                return Err(anyhow!("Nullifier mismatch"));
            }
        }
        // Enforce one-time use of receiver commitment via deterministic commitment_id
        let next_lock = self.next_lock_hash.ok_or_else(|| anyhow!("Missing next_lock_hash in V3 spend"))?;
        let cid = commitment_id_v1(&self.to.one_time_pk, &self.to.kyber_ct, &next_lock, &self.coin_id, self.to.amount_le, &chain_id);
        if db.get::<[u8;1]>("commitment_used", &cid)?.is_some() {
            return Err(anyhow!("Receiver commitment already used"));
        }

        // 7) Basic sanity of `to` (strict size checks before parsing)
        if self.to.one_time_pk.len() != OTP_PK_BYTES { return Err(anyhow!("Invalid one-time pk length")); }
        if self.to.kyber_ct.len() != KYBER_CT_BYTES { return Err(anyhow!("Invalid Kyber ct length")); }
        // Do not parse one_time_pk as a real Dilithium key; it's opaque bytes bound to Kyber
        let _ = KyberCt::from_bytes(&self.to.kyber_ct).context("Invalid Kyber ct")?;

        Ok(())
    }

    pub fn apply(&self, db: &crate::storage::Store) -> Result<()> {
        // Atomically mark spend, nullifier, and (when V3) commitment_id used
        let (Some(sp_cf), Some(nf_cf)) = (
            db.db.cf_handle("spend"),
            db.db.cf_handle("nullifier"),
        ) else { return Err(anyhow!("Column family missing")); };
        let cid_cf = db.db.cf_handle("commitment_used");
        let mut batch = rocksdb::WriteBatch::default();
        let bytes = bincode::serialize(self).context("serialize spend")?;
        batch.put_cf(sp_cf, &self.coin_id, &bytes);
        batch.put_cf(nf_cf, &self.nullifier, &[1u8;1]);
        if let Some(_) = self.unlock_preimage {
            if let Some(cf) = cid_cf {
                let chain_id = db.get_chain_id()?;
                let next_lock = self.next_lock_hash.ok_or_else(|| anyhow!("Missing next_lock_hash in V3 spend"))?;
                let cid = commitment_id_v1(&self.to.one_time_pk, &self.to.kyber_ct, &next_lock, &self.coin_id, self.to.amount_le, &chain_id);
                batch.put_cf(cf, &cid, &[1u8;1]);
            }
        }
        db.write_batch(batch).context("write spend batch")?;
        Ok(())
    }
}

// (Legacy TransferRecord variant removed)