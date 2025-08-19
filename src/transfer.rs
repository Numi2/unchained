// transfer.rs
// Copyright 2025 The Unchained Authors
// SPDX-License-Identifier: Apache-2.0

//! Stealth transfer implementation (V3 hashlock only).

use serde::{Serialize, Deserialize};
use serde_big_array::BigArray;
use anyhow::{Result, Context, anyhow};

use crate::crypto::{
    Address, address_from_pk,
    DILITHIUM3_PK_BYTES, DILITHIUM3_SK_BYTES,
    KYBER768_CT_BYTES as KYBER_CT_BYTES,
    commitment_of_stealth_ct, stealth_seed_v1, dilithium3_seeded_keypair,
    derive_next_lock_secret, commitment_id_v1,
};
use pqcrypto_dilithium::dilithium3::{
    PublicKey as DiliPk, SecretKey as DiliSk,
};
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};

use pqcrypto_kyber::kyber768::{
    SecretKey as KyberSk, Ciphertext as KyberCt,
    decapsulate,
};
use pqcrypto_traits::kem::{Ciphertext as KyberCtTrait, SharedSecret as KyberSharedSecretTrait};

// use subtle::ConstantTimeEq;  // not needed; using fully-qualified call

// ------------ Stealth Output ------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StealthOutput {
    // One-time Dilithium3 public key (public, used as recipient address)
    #[serde(with = "BigArray")]
    pub one_time_pk: [u8; DILITHIUM3_PK_BYTES],
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
    /// Deterministic bytes used inside signatures/commitments.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(
            DILITHIUM3_PK_BYTES + KYBER_CT_BYTES + 12 + (DILITHIUM3_SK_BYTES + 16),
        );
        v.extend_from_slice(&self.one_time_pk);
        v.extend_from_slice(&self.kyber_ct);
        v.extend_from_slice(&self.amount_le.to_le_bytes());
        if let Some(vt) = self.view_tag { v.push(vt); }
        v
    }

    /// Recipient tries to recover the one-time secret key using their Kyber SK and receiver identity.
    /// Tries address-bound seed first (new), then falls back to legacy PK-bound seed for compatibility.
    pub fn try_recover_one_time_sk(&self, kyber_sk: &KyberSk, receiver_dili_pk: &DiliPk, chain_id32: &[u8;32]) -> Result<DiliSk> {
        let ct = KyberCt::from_bytes(&self.kyber_ct)
            .context("Invalid Kyber ciphertext")?;
        let shared = decapsulate(&ct, kyber_sk);
        // View tag check if present (cheap early filter)
        if let Some(vt) = self.view_tag {
            if crate::crypto::view_tag(shared.as_bytes()) != vt { return Err(anyhow!("View tag mismatch")); }
        }
        let value_tag = self.amount_le.to_le_bytes();
        // Bind stealth seed to receiver address (stable identity) rather than raw Dilithium PK bytes
        let receiver_addr = address_from_pk(receiver_dili_pk);
        let seed_addr = stealth_seed_v1(shared.as_bytes(), &receiver_addr, ct.as_bytes(), &value_tag, chain_id32);
        let (derived_pk_addr, derived_sk_addr) = dilithium3_seeded_keypair(seed_addr);
        if subtle::ConstantTimeEq::ct_eq(derived_pk_addr.as_bytes(), &self.one_time_pk).unwrap_u8() == 1 {
            let sk = DiliSk::from_bytes(derived_sk_addr.as_bytes()).context("Invalid Dilithium3 SK bytes")?;
            return Ok(sk);
        }
        // Legacy fallback: derive using receiver Dilithium PK bytes
        let seed_legacy = stealth_seed_v1(shared.as_bytes(), receiver_dili_pk.as_bytes(), ct.as_bytes(), &value_tag, chain_id32);
        let (derived_pk_legacy, derived_sk_legacy) = dilithium3_seeded_keypair(seed_legacy);
        if subtle::ConstantTimeEq::ct_eq(derived_pk_legacy.as_bytes(), &self.one_time_pk).unwrap_u8() == 1 {
            let sk = DiliSk::from_bytes(derived_sk_legacy.as_bytes()).context("Invalid Dilithium3 SK bytes")?;
            return Ok(sk);
        }
        Err(anyhow!("Derived OTP pk mismatch"))
    }

    /// Recipient derives the lock secret for next-hop ownership using Kyber shared secret and context.
    pub fn derive_lock_secret(&self, kyber_sk: &KyberSk, coin_id: &[u8;32], chain_id32: &[u8;32]) -> Result<[u8;32]> {
        let ct = KyberCt::from_bytes(&self.kyber_ct)
            .context("Invalid Kyber ciphertext")?;
        let shared = decapsulate(&ct, kyber_sk);
        Ok(derive_next_lock_secret(shared.as_bytes(), ct.as_bytes(), self.amount_le, coin_id, chain_id32))
    }

    /// Compute the recipient Address as hash of the one-time pk (same addressing as normal keys).
    pub fn recipient_address(&self) -> Result<Address> {
        let pk = DiliPk::from_bytes(&self.one_time_pk)
            .context("Invalid one-time Dilithium3 public key")?;
        Ok(address_from_pk(&pk))
    }
}
// (Legacy V1 transfer has been fully removed.)

// ------------ V3 Hashlock Spend ------------

/// Receiver-supplied lock commitment for V3 hashlock spends.
/// The receiver generates `kyber_ct` (encapsulated to their own Kyber PK), decapsulates to get
/// the shared secret, derives the one-time Dilithium key deterministically using `stealth_seed_v1`,
/// and computes the next-hop lock preimage `s_next` using `derive_next_lock_secret`.
/// The receiver shares only commitment values: `one_time_pk`, `kyber_ct`, `next_lock_hash`, and
/// the bound `amount_le`. The sender never learns `s_next`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiverLockCommitment {
    #[serde(with = "BigArray")]
    pub one_time_pk: [u8; DILITHIUM3_PK_BYTES],
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
}

impl Spend {
    /// Authorization bytes: root || nullifier || commitment || coin_id || to.canonical_bytes() || [next_lock_hash?]
    pub fn auth_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(32 + 32 + 32 + 32 + self.to.canonical_bytes().len() + 32);
        v.extend_from_slice(&self.root);
        v.extend_from_slice(&self.nullifier);
        v.extend_from_slice(&self.commitment);
        v.extend_from_slice(&self.coin_id);
        v.extend_from_slice(&self.to.canonical_bytes());
        if let Some(nh) = self.next_lock_hash {
            v.extend_from_slice(&nh);
        }
        v
    }

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
            one_time_pk: [0u8; DILITHIUM3_PK_BYTES],
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

        // 2) Anchor exists and root matches (use the epoch that COMMITTED this coin)
        let commit_epoch = db
            .get_epoch_for_coin(&self.coin_id)
            .context("Failed to query coin->epoch mapping")?
            .ok_or_else(|| anyhow!("Missing coin->epoch index for committed coin"))?;
        let anchor: crate::epoch::Anchor = db
            .get("epoch", &commit_epoch.to_le_bytes())
            .context("Failed to query committing anchor by epoch number")?
            .ok_or_else(|| anyhow!("Anchor not found for committed epoch"))?;
        if anchor.merkle_root != self.root { return Err(anyhow!("Merkle root mismatch")); }

        // 3) Proof verifies
        let expected_len = crate::epoch::MerkleTree::expected_proof_len(anchor.coin_count);
        if self.proof.len() != expected_len { return Err(anyhow!("Merkle proof length mismatch")); }
        let leaf = crate::coin::Coin::id_to_leaf_hash(&self.coin_id);
        if !crate::epoch::MerkleTree::verify_proof(&leaf, &self.proof, &self.root) {
            return Err(anyhow!("Invalid Merkle proof"));
        }

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

        // 6) Authorization: require V3 hashlock
        let preimage = self.unlock_preimage.ok_or_else(|| anyhow!("V3 hashlock preimage required"))?;
        // Determine expected previous lock hash
        let expected_lock_hash = if let Some(prev_spend) = db.get_spend_tolerant(&self.coin_id)? {
            prev_spend.next_lock_hash.ok_or_else(|| anyhow!("Previous spend missing next_lock_hash"))?
        } else {
            // Genesis lock hash stored in coin
            coin.lock_hash
        };
        // Check preimage matches
        let chain_id = db.get_chain_id()?;
        if crate::crypto::lock_hash_from_preimage(&chain_id, &self.coin_id, &preimage) != expected_lock_hash { return Err(anyhow!("Invalid hashlock preimage")); }
        // Recompute nullifier using new derivation from preimage
        let exp_nf = crate::crypto::nullifier_from_preimage(&chain_id, &self.coin_id, &preimage);
        if exp_nf != self.nullifier { return Err(anyhow!("Nullifier mismatch")); }
        // Enforce one-time use of receiver commitment via deterministic commitment_id
        let next_lock = self.next_lock_hash.ok_or_else(|| anyhow!("Missing next_lock_hash in V3 spend"))?;
        let cid = commitment_id_v1(&self.to.one_time_pk, &self.to.kyber_ct, &next_lock, &self.coin_id, self.to.amount_le, &chain_id);
        if db.get::<[u8;1]>("commitment_used", &cid)?.is_some() {
            return Err(anyhow!("Receiver commitment already used"));
        }

        // 7) Basic sanity of `to` (strict size checks before parsing)
        if self.to.one_time_pk.len() != DILITHIUM3_PK_BYTES { return Err(anyhow!("Invalid one-time pk length")); }
        if self.to.kyber_ct.len() != KYBER_CT_BYTES { return Err(anyhow!("Invalid Kyber ct length")); }
        let _ = DiliPk::from_bytes(&self.to.one_time_pk).context("Invalid one-time pk")?;
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
        db.db.write(batch).context("write spend batch")?;
        Ok(())
    }
}

// (Legacy TransferRecord variant removed)