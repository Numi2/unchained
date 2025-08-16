// transfer.rs
// Copyright 2025 The Unchained Authors
// SPDX-License-Identifier: Apache-2.0

//! Stealth transfer implementation (V2 only).

use serde::{Serialize, Deserialize};
use serde_big_array::BigArray;
use anyhow::{Result, Context, anyhow};

use crate::crypto::{
    Address, blake3_hash, address_from_pk,
    DILITHIUM3_PK_BYTES, DILITHIUM3_SK_BYTES, DILITHIUM3_SIG_BYTES,
    KYBER768_CT_BYTES as KYBER_CT_BYTES,
    commitment_of_stealth_ct, stealth_seed_v1, dilithium3_seeded_keypair,
};
use pqcrypto_dilithium::dilithium3::{
    PublicKey as DiliPk, SecretKey as DiliSk, DetachedSignature,
    detached_sign, verify_detached_signature,
};
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _, DetachedSignature as _};

use pqcrypto_kyber::kyber768::{
    PublicKey as KyberPk, SecretKey as KyberSk, Ciphertext as KyberCt,
    encapsulate, decapsulate,
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
        v
    }

    /// Recipient tries to recover the one-time secret key using their Kyber SK and receiver Dilithium PK.
    pub fn try_recover_one_time_sk(&self, kyber_sk: &KyberSk, receiver_dili_pk: &DiliPk, chain_id32: &[u8;32]) -> Result<DiliSk> {
        let ct = KyberCt::from_bytes(&self.kyber_ct)
            .context("Invalid Kyber ciphertext")?;
        let shared = decapsulate(&ct, kyber_sk);
        let value_tag = self.amount_le.to_le_bytes();
        let seed = stealth_seed_v1(shared.as_bytes(), receiver_dili_pk.as_bytes(), ct.as_bytes(), &value_tag, chain_id32);
        let (derived_pk, derived_sk) = dilithium3_seeded_keypair(seed);
        // Constant-time compare
        if subtle::ConstantTimeEq::ct_eq(derived_pk.as_bytes(), &self.one_time_pk).unwrap_u8() != 1 {
            return Err(anyhow!("Derived OTP pk mismatch"));
        }
        let sk = DiliSk::from_bytes(derived_sk.as_bytes())
            .context("Invalid Dilithium3 SK bytes")?;
        Ok(sk)
    }

    /// Compute the recipient Address as hash of the one-time pk (same addressing as normal keys).
    pub fn recipient_address(&self) -> Result<Address> {
        let pk = DiliPk::from_bytes(&self.one_time_pk)
            .context("Invalid one-time Dilithium3 public key")?;
        Ok(address_from_pk(&pk))
    }
}
// (Legacy V1 transfer has been fully removed.)

// ------------ Spend-key-blinded nullifier (V2) ------------

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
    /// Nullifier derived from the (public) spend key and coin id
    pub nullifier: [u8; 32],
    /// Dilithium3 signature by the current owner sk over auth_bytes()
    #[serde(with = "BigArray")]
    pub sig: [u8; DILITHIUM3_SIG_BYTES],
    /// The actual stealth output (one-time pk + enc payload)
    pub to: StealthOutput,
}

impl Spend {
    /// Authorization bytes: root || nullifier || commitment || coin_id || to.canonical_bytes()
    pub fn auth_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(32 + 32 + 32 + 32 + self.to.canonical_bytes().len());
        v.extend_from_slice(&self.root);
        v.extend_from_slice(&self.nullifier);
        v.extend_from_slice(&self.commitment);
        v.extend_from_slice(&self.coin_id);
        v.extend_from_slice(&self.to.canonical_bytes());
        v
    }

    /// Construct a spend.
    /// NOTE: The nullifier is derived from the PUBLIC current owner key + coin_id (not SK),
    /// so validators can recompute and enforce uniqueness.
    pub fn create(
        coin_id: [u8; 32],
        anchor: &crate::epoch::Anchor,
        proof: Vec<([u8; 32], bool)>,
        current_owner_pk: &DiliPk,
        current_owner_sk: &DiliSk,
        recipient_dili_pk: &DiliPk,
        recipient_kyber_pk: &KyberPk,
        amount: u64,
        chain_id32: &[u8; 32],
    ) -> Result<Self> {
        let (shared, ct) = encapsulate(recipient_kyber_pk);
        let commitment = commitment_of_stealth_ct(ct.as_bytes());
        let value_tag = amount.to_le_bytes();
        let chain_id = chain_id32;
        let seed = stealth_seed_v1(shared.as_bytes(), recipient_dili_pk.as_bytes(), ct.as_bytes(), &value_tag, chain_id);
        let (ot_pk, _ot_sk) = dilithium3_seeded_keypair(seed);

        let mut to = StealthOutput {
            one_time_pk: [0u8; DILITHIUM3_PK_BYTES],
            kyber_ct: [0u8; KYBER_CT_BYTES],
            amount_le: amount,
        };
        to.one_time_pk.copy_from_slice(ot_pk.as_bytes());
        to.kyber_ct.copy_from_slice(ct.as_bytes());

        // Commitment was defined as H(kyber_ct)

        // Nullifier (public-key-based): H("unchained.nullifier.v2" || owner_pk || coin_id)
        let mut pre = Vec::with_capacity(24 + DILITHIUM3_PK_BYTES + 32);
        pre.extend_from_slice(b"unchained.nullifier.v2");
        pre.extend_from_slice(current_owner_pk.as_bytes());
        pre.extend_from_slice(&coin_id);
        let nullifier = blake3_hash(&pre);

        let mut spend = Spend {
            coin_id,
            root: anchor.merkle_root,
            proof,
            commitment,
            nullifier,
            sig: [0u8; DILITHIUM3_SIG_BYTES],
            to,
        };
        let sig = detached_sign(&spend.auth_bytes(), current_owner_sk);
        spend.sig.copy_from_slice(sig.as_bytes());
        Ok(spend)
    }

    /// Validate spend statelessly + against DB: proof, uniqueness, signature, commitment, nullifier.
    /// Note: A V2 spend is chainable. The presence of a prior spend means the last owner
    /// is defined by that spend's one-time key; it is not a terminal state. Double-spend
    /// is prevented by the nullifier uniqueness check.
    pub fn validate(&self, db: &crate::storage::Store) -> Result<()> {

        // 1) Coin exists
        let coin: crate::coin::Coin = db.get("coin", &self.coin_id)
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

        // 5) Nullifier unseen (DB collision check)
        if db.get::<[u8; 1]>("nullifier", &self.nullifier)
            .context("Failed to query nullifier")?
            .is_some() {
            return Err(anyhow!("Nullifier already seen (double spend)"));
        }

        // 6) Determine expected current owner (prefer last V2 spend, else creator)
        let last_spend: Option<Spend> = db.get("spend", &self.coin_id)
            .context("Failed to query last spend")?;

        let sig = DetachedSignature::from_bytes(&self.sig)
            .context("Invalid spend signature format")?;

        let mut verified_pk: Option<DiliPk> = None;
        // a) If there was a previous V2 spend, the owner is that spend's one-time pk
        if verified_pk.is_none() {
            if let Some(sp) = &last_spend {
                if let Ok(pk) = DiliPk::from_bytes(&sp.to.one_time_pk) {
                    if verify_detached_signature(&sig, &self.auth_bytes(), &pk).is_ok() {
                        verified_pk = Some(pk);
                    }
                }
            }
        }
        // (Legacy V1 transfer support removed)
        // c) Else genesis owner is the coin creator
        if verified_pk.is_none() && coin.creator_pk != [0u8; DILITHIUM3_PK_BYTES] {
            if let Ok(pk) = DiliPk::from_bytes(&coin.creator_pk) {
                if verify_detached_signature(&sig, &self.auth_bytes(), &pk).is_ok() {
                    verified_pk = Some(pk);
                }
            }
        }
        let pk = verified_pk.ok_or_else(|| anyhow!("Invalid spend signature"))?;

        // 7) Recompute and enforce public-key-based nullifier
        let mut pre = Vec::with_capacity(24 + DILITHIUM3_PK_BYTES + 32);
        pre.extend_from_slice(b"unchained.nullifier.v2");
        pre.extend_from_slice(pk.as_bytes());
        pre.extend_from_slice(&self.coin_id);
        let expected_nullifier = blake3_hash(&pre);
        if self.nullifier != expected_nullifier {
            return Err(anyhow!("Nullifier mismatch"));
        }

        // 8) Basic sanity of `to` (strict size checks before parsing)
        if self.to.one_time_pk.len() != DILITHIUM3_PK_BYTES { return Err(anyhow!("Invalid one-time pk length")); }
        if self.to.kyber_ct.len() != KYBER_CT_BYTES { return Err(anyhow!("Invalid Kyber ct length")); }
        let _ = DiliPk::from_bytes(&self.to.one_time_pk).context("Invalid one-time pk")?;
        let _ = KyberCt::from_bytes(&self.to.kyber_ct).context("Invalid Kyber ct")?;

        Ok(())
    }

    pub fn apply(&self, db: &crate::storage::Store) -> Result<()> {
        // Mark nullifier seen and store spend as the latest state under its own CF keyed by coin_id
        db.put("spend", &self.coin_id, self)?;
        db.put("nullifier", &self.nullifier, &[1u8;1])?;
        Ok(())
    }
}

// (Legacy TransferRecord variant removed)