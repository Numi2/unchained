// transfer.rs
// Copyright 2025 The Unchained Authors
// SPDX-License-Identifier: Apache-2.0

//! Stealth transfer implementation (V1 kept read-only; V2 is active).
//! V1 transfers are no longer produced or gossiped. Use V2 `Spend`.

use serde::{Serialize, Deserialize};
use serde_big_array::BigArray;
use anyhow::{Result, Context, anyhow};

use crate::crypto::{
    Address, blake3_hash, address_from_pk,
    DILITHIUM3_PK_BYTES, DILITHIUM3_SK_BYTES, DILITHIUM3_SIG_BYTES,
    KYBER768_CT_BYTES as KYBER_CT_BYTES,
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

use aes_gcm_siv::aead::{Aead, KeyInit, Payload};
use aes_gcm_siv::Aes256GcmSiv;
use rand::rngs::OsRng;
use rand::RngCore;

// ------------ Stealth Output ------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StealthOutput {
    // One-time Dilithium3 public key (public, used as recipient address)
    #[serde(with = "BigArray")]
    pub one_time_pk: [u8; DILITHIUM3_PK_BYTES],
    // Kyber768 ciphertext so recipient can derive the shared secret
    #[serde(with = "BigArray")]
    pub kyber_ct: [u8; KYBER_CT_BYTES],
    // Nonce for AES-GCM-SIV (12 bytes)
    #[serde(with = "BigArray")]
    pub enc_sk_nonce: [u8; 12],
    // One-time Dilithium3 secret key encrypted under key = BLAKE3("stealth_aead_v1", shared_secret)
    // Length: DILITHIUM3_SK_BYTES + 16 (AEAD tag)
    #[serde(with = "BigArray")]
    pub enc_one_time_sk: [u8; DILITHIUM3_SK_BYTES + 16],
}

impl StealthOutput {
    /// Deterministic bytes used inside signatures/commitments.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(
            DILITHIUM3_PK_BYTES + KYBER_CT_BYTES + 12 + (DILITHIUM3_SK_BYTES + 16),
        );
        v.extend_from_slice(&self.one_time_pk);
        v.extend_from_slice(&self.kyber_ct);
        v.extend_from_slice(&self.enc_sk_nonce);
        v.extend_from_slice(&self.enc_one_time_sk);
        v
    }

    /// Recipient tries to recover the one-time secret key using their Kyber SK.
    pub fn try_recover_one_time_sk(&self, kyber_sk: &KyberSk) -> Result<DiliSk> {
        let ct = KyberCt::from_bytes(&self.kyber_ct)
            .context("Invalid Kyber ciphertext")?;
        let shared = decapsulate(&ct, kyber_sk);
        let aead_key = blake3::derive_key("unchained.stealth.aead.v1", shared.as_bytes());
        let cipher = Aes256GcmSiv::new_from_slice(&aead_key)
            .expect("key length is 32");
        let plaintext = cipher.decrypt(
            self.enc_sk_nonce.as_slice().into(),
            Payload {
                msg: &self.enc_one_time_sk,
                // bind decryption to one_time_pk to prevent cross-swap
                aad: &self.one_time_pk,
            },
        ).map_err(|_| anyhow!("Failed to decrypt one-time Dilithium SK"))?;

        let mut sk_bytes = [0u8; DILITHIUM3_SK_BYTES];
        if plaintext.len() != DILITHIUM3_SK_BYTES {
            return Err(anyhow!("Unexpected SK length"));
        }
        sk_bytes.copy_from_slice(&plaintext);
        let sk = DiliSk::from_bytes(&sk_bytes)
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

// ------------ Transfer V1 (legacy; read-only) ------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Transfer {
    pub coin_id: [u8; 32],
    // Sender's Dilithium3 full public key (reveals current owner)
    #[serde(with = "BigArray")]
    pub sender_pk: [u8; DILITHIUM3_PK_BYTES],
    // Stealth output to new owner
    pub to: StealthOutput,
    // Previous tx hash in this coin's chain
    pub prev_tx_hash: [u8; 32],
    // Dilithium3 signature by current owner over canonical bytes
    #[serde(with = "BigArray")]
    pub sig: [u8; DILITHIUM3_SIG_BYTES],
    // Nullifier for uniqueness (derived from signature; stored & checked by nodes)
    pub nullifier: [u8; 32],
}

impl Transfer {
    /// Canonical bytes-to-sign: coin_id ‖ sender_pk ‖ to.canonical_bytes() ‖ prev_tx_hash
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(
            32 + DILITHIUM3_PK_BYTES + self.to.canonical_bytes().len() + 32
        );
        v.extend_from_slice(&self.coin_id);
        v.extend_from_slice(&self.sender_pk);
        v.extend_from_slice(&self.to.canonical_bytes());
        v.extend_from_slice(&self.prev_tx_hash);
        v
    }

    /// BLAKE3 hash of canonical signing bytes (tx id / commitment)
    pub fn hash(&self) -> [u8; 32] {
        blake3_hash(&self.signing_bytes())
    }

    /// Recipient's one-time address (derived from one-time pk)
    pub fn recipient(&self) -> Address {
        self.to.recipient_address().expect("one-time pk already validated")
    }

    /// Sender's address (derived from sender pk)
    pub fn sender(&self) -> Result<Address> {
        let sender_pk = DiliPk::from_bytes(&self.sender_pk)
            .context("Invalid sender public key")?;
        Ok(address_from_pk(&sender_pk))
    }

    /// Validate legacy transfer locally (read-only path).
    /// - Reject if a V2 spend exists for the coin.
    /// - Validate signature, prev hash, basic stealth fields.
    /// - Recompute and enforce nullifier_v1.
    pub fn validate(&self, db: &crate::storage::Store) -> Result<()> {
        // Reject if already spent via V2
        if db.get::<crate::transfer::Spend>("spend", &self.coin_id)?
            .is_some() {
            return Err(anyhow!("Coin already spent (V2)"));
        }

        // 1) coin exists
        let coin: crate::coin::Coin = db.get("coin", &self.coin_id)
            .context("Failed to query coin")?
            .ok_or_else(|| anyhow!("Referenced coin does not exist"))?;

        // 2) determine current owner + expected prev hash
        let last_tx: Option<Transfer> = db.get("transfer", &self.coin_id)
            .context("Failed to query transfer")?;
        let (expected_owner_addr, expected_prev_hash) = match last_tx {
            Some(ref t) => (t.recipient(), t.hash()),
            None => (coin.creator_address, self.coin_id),
        };

        // 3) sender is current owner
        let sender_pk = DiliPk::from_bytes(&self.sender_pk)
            .context("Invalid sender public key")?;
        let sender_addr = address_from_pk(&sender_pk);
        if sender_addr != expected_owner_addr {
            return Err(anyhow!("Sender is not current owner"));
        }

        // 4) signature valid
        let sig = DetachedSignature::from_bytes(&self.sig)
            .context("Invalid signature format")?;
        verify_detached_signature(&sig, &self.signing_bytes(), &sender_pk)
            .map_err(|_| anyhow!("Invalid signature"))?;

        // 5) prev-tx chain
        if self.prev_tx_hash != expected_prev_hash {
            return Err(anyhow!("Invalid prev_tx_hash"));
        }

        // 6) basic stealth output sanity
        let _ = DiliPk::from_bytes(&self.to.one_time_pk)
            .context("Invalid one-time pk")?;
        let _ = KyberCt::from_bytes(&self.to.kyber_ct)
            .context("Invalid Kyber ct")?;

        // 7) nullifier unseen
        let seen: Option<[u8; 1]> = db.get("nullifier", &self.nullifier)
            .context("Failed to query nullifier")?;
        if seen.is_some() {
            return Err(anyhow!("Nullifier already seen (possible double spend)"));
        }

        // 8) Recompute and enforce nullifier_v1 = H("nullifier_v1" || coin_id || sig)
        let mut preimage = Vec::with_capacity(12 + 32 + DILITHIUM3_SIG_BYTES);
        preimage.extend_from_slice(b"nullifier_v1");
        preimage.extend_from_slice(&self.coin_id);
        preimage.extend_from_slice(&self.sig);
        let expected = blake3_hash(&preimage);
        if self.nullifier != expected {
            return Err(anyhow!("Nullifier mismatch"));
        }

        Ok(())
    }

    /// Apply transfer: store tx and mark nullifier seen. (Legacy local apply)
    pub fn apply(&self, db: &crate::storage::Store) -> Result<()> {
        db.put("transfer", &self.coin_id, self)
            .context("Failed to store transfer")?;
        db.put("nullifier", &self.nullifier, &[1u8; 1])
            .context("Failed to store nullifier")?;
        Ok(())
    }

    /// Convenience checks
    pub fn is_to(&self, addr: &Address) -> bool { &self.recipient() == addr }
    pub fn is_from(&self, addr: &Address) -> Result<bool> { Ok(self.sender()? == *addr) }
}

// ------------ Transfer Manager (V1 disabled for sending) ------------

pub struct TransferManager {
    pub(crate) db: std::sync::Arc<crate::storage::Store>,
}

impl TransferManager {
    pub fn new(db: std::sync::Arc<crate::storage::Store>) -> Self { Self { db } }

    pub fn get_transfer_for_coin(&self, coin_id: &[u8; 32]) -> Result<Option<Transfer>> {
        self.db.get("transfer", coin_id)
    }

    pub fn is_coin_spent(&self, coin_id: &[u8; 32]) -> Result<bool> {
        // Consider a coin spent if either a V2 spend exists or a legacy transfer exists
        if self.db.get::<crate::transfer::Spend>("spend", coin_id)?.is_some() { return Ok(true); }
        Ok(self.get_transfer_for_coin(coin_id)?.is_some())
    }

    /// Legacy V1 send path is disabled. Use V2 Spend.
    pub async fn send_stealth_transfer(
        &self,
        _coin_id: [u8; 32],
        _sender_pk: DiliPk,
        _sender_sk: &DiliSk,
        _recipient_kyber_pk: &KyberPk,
        _network: &crate::network::NetHandle,
    ) -> Result<Transfer> {
        Err(anyhow!("Legacy V1 transfers are disabled. Use V2 Spend::create/apply."))
    }

    /// Optional: scan all transfers to find those addressed to you (by Kyber SK).
    pub fn scan_for_me(&self, kyber_sk: &KyberSk) -> Result<Vec<(Transfer, DiliSk)>> {
        let cf = self.db.db.cf_handle("transfer")
            .ok_or_else(|| anyhow!("'transfer' column family missing"))?;
        let iter = self.db.db.iterator_cf(cf, rocksdb::IteratorMode::Start);

        let mut found = Vec::new();
        for item in iter {
            let (_key, value) = item?;
            if let Ok(t) = bincode::deserialize::<Transfer>(&value) {
                if let Ok(sk) = t.to.try_recover_one_time_sk(kyber_sk) {
                    // Confirm that addr(one_time_pk) matches computed recipient
                    let addr = t.recipient();
                    let pk = DiliPk::from_bytes(&t.to.one_time_pk)?;
                    if address_from_pk(&pk) == addr {
                        found.push((t, sk));
                    }
                }
            }
        }
        Ok(found)
    }
}

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
    /// Authorization bytes: root || nullifier || commitment || coin_id
    pub fn auth_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(32 + 32 + 32 + 32);
        v.extend_from_slice(&self.root);
        v.extend_from_slice(&self.nullifier);
        v.extend_from_slice(&self.commitment);
        v.extend_from_slice(&self.coin_id);
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
        recipient_kyber_pk: &KyberPk,
    ) -> Result<Self> {
        // Build new stealth output
        let (ot_pk, ot_sk) = pqcrypto_dilithium::dilithium3::keypair();
        let ot_pk_bytes = ot_pk.as_bytes();
        let ot_sk_bytes = ot_sk.as_bytes();

        // Kyber encapsulation returns (shared_secret, ciphertext)
        let (shared, ct) = encapsulate(recipient_kyber_pk);
        let aead_key = blake3::derive_key("unchained.stealth.aead.v1", shared.as_bytes());
        let cipher = Aes256GcmSiv::new_from_slice(&aead_key).expect("key length is 32");
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let enc = cipher.encrypt(
            nonce.as_slice().into(),
            Payload { msg: ot_sk_bytes, aad: ot_pk_bytes },
        ).map_err(|_| anyhow!("AEAD encrypt one-time SK failed"))?;
        if enc.len() != DILITHIUM3_SK_BYTES + 16 { return Err(anyhow!("Unexpected AEAD ciphertext length")); }
        let mut enc_sk = [0u8; DILITHIUM3_SK_BYTES + 16];
        enc_sk.copy_from_slice(&enc);

        let mut to = StealthOutput {
            one_time_pk: [0u8; DILITHIUM3_PK_BYTES],
            kyber_ct: [0u8; KYBER_CT_BYTES],
            enc_sk_nonce: nonce,
            enc_one_time_sk: enc_sk,
        };
        to.one_time_pk.copy_from_slice(ot_pk_bytes);
        to.kyber_ct.copy_from_slice(ct.as_bytes());

        // Commitment = H(to.canonical_bytes())
        let commitment = crate::crypto::commitment_of_stealth_output(&to.canonical_bytes());

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

        // 2) Anchor exists and root matches
        let anchor: crate::epoch::Anchor = db.get("anchor", &coin.epoch_hash)
            .context("Failed to query anchor")?
            .ok_or_else(|| anyhow!("Anchor not found for coin's epoch"))?;
        if anchor.merkle_root != self.root { return Err(anyhow!("Merkle root mismatch")); }

        // 3) Proof verifies
        let leaf = crate::coin::Coin::id_to_leaf_hash(&self.coin_id);
        if !crate::epoch::MerkleTree::verify_proof(&leaf, &self.proof, &self.root) {
            return Err(anyhow!("Invalid Merkle proof"));
        }

        // 4) Commitment check – must be H(canonical_bytes(to))
        let expected_commitment = crate::crypto::commitment_of_stealth_output(&self.to.canonical_bytes());
        if expected_commitment != self.commitment { return Err(anyhow!("Commitment mismatch")); }

        // 5) Nullifier unseen (DB collision check)
        if db.get::<[u8; 1]>("nullifier", &self.nullifier)
            .context("Failed to query nullifier")?
            .is_some() {
            return Err(anyhow!("Nullifier already seen (double spend)"));
        }

        // 6) Determine expected current owner (prefer last V2 spend, else legacy transfer, else creator)
        let last_spend: Option<Spend> = db.get("spend", &self.coin_id)
            .context("Failed to query last spend")?;
        let last_transfer: Option<Transfer> = db.get("transfer", &self.coin_id)
            .context("Failed to query legacy transfer")?;

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
        // b) Else, if there was a legacy transfer, the owner is its one-time pk
        if verified_pk.is_none() {
            if let Some(t) = &last_transfer {
                if let Ok(pk) = DiliPk::from_bytes(&t.to.one_time_pk) {
                    if verify_detached_signature(&sig, &self.auth_bytes(), &pk).is_ok() {
                        verified_pk = Some(pk);
                    }
                }
            }
        }
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

        // 8) Basic sanity of `to`
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransferRecord {
    V1(Transfer),
    V2(Spend),
}