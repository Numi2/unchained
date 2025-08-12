use serde::{Serialize, Deserialize};
use serde_big_array::BigArray;
use anyhow::{Result, Context, anyhow};

use crate::crypto::{Address, blake3_hash, address_from_pk, DILITHIUM3_PK_BYTES, DILITHIUM3_SK_BYTES, DILITHIUM3_SIG_BYTES};
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
use crate::crypto::{KYBER768_CT_BYTES as KYBER_CT_BYTES};

use aes_gcm_siv::aead::{Aead, KeyInit, Payload};
use aes_gcm_siv::Aes256GcmSiv;
use rand::rngs::OsRng;
use rand::RngCore;
// use hex; // not used here

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

// ------------ Transfer with stealth output + nullifier ------------
// V1 (legacy) publishes sender_pk and signs over full transfer body. Kept for compatibility.

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

    /// Create a stealth transfer to a recipient's Kyber PK.
    /// - Generates a one-time Dilithium3 keypair.
    /// - Encrypts the one-time SK using key derived from Kyber shared secret.
    /// - Builds stealth output, signs the transfer, computes nullifier.
    pub fn create_stealth(
        coin_id: [u8; 32],
        sender_pk: DiliPk,
        sender_sk: &DiliSk,
        recipient_kyber_pk: &KyberPk,
        prev_tx_hash: [u8; 32],
    ) -> Result<Self> {
        if coin_id == [0u8; 32] { return Err(anyhow!("Invalid coin_id")); }

        // 1) One-time DILITHIUM3 keypair (new owner key)
        let (ot_pk, ot_sk) = pqcrypto_dilithium::dilithium3::keypair(); // randomized
        let ot_pk_bytes = ot_pk.as_bytes();
        let ot_sk_bytes = ot_sk.as_bytes();

        // 2) Kyber encapsulation to recipient (returns (shared_secret, ciphertext))
        let (shared, ct) = encapsulate(recipient_kyber_pk);

        // 3) AEAD key from shared secret (BLAKE3 KDF)
        let aead_key = blake3::derive_key("unchained.stealth.aead.v1", shared.as_bytes());
        let cipher = Aes256GcmSiv::new_from_slice(&aead_key)
            .expect("key length is 32");

        // 4) Nonce and encrypt one-time SK, bind to one_time_pk as AAD
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let enc = cipher.encrypt(
            nonce.as_slice().into(),
            Payload { msg: ot_sk_bytes, aad: ot_pk_bytes },
        ).map_err(|_| anyhow!("AEAD encrypt one-time SK failed"))?;

        if enc.len() != DILITHIUM3_SK_BYTES + 16 {
            return Err(anyhow!("Unexpected AEAD ciphertext length"));
        }
        let mut enc_sk = [0u8; DILITHIUM3_SK_BYTES + 16];
        enc_sk.copy_from_slice(&enc);

        // 5) Assemble stealth output
        let mut to = StealthOutput {
            one_time_pk: [0u8; DILITHIUM3_PK_BYTES],
            kyber_ct: [0u8; KYBER_CT_BYTES],
            enc_sk_nonce: nonce,
            enc_one_time_sk: enc_sk,
        };
        to.one_time_pk.copy_from_slice(ot_pk_bytes);
        to.kyber_ct.copy_from_slice(ct.as_bytes());

        // 6) Build unsigned transfer
        let mut t = Transfer {
            coin_id,
            sender_pk: [0u8; DILITHIUM3_PK_BYTES],
            to,
            prev_tx_hash,
            sig: [0u8; DILITHIUM3_SIG_BYTES],
            nullifier: [0u8; 32],
        };
        t.sender_pk.copy_from_slice(sender_pk.as_bytes());

        // 7) Sign
        let sig = detached_sign(&t.signing_bytes(), sender_sk);
        t.sig.copy_from_slice(sig.as_bytes());

        // 8) Nullifier (unpredictable pre-broadcast; unique per spend)
        let mut preimage = Vec::with_capacity(12 + 32 + DILITHIUM3_SIG_BYTES);
        preimage.extend_from_slice(b"nullifier_v1");
        preimage.extend_from_slice(&t.coin_id);
        preimage.extend_from_slice(sig.as_bytes());
        let n = blake3_hash(&preimage);
        t.nullifier = n;

        Ok(t)
    }

    /// Validate transfer against DB:
    /// - coin exists
    /// - sender is current owner
    /// - signature is valid
    /// - prev_tx_hash matches current tip
    /// - nullifier unseen
    pub fn validate(&self, db: &crate::storage::Store) -> Result<()> {
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

        Ok(())
    }

    /// Apply transfer: store tx and mark nullifier seen.
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

// ------------ Transfer Manager (stealth send) ------------

pub struct TransferManager {
    pub(crate) db: std::sync::Arc<crate::storage::Store>,
}

impl TransferManager {
    pub fn new(db: std::sync::Arc<crate::storage::Store>) -> Self { Self { db } }

    fn get_previous_tx_hash(&self, coin_id: &[u8; 32]) -> Result<[u8; 32]> {
        if let Some(last) = self.get_transfer_for_coin(coin_id)? {
            Ok(last.hash())
        } else {
            Ok(*coin_id)
        }
    }

    pub fn get_transfer_for_coin(&self, coin_id: &[u8; 32]) -> Result<Option<Transfer>> {
        self.db.get("transfer", coin_id)
    }

    pub fn is_coin_spent(&self, coin_id: &[u8; 32]) -> Result<bool> {
        Ok(self.get_transfer_for_coin(coin_id)?.is_some())
    }

    /// Create + broadcast a stealth transfer to recipient's Kyber PK
    pub async fn send_stealth_transfer(
        &self,
        coin_id: [u8; 32],
        sender_pk: DiliPk,
        sender_sk: &DiliSk,
        recipient_kyber_pk: &KyberPk,
        network: &crate::network::NetHandle,
    ) -> Result<Transfer> {
        let prev_tx_hash = self.get_previous_tx_hash(&coin_id)?;
        let t = Transfer::create_stealth(
            coin_id,
            sender_pk,
            sender_sk,
            recipient_kyber_pk,
            prev_tx_hash,
        )?;

        t.validate(&self.db)?;
        t.apply(&self.db)?;
        network.gossip_transfer(&t).await;
        Ok(t)
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
    /// Nullifier derived from the spend secret and coin id
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

    /// Construct a spend using the recovered one-time key as the spend key
    pub fn create(
        coin_id: [u8; 32],
        anchor: &crate::epoch::Anchor,
        proof: Vec<([u8; 32], bool)>,
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

        // Nullifier = H_v2(spend_sk || coin_id)
        let nullifier = crate::crypto::compute_nullifier_v2(current_owner_sk.as_bytes(), &coin_id);

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

    /// Validate spend statelessly + against DB: proof, nullifier uniqueness, signature
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
        // 4) Nullifier unseen
        let seen: Option<[u8; 1]> = db.get("nullifier", &self.nullifier)
            .context("Failed to query nullifier")?;
        if seen.is_some() { return Err(anyhow!("Nullifier already seen (double spend)")); }
        // 5) Signature by current owner: verify against coin.creator_address
        // We need a pk whose address hashes to creator_address. For Dilithium, this means
        // reconstruct the pk from sig? Not possible. Instead, we require the signer pk equals the one that created the coin.
        // We can verify by checking that the public key derived from the signature and message matches coin.creator_address
        // However Dilithium has no key recovery. So we must store current owner pk somewhere.
        // In this design, the spend auth must be verified against a public key whose address equals coin's current owner address.
        // The signer public key is the one-time pk of the current owner (which created this coin or received via previous spend).
        // Therefore require that the signature verifies under some pk that hashes to expected owner address.
        // We reconstruct expected owner address from last transfer (or coin.creator_address if unspent).
        let last_transfer: Option<Transfer> = db.get("transfer", &self.coin_id)
            .context("Failed to query legacy transfer")?;
        let expected_owner_addr = match last_transfer {
            Some(ref t) => t.recipient(),
            None => coin.creator_address,
        };
        // Verify signature against both possibilities: the creator pk or the recipient one-time pk from last transfer.
        // If last_transfer exists, try its one_time_pk as the signer pk.
        let mut ok = false;
        if let Some(t) = last_transfer {
            if let Ok(pk) = DiliPk::from_bytes(&t.to.one_time_pk) {
                if address_from_pk(&pk) == expected_owner_addr {
                    if let Ok(sig) = DetachedSignature::from_bytes(&self.sig) {
                        if verify_detached_signature(&sig, &self.auth_bytes(), &pk).is_ok() { ok = true; }
                    }
                }
            }
        } else {
            // No previous transfer: owner is the coin creator, but we don't have their pk on chain.
            // For genesis spend, we fallback to V1 path in wallet to create a legacy transfer first.
            return Err(anyhow!("Cannot validate spend without previous owner pk (genesis spend requires legacy transfer)"));
        }
        if !ok { return Err(anyhow!("Invalid spend signature")); }
        // 6) Basic sanity of `to`
        let _ = DiliPk::from_bytes(&self.to.one_time_pk).context("Invalid one-time pk")?;
        let _ = KyberCt::from_bytes(&self.to.kyber_ct).context("Invalid Kyber ct")?;
        Ok(())
    }

    pub fn apply(&self, db: &crate::storage::Store) -> Result<()> {
        // Mark nullifier seen and store spend under its own CF keyed by coin_id
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