use crate::{
    storage::Store,
    crypto::{self, Address, DILITHIUM3_PK_BYTES, DILITHIUM3_SK_BYTES},
};
use crate::ringsig::{RingSignatureScheme, RingPublicKey};
use crate::ring_transfer::{RingTransfer, RingOutput};
use pqcrypto_dilithium::dilithium3::{PublicKey, SecretKey};
use anyhow::{Result, Context, anyhow, bail};
use std::sync::Arc;
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
use argon2::{Argon2, Params};
use chacha20poly1305::{aead::{Aead, NewAead}, XChaCha20Poly1305, Key, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use rpassword;
use atty;

const WALLET_KEY: &[u8] = b"default_keypair";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const WALLET_VERSION_ENCRYPTED: u8 = 1;
// Tunable KDF parameters for wallet encryption
const WALLET_KDF_MEM_KIB: u32 = 256 * 1024; // 256 MiB
const WALLET_KDF_TIME_COST: u32 = 3; // iterations

pub struct Wallet {
    _db: std::sync::Weak<Store>,
    pk: PublicKey,
    sk: SecretKey,
    address: Address,
}

impl Wallet {
    /// Loads the default keypair from the store, or creates a new one if none exists.
    /// This ensures the miner's identity is persistent across restarts.
    pub fn load_or_create(db: Arc<Store>) -> Result<Self> {
        // Helper to obtain a pass-phrase depending on environment
        fn obtain_passphrase(prompt: &str) -> Result<String> {
            if let Ok(p) = std::env::var("WALLET_PASSPHRASE") {
                return Ok(p);
            }
            if atty::is(atty::Stream::Stdin) {
                let pw = rpassword::prompt_password(prompt)
                    .context("Failed to read pass-phrase")?;
                Ok(pw)
            } else {
                // Non-interactive (prod/CI): require env var, fail fast if missing
                std::env::var("WALLET_PASSPHRASE").map_err(|_| anyhow!("WALLET_PASSPHRASE is required in non-interactive mode"))
            }
        }

        if let Some(encoded) = db.get::<Vec<u8>>("wallet", WALLET_KEY)? {
            // Detect legacy plaintext wallet (pk + sk concatenated)
            if encoded.len() == DILITHIUM3_PK_BYTES + DILITHIUM3_SK_BYTES {
                println!("⚠️  Detected legacy plaintext wallet – migrating to encrypted format...");
                let (pk_bytes, sk_bytes) = encoded.split_at(DILITHIUM3_PK_BYTES);
                let pk = PublicKey::from_bytes(pk_bytes)
                    .with_context(|| "Failed to decode public key from wallet")?;
                let sk = SecretKey::from_bytes(sk_bytes)
                    .with_context(|| "Failed to decode secret key from wallet")?;

                let passphrase = obtain_passphrase("Set a pass-phrase to encrypt your wallet: ")?;
                let mut salt = [0u8; SALT_LEN];
                OsRng.fill_bytes(&mut salt);

                let mut key = [0u8; 32];
                let params = Params::new(WALLET_KDF_MEM_KIB, WALLET_KDF_TIME_COST, 1, None)
                    .map_err(|e| anyhow!("Invalid Argon2id params: {}", e))?;
                Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
                    .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
                    .map_err(|e| anyhow!("Argon2id key derivation failed: {}", e))?;

                let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
                let mut nonce = [0u8; NONCE_LEN];
                OsRng.fill_bytes(&mut nonce);
                let ciphertext = cipher
                    .encrypt(XNonce::from_slice(&nonce), sk.as_bytes())
                    .map_err(|e| anyhow!("Failed to encrypt secret key: {}", e))?;
                // best-effort zeroize
                key.iter_mut().for_each(|b| *b = 0);

                let mut new_encoded = Vec::with_capacity(DILITHIUM3_PK_BYTES + 1 + SALT_LEN + NONCE_LEN + ciphertext.len());
                new_encoded.extend_from_slice(pk.as_bytes());
                new_encoded.push(WALLET_VERSION_ENCRYPTED);
                new_encoded.extend_from_slice(&salt);
                new_encoded.extend_from_slice(&nonce);
                new_encoded.extend_from_slice(&ciphertext);
                db.put("wallet", WALLET_KEY, &new_encoded)?;

                let address = crypto::address_from_pk(&pk);
                println!("🔐 Wallet migrated and unlocked. Address: {}", hex::encode(address));
                return Ok(Wallet { _db: Arc::downgrade(&db), pk, sk, address });
            }

            // --- Encrypted wallet path ---
            let pk_bytes = &encoded[0..DILITHIUM3_PK_BYTES];
            let version = encoded[DILITHIUM3_PK_BYTES];
            if version != WALLET_VERSION_ENCRYPTED {
                bail!("Unsupported wallet version: {}", version);
            }

            let salt_start = DILITHIUM3_PK_BYTES + 1;
            let nonce_start = salt_start + SALT_LEN;
            let ct_start = nonce_start + NONCE_LEN;

            let salt = &encoded[salt_start..salt_start + SALT_LEN];
            let nonce = &encoded[nonce_start..nonce_start + NONCE_LEN];
            let ciphertext = &encoded[ct_start..];

            let passphrase = obtain_passphrase("Enter wallet pass-phrase: ")?;
            let mut key = [0u8; 32];
            let params = Params::new(WALLET_KDF_MEM_KIB, WALLET_KDF_TIME_COST, 1, None)
                .map_err(|e| anyhow!("Invalid Argon2id params: {}", e))?;
            Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
                .hash_password_into(passphrase.as_bytes(), salt, &mut key)
                .map_err(|e| anyhow!("Argon2id key derivation failed: {}", e))?;

            let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
            let sk_bytes = cipher
                .decrypt(XNonce::from_slice(nonce), ciphertext)
                .map_err(|_| anyhow!("Invalid pass-phrase"))?;

            let pk = PublicKey::from_bytes(pk_bytes)
                .with_context(|| "Failed to decode public key")?;
            let sk = SecretKey::from_bytes(&sk_bytes)
                .with_context(|| "Failed to decode secret key bytes")?;
            // zeroize key and decrypted buffer
            let mut key_zero = key;
            key_zero.iter_mut().for_each(|b| *b = 0);

            let address = crypto::address_from_pk(&pk);
            // Avoid printing address unless explicitly requested via logs
            return Ok(Wallet { _db: Arc::downgrade(&db), pk, sk, address })

        }

        // --- Brand new wallet ---
        println!("✨ No wallet found, creating a new one...");
        let (pk, sk) = crypto::dilithium3_keypair();
        let address = crypto::address_from_pk(&pk);

        let passphrase = obtain_passphrase("Set a pass-phrase for your new wallet: ")?;
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);

        let mut key = [0u8; 32];
        let params = Params::new(WALLET_KDF_MEM_KIB, WALLET_KDF_TIME_COST, 1, None)
            .map_err(|e| anyhow!("Invalid Argon2id params: {}", e))?;
        Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
            .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
            .map_err(|e| anyhow!("Argon2id key derivation failed: {}", e))?;

        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), sk.as_bytes())
            .map_err(|e| anyhow!("Failed to encrypt secret key: {}", e))?;
        // best-effort zeroize
        key.iter_mut().for_each(|b| *b = 0);

        let mut encoded = Vec::with_capacity(DILITHIUM3_PK_BYTES + 1 + SALT_LEN + NONCE_LEN + ciphertext.len());
        encoded.extend_from_slice(pk.as_bytes());
        encoded.push(WALLET_VERSION_ENCRYPTED);
        encoded.extend_from_slice(&salt);
        encoded.extend_from_slice(&nonce);
        encoded.extend_from_slice(&ciphertext);

        db.put("wallet", WALLET_KEY, &encoded)?;
        println!("✅ New wallet created and saved");
        Ok(Wallet { _db: Arc::downgrade(&db), pk, sk, address })
    }

    

    pub fn address(&self) -> Address {
        self.address
    }

    /// Gets the public key
    pub fn public_key(&self) -> &PublicKey {
        &self.pk
    }

    // Removed direct secret key accessor; use sign() instead

    /// Signs a message using the wallet's secret key, returning the detached signature.
    pub fn sign(&self, message: &[u8]) -> pqcrypto_dilithium::dilithium3::DetachedSignature {
        pqcrypto_dilithium::dilithium3::detached_sign(message, &self.sk)
    }

    /// Verifies a message/signature pair using the wallet's public key.
    pub fn verify(&self, message: &[u8], signature: &pqcrypto_dilithium::dilithium3::DetachedSignature) -> bool {
        pqcrypto_dilithium::dilithium3::verify_detached_signature(signature, message, &self.pk).is_ok()
    }

    // ---------------------------------------------------------------------
    // 🪙 UTXO helpers
    // ---------------------------------------------------------------------
    /// Returns all coins currently owned by this wallet that are **unspent by this wallet**.
    /// Ownership is determined by the latest transfer tip: if no transfers, creator is owner; else last recipient.
    pub fn list_unspent(&self) -> Result<Vec<crate::coin::Coin>> {
        let store = self
            ._db
            .upgrade()
            .ok_or_else(|| anyhow!("Database connection dropped"))?;

        let cf = store.db.cf_handle("coin").ok_or_else(|| anyhow!("'coin' column family missing"))?;
        let iter = store.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut utxos = Vec::new();
        for item in iter {
            let (_key, value) = item?;
            if let Ok(coin) = crate::coin::decode_coin(&value) {
                // Determine current owner
                let owner = match store.get_transfer_tip(&coin.id)? {
                    Some(tip) if tip.last_seq > 0 => {
                        if let Some(last) = store.get_last_transfer_for_coin(&coin.id)? {
                            last.recipient()
                        } else { coin.creator_address }
                    }
                    _ => coin.creator_address,
                };
                if owner == self.address { utxos.push(coin); }
            }
        }
        Ok(utxos)
    }

    /// Sum of `value` across all unspent coins.
    pub fn balance(&self) -> Result<u64> {
        let unspent = self.list_unspent()?;
        let balance = unspent.iter().map(|c| c.value).sum();
        Ok(balance)
    }

    /// Selects a minimal set of inputs whose combined value ≥ `amount`.
    /// Returns the inputs **unsorted** (caller may sort for determinism).
    pub fn select_inputs(&self, amount: u64) -> Result<Vec<crate::coin::Coin>> {
        let mut coins = self.list_unspent()?;
        // Simple greedy selection: sort ascending, pick until we cover the amount.
        coins.sort_by_key(|c| c.value);
        let mut selected = Vec::new();
        let mut total = 0u64;
        for coin in coins.into_iter().rev() { // start with largest
            selected.push(coin);
            total += selected.last().unwrap().value;
            if total >= amount { break; }
        }
        if total < amount {
            Err(anyhow!("Insufficient funds: requested {}, available {}", amount, total))
        } else {
            Ok(selected)
        }
    }

    /// Sends a transfer to a recipient address.
    /// This is the main entry point for sending coins.
    pub async fn send_transfer(
        &self,
        to: crate::crypto::Address,
        amount: u64,
        network: &crate::network::NetHandle,
    ) -> Result<Vec<crate::transfer::Transfer>> {
        let store = self
            ._db
            .upgrade()
            .ok_or_else(|| anyhow!("Database connection dropped"))?;

        // Select coins to spend
        let coins_to_spend = self.select_inputs(amount)?;
        
        // Create transfer manager
        let transfer_mgr = crate::transfer::TransferManager::new(store);
        
        // Create transfers for each coin currently owned by us
        let mut transfers = Vec::new();
        for coin in coins_to_spend {
            // Ensure we still own this coin at send time
            let current_owner = match transfer_mgr.get_transfer_for_coin(&coin.id)? {
                Some(last) => last.recipient(),
                None => coin.creator_address,
            };
            if current_owner != self.address { continue; }
            let transfer = transfer_mgr.send_transfer(
                coin.id,
                self.pk.clone(),
                &self.sk,
                to,
                network,
            ).await?;
            transfers.push(transfer);
        }
        
        Ok(transfers)
    }

    /// Gets all transfers involving this wallet (as sender or recipient)
    pub fn get_transfers(&self) -> Result<Vec<crate::transfer::Transfer>> {
        let store = self
            ._db
            .upgrade()
            .ok_or_else(|| anyhow!("Database connection dropped"))?;

        let transfer_mgr = crate::transfer::TransferManager::new(store);
        transfer_mgr.get_transfers_for_address(&self.address)
    }

    /// Gets the transaction history for this wallet
    pub fn get_transaction_history(&self) -> Result<Vec<TransactionRecord>> {
        let transfers = self.get_transfers()?;
        let mut history = Vec::new();
        
        for transfer in transfers {
            let is_sender = transfer.is_from(&self.address)?;
            let record = TransactionRecord {
                coin_id: transfer.coin_id,
                transfer_hash: transfer.hash(),
                timestamp: std::time::SystemTime::now(), // TODO: Get actual timestamp from epoch
                is_sender,
                amount: 1, // All coins have value 1 in current implementation
                counterparty: if is_sender { 
                    transfer.recipient() 
                } else { 
                    transfer.sender()? 
                },
            };
            history.push(record);
        }
        
        Ok(history)
    }

    // ------------------------- Ring outputs (private spends) -------------------------
    /// Derive a one-time pubkey for receiving outputs; for now reuse the main key as placeholder.
    fn derive_one_time_public(&self) -> RingPublicKey {
        RingPublicKey(self.pk.as_bytes().to_vec())
    }

    /// List owned ring outputs by matching the one-time public key
    pub fn list_owned_outputs(&self) -> Result<Vec<RingOutput>> {
        let store = self
            ._db
            .upgrade()
            .ok_or_else(|| anyhow!("Database connection dropped"))?;
        // Use `addr_utxo` index for O(keys) lookup
        let addr = crypto::address_from_pk(&self.pk);
        let cf = store.db.cf_handle("addr_utxo").ok_or_else(|| anyhow!("'addr_utxo' CF missing"))?;
        let iter = store.db.iterator_cf(cf, rocksdb::IteratorMode::From(&addr, rocksdb::Direction::Forward));
        let mut outs = Vec::new();
        for item in iter {
            let (k, _v) = item?;
            if k.len() < 64 || &k[..32] != &addr { break; }
            let mut out_id = [0u8;32]; out_id.copy_from_slice(&k[32..64]);
            if let Some(out) = store.get_output(&out_id)? { outs.push(out); }
        }
        Ok(outs)
    }

    /// Select decoys from outputs CF deterministically by epoch buckets.
    fn select_decoy_pubkeys(&self, store: &Store, target_count: usize) -> Result<Vec<RingPublicKey>> {
        let cf = store.db.cf_handle("outputs").ok_or_else(|| anyhow!("'outputs' CF missing"))?;
        let iter = store.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut picks: Vec<RingPublicKey> = Vec::new();
        for item in iter {
            let (_k, v) = item?;
            if let Ok(out) = bincode::deserialize::<RingOutput>(&v) {
                picks.push(out.pubkey.clone());
                if picks.len() >= target_count { break; }
            }
        }
        Ok(picks)
    }

    /// Build a ring transfer with 4 decoys (total ring size 5)
    pub fn build_ring_transfer<S: RingSignatureScheme>(
        &self,
        store: &Store,
        scheme: &S,
        real_output: &RingOutput,
        to: Address,
    ) -> Result<RingTransfer> {
        let mut ring = self.select_decoy_pubkeys(store, 4)?;
        // Ensure decoys don't accidentally equal the real key
        ring.retain(|pk| pk.0 != real_output.pubkey.0);
        // Insert real at a deterministic position (e.g., 0)
        ring.insert(0, real_output.pubkey.clone());

        let recipient_one_time = self.derive_one_time_public();
        let msg = {
            let mut v = Vec::new();
            v.extend_from_slice(&to);
            // Commit to ring members via a BLAKE3 root over concatenated pubkeys
            let mut concat = Vec::new();
            for m in &ring { concat.extend_from_slice(&m.0); }
            let ring_root = crate::crypto::blake3_hash(&concat);
            // Domain-separated binding message
            v.extend_from_slice(b"ring_tx");
            v.extend_from_slice(&ring_root);
            v.extend_from_slice(&recipient_one_time.0);
            v
        };
        let (sig, tag) = scheme.sign(&msg, &ring, self.sk.as_bytes())?;
        Ok(RingTransfer {
            ring_members: ring,
            recipient_one_time,
            to,
            signature: sig,
            link_tag: tag,
        })
    }
}

/// Represents a transaction record for wallet history
#[derive(Debug, Clone)]
pub struct TransactionRecord {
    pub coin_id: [u8; 32],
    pub transfer_hash: [u8; 32],
    pub timestamp: std::time::SystemTime,
    pub is_sender: bool,
    pub amount: u64,
    pub counterparty: crate::crypto::Address,
}