use crate::{
    storage::Store,
    crypto::{self, Address, DILITHIUM3_PK_BYTES, DILITHIUM3_SK_BYTES},
};
use pqcrypto_dilithium::dilithium3::{PublicKey, SecretKey};
use anyhow::{Result, Context, anyhow, bail};
use std::sync::Arc;
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
use argon2::Argon2;
use chacha20poly1305::{aead::{Aead, NewAead}, XChaCha20Poly1305, Key, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use rpassword;
use atty;

const WALLET_KEY: &[u8] = b"default_keypair";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const WALLET_VERSION_ENCRYPTED: u8 = 1;

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
                // Non-interactive (tests / CI) – use deterministic placeholder
                Ok("test_passphrase".to_string())
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
                Argon2::default()
                    .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
                    .map_err(|e| anyhow!("Argon2id key derivation failed: {}", e))?;

                let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
                let mut nonce = [0u8; NONCE_LEN];
                OsRng.fill_bytes(&mut nonce);
                let ciphertext = cipher
                    .encrypt(XNonce::from_slice(&nonce), sk.as_bytes())
                    .map_err(|e| anyhow!("Failed to encrypt secret key: {}", e))?;

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
            Argon2::default()
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

            let address = crypto::address_from_pk(&pk);
            println!("🔑 Wallet unlocked. Address: {}", hex::encode(address));
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
        Argon2::default()
            .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
            .map_err(|e| anyhow!("Argon2id key derivation failed: {}", e))?;

        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), sk.as_bytes())
            .map_err(|e| anyhow!("Failed to encrypt secret key: {}", e))?;

        let mut encoded = Vec::with_capacity(DILITHIUM3_PK_BYTES + 1 + SALT_LEN + NONCE_LEN + ciphertext.len());
        encoded.extend_from_slice(pk.as_bytes());
        encoded.push(WALLET_VERSION_ENCRYPTED);
        encoded.extend_from_slice(&salt);
        encoded.extend_from_slice(&nonce);
        encoded.extend_from_slice(&ciphertext);

        db.put("wallet", WALLET_KEY, &encoded)?;
        println!("✅ New wallet created and saved. Address: {}", hex::encode(address));
        Ok(Wallet { _db: Arc::downgrade(&db), pk, sk, address })
    }

    

    pub fn address(&self) -> Address {
        self.address
    }

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
    /// Returns all coins created by this wallet that are currently **unspent**.
    /// A coin is considered unspent if:
    ///   1. It belongs to `self.address`, **and**
    ///   2. There is no transfer recorded with the same `coin_id`.
    ///
    /// Currently transfers are not yet persisted, so condition (2) is a stub.
    /// The function is implemented defensively so once `transfer` persistence
    /// exists the spent-coin filter can be filled in without changing callers.
    pub fn list_unspent(&self) -> Result<Vec<crate::coin::Coin>> {
        use std::fs;
        use std::path::Path;

        let store = self._db.upgrade().ok_or_else(|| anyhow!("Database connection dropped"))?;
        let coins_dir = store.coins_dir();
        if !Path::new(&coins_dir).exists() {
            return Ok(vec![]); // No coins yet
        }

        let mut utxos = Vec::new();
        for entry in fs::read_dir(&coins_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let data = fs::read(entry.path())?;
                // Skip unreadable entries gracefully to avoid poisoning balance
                if let Ok(coin) = bincode::deserialize::<crate::coin::Coin>(&data) {
                    if coin.creator_address == self.address {
                        // A coin is unspent if there's no transfer recorded under the same ID
                        let spent: Option<crate::transfer::Transfer> = store.get("transfer", &coin.id)?;
                        if spent.is_none() {
                            utxos.push(coin);
                        }
                    }
                }
            }
        }
        Ok(utxos)
    }

    /// Sum of `value` across all unspent coins.
    pub fn balance(&self) -> Result<u64> {
        Ok(self.list_unspent()?.iter().map(|c| c.value).sum())
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
}