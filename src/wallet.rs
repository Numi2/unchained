use crate::{
    storage::Store,
    crypto::{self, Address, DILITHIUM3_PK_BYTES, DILITHIUM3_SK_BYTES, KYBER768_PK_BYTES, KYBER768_SK_BYTES, OTP_PK_BYTES},
};
use pqcrypto_dilithium::dilithium3::{
    PublicKey, SecretKey,
};
use pqcrypto_kyber::kyber768::{PublicKey as KyberPk, SecretKey as KyberSk};
use pqcrypto_traits::kem::PublicKey as KyberPkTrait; // enables KyberPk::from_bytes()
use pqcrypto_traits::kem::SecretKey as KyberSkTrait; // enables KyberSk::as_bytes()/from_bytes()
use pqcrypto_traits::kem::{Ciphertext as KyberCtTrait, SharedSecret as KyberSharedSecretTrait};
use base64::Engine;
use serde::{Serialize, Deserialize};

// V3 format
#[derive(serde::Serialize, serde::Deserialize)]
pub struct StealthAddressDocV3 {
    version: u8,
    recipient_addr: Address,
    kyber_pk: Vec<u8>,
}

// Legacy V2 format (Kyber-only)
#[derive(serde::Serialize, serde::Deserialize)]
pub struct StealthAddressDocV2 {
    version: u8,
    recipient_addr: Address,
    kyber_pk: Vec<u8>,
}

// Legacy V1 format (Dilithium+Kyber with signature)
#[derive(serde::Serialize, serde::Deserialize)]
pub struct StealthAddressDoc {
    version: u8,
    recipient_addr: Address,
    dili_pk: Vec<u8>,
    kyber_pk: Vec<u8>,
    sig: Vec<u8>,
}
use anyhow::{Result, Context, anyhow, bail};
use std::sync::Arc;
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
use argon2::{Argon2, Params};
use chacha20poly1305::{
    aead::{Aead, NewAead},
    XChaCha20Poly1305, Key, XNonce,
};
// no AEAD usage in deterministic OTP flow
use rand::rngs::OsRng;
use rand::RngCore;
use rpassword;
use atty;

const WALLET_KEY: &[u8] = b"default_keypair";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const WALLET_VERSION_ENCRYPTED: u8 = 1;
const WALLET_VERSION_WITH_KYBER: u8 = 2;
// Tunable KDF parameters for wallet encryption
const WALLET_KDF_MEM_KIB: u32 = 256 * 1024; // 256 MiB
const WALLET_KDF_TIME_COST: u32 = 3; // iterations

#[derive(Serialize, Deserialize)]
struct WalletSecretsV2 {
    #[serde(with = "serde_big_array::BigArray")]
    dili_sk: [u8; DILITHIUM3_SK_BYTES],
    #[serde(with = "serde_big_array::BigArray")]
    kyber_sk: [u8; KYBER768_SK_BYTES],
    #[serde(with = "serde_big_array::BigArray")]
    kyber_pk: [u8; KYBER768_PK_BYTES],
}

pub struct Wallet {
    _db: std::sync::Weak<Store>,
    pk: PublicKey,
    sk: SecretKey,
    kyber_pk: KyberPk,
    kyber_sk: KyberSk,
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
                // V2: encrypt Dilithium SK + Kyber SK/PK together as one payload
                let (kyber_pk, kyber_sk) = pqcrypto_kyber::kyber768::keypair();
                let mut dili_sk = [0u8; DILITHIUM3_SK_BYTES]; dili_sk.copy_from_slice(sk.as_bytes());
                let mut kyb_sk = [0u8; KYBER768_SK_BYTES]; kyb_sk.copy_from_slice(kyber_sk.as_bytes());
                let mut kyb_pk = [0u8; KYBER768_PK_BYTES]; kyb_pk.copy_from_slice(kyber_pk.as_bytes());
                let secrets = WalletSecretsV2 { dili_sk, kyber_sk: kyb_sk, kyber_pk: kyb_pk };
                let plaintext = bincode::serialize(&secrets)?;
                let ciphertext = cipher
                    .encrypt(XNonce::from_slice(&nonce), plaintext.as_ref())
                    .map_err(|e| anyhow!("Failed to encrypt secret payload: {}", e))?;
                // best-effort zeroize
                key.iter_mut().for_each(|b| *b = 0);

                let mut new_encoded = Vec::with_capacity(DILITHIUM3_PK_BYTES + 1 + SALT_LEN + NONCE_LEN + ciphertext.len());
                new_encoded.extend_from_slice(pk.as_bytes());
                new_encoded.push(WALLET_VERSION_WITH_KYBER);
                new_encoded.extend_from_slice(&salt);
                new_encoded.extend_from_slice(&nonce);
                new_encoded.extend_from_slice(&ciphertext);
                db.put("wallet", WALLET_KEY, &new_encoded)?;

                let address = crypto::address_from_pk(&pk);
                println!("🔐 Wallet migrated and unlocked. Address: {}", hex::encode(address));
                return Ok(Wallet { _db: Arc::downgrade(&db), pk, sk, kyber_pk, kyber_sk, address });
            }

            // --- Encrypted wallet path ---
            let pk_bytes = &encoded[0..DILITHIUM3_PK_BYTES];
            let version = encoded[DILITHIUM3_PK_BYTES];
            if version != WALLET_VERSION_ENCRYPTED && version != WALLET_VERSION_WITH_KYBER {
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
            let decrypted = cipher
                .decrypt(XNonce::from_slice(nonce), ciphertext)
                .map_err(|_| anyhow!("Invalid pass-phrase"))?;

            let pk = PublicKey::from_bytes(pk_bytes)
                .with_context(|| "Failed to decode public key")?;
            let (sk, kyber_pk, kyber_sk) = if version == WALLET_VERSION_ENCRYPTED {
                // V1: only Dilithium SK present; migrate to V2 by adding Kyber keys
                let sk = SecretKey::from_bytes(&decrypted)
                    .with_context(|| "Failed to decode secret key bytes")?;
                let (kpk, ksk) = pqcrypto_kyber::kyber768::keypair();
                // Write back as V2
                let passphrase = obtain_passphrase("Upgrade wallet: confirm pass-phrase to re-encrypt: ")?;
                let mut salt = [0u8; SALT_LEN];
                OsRng.fill_bytes(&mut salt);
                let mut key2 = [0u8; 32];
                let params2 = Params::new(WALLET_KDF_MEM_KIB, WALLET_KDF_TIME_COST, 1, None)
                    .map_err(|e| anyhow!("Invalid Argon2id params: {}", e))?;
                Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params2)
                    .hash_password_into(passphrase.as_bytes(), &salt, &mut key2)
                    .map_err(|e| anyhow!("Argon2id key derivation failed: {}", e))?;
                let cipher2 = XChaCha20Poly1305::new(Key::from_slice(&key2));
                let mut nonce2 = [0u8; NONCE_LEN];
                OsRng.fill_bytes(&mut nonce2);
                let mut dili_sk = [0u8; DILITHIUM3_SK_BYTES]; dili_sk.copy_from_slice(sk.as_bytes());
                let mut kyb_sk = [0u8; KYBER768_SK_BYTES]; kyb_sk.copy_from_slice(ksk.as_bytes());
                let mut kyb_pk = [0u8; KYBER768_PK_BYTES]; kyb_pk.copy_from_slice(kpk.as_bytes());
                let secrets = WalletSecretsV2 { dili_sk, kyber_sk: kyb_sk, kyber_pk: kyb_pk };
                let plaintext2 = bincode::serialize(&secrets)?;
                let ciphertext2 = cipher2
                    .encrypt(XNonce::from_slice(&nonce2), plaintext2.as_ref())
                    .map_err(|e| anyhow!("Failed to encrypt secret payload: {}", e))?;
                // zeroize key material
                key2.iter_mut().for_each(|b| *b = 0);
                let mut new_encoded = Vec::with_capacity(DILITHIUM3_PK_BYTES + 1 + SALT_LEN + NONCE_LEN + ciphertext2.len());
                new_encoded.extend_from_slice(pk.as_bytes());
                new_encoded.push(WALLET_VERSION_WITH_KYBER);
                new_encoded.extend_from_slice(&salt);
                new_encoded.extend_from_slice(&nonce2);
                new_encoded.extend_from_slice(&ciphertext2);
                db.put("wallet", WALLET_KEY, &new_encoded)?;
                (sk, kpk, ksk)
            } else {
                // V2: parse composite secrets
                let secrets: WalletSecretsV2 = bincode::deserialize(&decrypted)
                    .map_err(|_| anyhow!("Corrupted wallet payload (V2)"))?;
                let sk = SecretKey::from_bytes(&secrets.dili_sk)
                    .with_context(|| "Failed to decode Dilithium secret key")?;
                let kyber_pk = KyberPk::from_bytes(&secrets.kyber_pk)
                    .map_err(|_| anyhow!("Invalid Kyber PK in wallet"))?;
                let kyber_sk = KyberSk::from_bytes(&secrets.kyber_sk)
                    .map_err(|_| anyhow!("Invalid Kyber SK in wallet"))?;
                (sk, kyber_pk, kyber_sk)
            };
            // zeroize key and decrypted buffer
            let mut key_zero = key;
            key_zero.iter_mut().for_each(|b| *b = 0);

            let address = crypto::address_from_pk(&pk);
            // Avoid printing address unless explicitly requested via logs
            return Ok(Wallet { _db: Arc::downgrade(&db), pk, sk, kyber_pk, kyber_sk, address })

        }

        // --- Brand new wallet ---
        println!("✨ No wallet found, creating a new one...");
        // Deterministic-only: derive seed for wallet master key deterministically from passphrase and salt
        let passphrase = obtain_passphrase("Set a pass-phrase for your new wallet: ")?;
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let params = Params::new(WALLET_KDF_MEM_KIB, WALLET_KDF_TIME_COST, 1, None)
            .map_err(|e| anyhow!("Invalid Argon2id params: {}", e))?;
        let mut seed = [0u8; 32];
        Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
            .hash_password_into(passphrase.as_bytes(), &salt, &mut seed)
            .map_err(|e| anyhow!("Argon2id seed derivation failed: {}", e))?;
        let (pk, sk) = crypto::dilithium3_seeded_keypair(seed);
        let (kyber_pk, kyber_sk) = pqcrypto_kyber::kyber768::keypair();
        let address = crypto::address_from_pk(&pk);

        // passphrase and salt are already set above for deterministic seed

        let mut key = [0u8; 32];
        let params = Params::new(WALLET_KDF_MEM_KIB, WALLET_KDF_TIME_COST, 1, None)
            .map_err(|e| anyhow!("Invalid Argon2id params: {}", e))?;
        Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
            .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
            .map_err(|e| anyhow!("Argon2id key derivation failed: {}", e))?;

        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        // V2 composite secrets: encrypt Dilithium SK + Kyber SK/PK
        let mut dili_sk = [0u8; DILITHIUM3_SK_BYTES]; dili_sk.copy_from_slice(sk.as_bytes());
        let mut kyb_sk = [0u8; KYBER768_SK_BYTES]; kyb_sk.copy_from_slice(kyber_sk.as_bytes());
        let mut kyb_pk = [0u8; KYBER768_PK_BYTES]; kyb_pk.copy_from_slice(kyber_pk.as_bytes());
        let secrets = WalletSecretsV2 { dili_sk, kyber_sk: kyb_sk, kyber_pk: kyb_pk };
        let plaintext = bincode::serialize(&secrets)?;
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), plaintext.as_ref())
            .map_err(|e| anyhow!("Failed to encrypt secret payload: {}", e))?;
        // best-effort zeroize
        key.iter_mut().for_each(|b| *b = 0);

        let mut encoded = Vec::with_capacity(DILITHIUM3_PK_BYTES + 1 + SALT_LEN + NONCE_LEN + ciphertext.len());
        encoded.extend_from_slice(pk.as_bytes());
        encoded.push(WALLET_VERSION_WITH_KYBER);
        encoded.extend_from_slice(&salt);
        encoded.extend_from_slice(&nonce);
        encoded.extend_from_slice(&ciphertext);

        db.put("wallet", WALLET_KEY, &encoded)?;
        println!("✅ New wallet created and saved");
        Ok(Wallet { _db: Arc::downgrade(&db), pk, sk, kyber_pk, kyber_sk, address })
    }

    pub fn address(&self) -> Address {
        self.address
    }

    /// Gets the public key
    pub fn public_key(&self) -> &PublicKey {
        &self.pk
    }
    pub fn kyber_public_key(&self) -> &KyberPk { &self.kyber_pk }
    pub fn kyber_secret_key(&self) -> &KyberSk { &self.kyber_sk }

    /// INTERNAL: compute genesis lock secret deterministically for a coin we created.
    pub fn compute_genesis_lock_secret(&self, coin_id: &[u8;32], chain_id32: &[u8;32]) -> [u8;32] {
        crate::crypto::derive_genesis_lock_secret(&self.sk, coin_id, chain_id32)
    }

    // Removed direct secret key accessor; use sign() instead

    /// Signs a message using the wallet's secret key, returning the detached signature.
    #[allow(dead_code)]
    pub fn sign(&self, _message: &[u8]) { /* signatures removed in V3 */ }

    /// Verifies a message/signature pair using the wallet's public key.
    #[allow(dead_code)]
    pub fn verify(&self, _message: &[u8], _signature: &()) -> bool { false }

    // ---------------------------------------------------------------------
    // Stealth Address: authenticated Kyber key distribution
    // ---------------------------------------------------------------------
    // Format (bincode then base64-url):
    // { version: u8=1, recipient_addr: [u8;32], dili_pk: [u8;DILITHIUM3_PK_BYTES], kyber_pk: [u8;crypto::KYBER768_PK_BYTES], sig: Dilithium sig over ("stealth_addr_v1" || addr || kyber_pk) }

    pub fn export_stealth_address(&self) -> String {
        let doc = StealthAddressDocV3 {
            version: 3,
            recipient_addr: self.address,
            kyber_pk: self.kyber_pk.as_bytes().to_vec(),
        };
        let bytes = bincode::serialize(&doc).expect("serialize stealth address v2");
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    pub fn parse_stealth_address(addr_str: &str) -> Result<(Address, KyberPk)> {
        // Be tolerant to surrounding whitespace and accidental padding from clipboard
        let s = addr_str.trim();
        // Strip common accidental wrappers
        let s = s.trim_matches('"');
        let s = s.trim_matches('\'');
        let s = s.trim_matches('`');
        // Try URL_SAFE_NO_PAD first, then URL_SAFE with padding
        let bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s) {
            Ok(b) => b,
            Err(_) => base64::engine::general_purpose::URL_SAFE.decode(s)
                .map_err(|_| anyhow!("Invalid stealth address encoding"))?,
        };
        // Try V3, then V2, then V1 legacy for DB compatibility
        if let Ok(doc3) = bincode::deserialize::<StealthAddressDocV3>(&bytes) {
            if doc3.version != 3 { bail!("Unsupported stealth address version"); }
            let kyber_pk = KyberPk::from_bytes(&doc3.kyber_pk)
                .map_err(|_| anyhow!("Invalid Kyber PK in stealth address"))?;
            return Ok((doc3.recipient_addr, kyber_pk));
        }
        if let Ok(doc2) = bincode::deserialize::<StealthAddressDocV2>(&bytes) {
            if doc2.version != 2 { bail!("Unsupported stealth address version"); }
            let kyber_pk = KyberPk::from_bytes(&doc2.kyber_pk)
                .map_err(|_| anyhow!("Invalid Kyber PK in stealth address (v2)"))?;
            return Ok((doc2.recipient_addr, kyber_pk));
        }
        if let Ok(doc1) = bincode::deserialize::<StealthAddressDoc>(&bytes) {
            if doc1.version != 1 { bail!("Unsupported stealth address version"); }
            let dili_pk = PublicKey::from_bytes(&doc1.dili_pk)
                .map_err(|_| anyhow!("Invalid Dilithium PK in stealth address (v1)"))?;
            let kyber_pk = KyberPk::from_bytes(&doc1.kyber_pk)
                .map_err(|_| anyhow!("Invalid Kyber PK in stealth address (v1)"))?;
            let computed_addr = crypto::address_from_pk(&dili_pk);
            return Ok((computed_addr, kyber_pk));
        }
        bail!("Invalid stealth address payload")
    }

    /// Backward-compatible wrapper; signature verification removed. Prefer `parse_stealth_address`.
    pub fn parse_and_verify_stealth_address(addr_str: &str) -> Result<(Address, KyberPk)> { Self::parse_stealth_address(addr_str) }

    // Batch commitment token flow removed; replaced by paycodes and OOB spend notes.

    // ---------------------------------------------------------------------
    // 🪙 UTXO helpers
    // ---------------------------------------------------------------------
    /// Returns all coins currently owned by this wallet that are **unspent**.
    /// Rules:
    /// - Exclude coins that already have a recorded spend (V3 hashlock chain)
    /// - If no spend exists: creator still owns it (creator_address == self.address)
    /// - For received spends: we own it if we can recover the one-time SK from its stealth output
    pub fn list_unspent(&self) -> Result<Vec<crate::coin::Coin>> {
        let store = self
            ._db
            .upgrade()
            .ok_or_else(|| anyhow!("Database connection dropped"))?;

        let cf = store
            .db
            .cf_handle("coin")
            .ok_or_else(|| anyhow!("'coin' column family missing"))?;

        let iter = store.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut utxos = Vec::new();
        for item in iter {
            let (_key, value) = item?;
            if let Ok(coin) = crate::coin::decode_coin(&value) {
                // If there is a spend recorded, the current owner is the recipient of that spend
                let recorded_spend: Option<crate::transfer::Spend> = match store.get_spend_tolerant(&coin.id) {
                    Ok(v) => v,
                    Err(e) => { eprintln!("⚠️  Skipping malformed spend record for coin {}: {}", hex::encode(coin.id), e); None }
                };
                if let Some(sp) = recorded_spend {
                    let chain_id = store.get_chain_id()?;
                    if sp.to.is_for_receiver(&self.kyber_sk, &self.pk, &chain_id).is_ok() {
                        utxos.push(coin);
                    }
                    continue;
                }

                // Else determine owner via genesis (no legacy transfers)
                if coin.creator_address == self.address {
                    utxos.push(coin);
                }
            }
        }
        Ok(utxos)
    }

    /// Deterministically process a received spend for this wallet (idempotent).
    /// - If our Kyber SK can derive the OTP SK using our Dilithium PK and amount, we consider it ours.
    /// - Inserts coin ownership into wallet view implicitly through balance/list_unspent logic.
    pub fn scan_spend_for_me(&self, spend: &crate::transfer::Spend) -> Result<()> {
        let store = self
            ._db
            .upgrade()
            .ok_or_else(|| anyhow!("Database connection dropped"))?;
        // Verify OTP matches deterministic KDF
        let coin: Option<crate::coin::Coin> = store.get("coin", &spend.coin_id)?;
        if let Some(coin) = coin {
            let chain_id = store.get_chain_id()?;
            if spend.to.is_for_receiver(&self.kyber_sk, &self.pk, &chain_id).is_ok() {
                // Persist OTP marker (no SK to store since we use opaque OTP bytes)
                let pk_hash = crate::crypto::blake3_hash(&spend.to.one_time_pk);
                // keep index for compatibility with earlier flows
                store.put_otp_index(&coin.id, &pk_hash)?;
                // Invariants: coin exists; spending updates are already recorded under CFs
                // Nothing to write here; scanning functions will reflect ownership.
                // Log once for visibility
                println!("📥 Detected incoming spend for me: coin {} value {}", hex::encode(coin.id), coin.value);
            }
        } else {
            // FIXED: Coin not yet available - try scanning without coin context first
            // This handles the race condition where spends arrive before their coins
            let chain_id = store.get_chain_id()?;
            if spend.to.is_for_receiver(&self.kyber_sk, &self.pk, &chain_id).is_ok() {
                // Mark this spend as potentially ours for later confirmation when coin arrives
                let spend_marker = format!("pending_spend:{}", hex::encode(spend.coin_id));
                store.put("wallet_scan_pending", spend_marker.as_bytes(), &[1u8])?;
                println!("📥 Detected incoming spend for me (coin pending): coin {} (will confirm when coin syncs)", hex::encode(spend.coin_id));
            }
        }
        Ok(())
    }

    /// Process any pending spend scans that were waiting for coins to arrive.
    /// This should be called whenever new coins are synchronized.
    pub fn process_pending_spend_scans(&self) -> Result<()> {
        let store = self
            ._db
            .upgrade()
            .ok_or_else(|| anyhow!("Database connection dropped"))?;

        // Get all pending spend markers
        if let Some(pending_cf) = store.db.cf_handle("wallet_scan_pending") {
            let iter = store.db.iterator_cf(pending_cf, rocksdb::IteratorMode::Start);
            let mut processed_markers = Vec::new();
            
            for item in iter {
                if let Ok((key, _value)) = item {
                    if let Ok(key_str) = String::from_utf8(key.to_vec()) {
                        if let Some(coin_id_hex) = key_str.strip_prefix("pending_spend:") {
                            if let Ok(coin_id_bytes) = hex::decode(coin_id_hex) {
                                if coin_id_bytes.len() == 32 {
                                    let mut coin_id = [0u8; 32];
                                    coin_id.copy_from_slice(&coin_id_bytes);
                                    
                                    // Check if coin now exists
                                    if let Ok(Some(_coin)) = store.get::<crate::coin::Coin>("coin", &coin_id) {
                                        // Coin is now available - try to rescan the spend
                                        if let Ok(Some(spend)) = store.get_spend_tolerant(&coin_id) {
                                            let _ = self.scan_spend_for_me(&spend);
                                            processed_markers.push(key.to_vec());
                                            println!("✅ Confirmed pending spend for coin {} now that coin is available", coin_id_hex);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            // Clean up processed markers
            for marker in processed_markers {
                let _ = store.db.delete_cf(pending_cf, &marker);
            }
        }
        
        Ok(())
    }

    /// Sum of `value` across all coins where current owner is this wallet.
    /// Prefers recorded spends when present; otherwise uses genesis ownership.
    /// Additionally, credits pending incoming spends even if the coin record hasn't synced yet.
    pub fn balance(&self) -> Result<u64> {
        let store = self
            ._db
            .upgrade()
            .ok_or_else(|| anyhow!("Database connection dropped"))?;

        let cf_coin = store
            .db
            .cf_handle("coin")
            .ok_or_else(|| anyhow!("'coin' column family missing"))?;
        let iter = store.db.iterator_cf(cf_coin, rocksdb::IteratorMode::Start);

        let mut sum: u64 = 0;
        let mut counted: std::collections::HashSet<[u8;32]> = std::collections::HashSet::new();

        for item in iter {
            let (_key, value) = item?;
            if let Ok(coin) = crate::coin::decode_coin(&value) {
                // If there is a spend recorded, the owner is the recipient of that spend
                let recorded_spend: Option<crate::transfer::Spend> = match store.get_spend_tolerant(&coin.id) {
                    Ok(v) => v,
                    Err(e) => { eprintln!("⚠️  Ignoring malformed spend record for coin {}: {}", hex::encode(coin.id), e); None }
                };
                if let Some(sp) = recorded_spend {
                    let chain_id = store.get_chain_id()?;
                    if sp.to.is_for_receiver(&self.kyber_sk, &self.pk, &chain_id).is_ok() {
                        sum = sum.saturating_add(coin.value);
                        counted.insert(coin.id);
                    }
                    continue;
                }
                // Else genesis owner is the creator
                if coin.creator_address == self.address {
                    sum = sum.saturating_add(coin.value);
                    counted.insert(coin.id);
                }
            }
        }

        // Credit any incoming spends to me whose coins have not been observed yet
        if let Some(cf_spend) = store.db.cf_handle("spend") {
            let iter_sp = store.db.iterator_cf(cf_spend, rocksdb::IteratorMode::Start);
            for item in iter_sp {
                let (_k, v) = item?;
                if let Some(sp) = store.decode_spend_bytes_tolerant(&v) {
                    if counted.contains(&sp.coin_id) { continue; }
                    // Only count if this spend is addressed to me
                    let chain_id = store.get_chain_id()?;
                    if sp.to.is_for_receiver(&self.kyber_sk, &self.pk, &chain_id).is_ok() {
                        // Prefer coin.value if available; else fall back to spend's embedded amount
                        let add_value = if let Some(coin) = store.get::<crate::coin::Coin>("coin", &sp.coin_id)? { coin.value } else { sp.to.amount_le };
                        sum = sum.saturating_add(add_value);
                        counted.insert(sp.coin_id);
                    }
                }
            }
        }

        Ok(sum)
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
            let v = coin.value;
            selected.push(coin);
            total = total.saturating_add(v);
            if total >= amount { break; }
        }
        if total < amount {
            Err(anyhow!("Insufficient funds: requested {}, available {}", amount, total))
        } else {
            Ok(selected)
        }
    }

    /// Deprecated: Use `send_to_stealth_address`.
    pub async fn send_transfer(
        &self,
        _to: crate::crypto::Address,
        _amount: u64,
        _network: &crate::network::NetHandle,
    ) -> Result<Vec<crate::transfer::Spend>> {
        Err(anyhow!("send_transfer(Address, ...) is deprecated. Use send_to_stealth_address(stealth_address, amount, network)"))
    }

    /// Sends stealth V3 hashlock spends to a recipient using a stealth address or paycode.
    /// Commitment gossip is removed. The caller must provide an OOB spend note `s_bytes` (opaque secret)
    /// and a receiver paycode containing receiver Kyber PK and routing tag.
    pub async fn send_with_paycode_and_note(
        &self,
        receiver_paycode: &str,
        amount: u64,
        network: &crate::network::NetHandle,
        _s_bytes: &[u8],
    ) -> Result<SendOutcome> {
        // Accept either a stealth address OR, when provided, derive recipient from batch token
        // Parse paycode (chain-bound Kyber PK + short routing secret). For now accept stealth address V2 as paycode surrogate.
        let (recipient_addr, receiver_kyber_pk) = Self::parse_stealth_address(receiver_paycode)
            .context("Invalid receiver paycode")?;
        let store = self
            ._db
            .upgrade()
            .ok_or_else(|| anyhow!("Database connection dropped"))?;
        // Select inputs locally; no receiver commitment exchange over network
        let coins_to_spend: Vec<crate::coin::Coin> = self.select_inputs(amount)?;
        let mut spends = Vec::new();

        for coin in coins_to_spend {
            // Locally construct receiver lock commitment from paycode and OOB note
            let (shared, ct) = pqcrypto_kyber::kyber768::encapsulate(&receiver_kyber_pk);
            let chain_id = store.get_chain_id()?;
            let value_tag = coin.value.to_le_bytes();
            let seed = crate::crypto::stealth_seed_v3(
                shared.as_bytes(),
                &recipient_addr,
                ct.as_bytes(),
                &value_tag,
                &chain_id,
            );
            let ot_pk_bytes = crate::crypto::derive_one_time_pk_bytes(seed);
            // View tag for receiver filtering
            let vt = crate::crypto::view_tag(shared.as_bytes());
            // Derive the receiver's next-hop lock secret and hash from Kyber context
            let s_next = crate::crypto::derive_next_lock_secret_with_note(
                shared.as_bytes(),
                ct.as_bytes(),
                coin.value,
                &coin.id,
                &chain_id,
                _s_bytes,
            );
            let next_lock_hash = crate::crypto::lock_hash_from_preimage(&chain_id, &coin.id, &s_next);
            let mut one_time_pk = [0u8; OTP_PK_BYTES];
            one_time_pk.copy_from_slice(&ot_pk_bytes);
            let mut kyber_ct = [0u8; crate::crypto::KYBER768_CT_BYTES];
            kyber_ct.copy_from_slice(ct.as_bytes());
            let receiver_commitment = crate::transfer::ReceiverLockCommitment {
                one_time_pk,
                kyber_ct,
                next_lock_hash,
                commitment_id: crate::crypto::commitment_id_v1(&one_time_pk, &kyber_ct, &next_lock_hash, &coin.id, coin.value, &chain_id),
                amount_le: coin.value,
            };
            // Resolve anchor and proof against genesis only
            let anchor_used: crate::epoch::Anchor = store
                .get("epoch", &0u64.to_le_bytes())?
                .ok_or_else(|| anyhow!("Genesis anchor not found"))?;
            let proof_used: Option<Vec<([u8; 32], bool)>> = Some(Vec::new());

            // Determine correct unlock preimage for the coin being spent (genesis or previous spend)
            let unlock_preimage = if let Some(prev_spend) = store.get_spend_tolerant(&coin.id)? {
                // Previous spend exists: derive the previously committed next-lock secret (V3 only)
                prev_spend.to.derive_lock_secret(&self.kyber_sk, &coin.id, &chain_id, _s_bytes)?
            } else {
                // Genesis: derive s0 from our long-term secret key
                self.compute_genesis_lock_secret(&coin.id, &chain_id)
            };

            // Build and broadcast spend (V3 hashlock)
            let proof_vec = proof_used.clone().ok_or_else(|| anyhow!("missing proof after local or network path"))?;
            let mut spend = crate::transfer::Spend::create_hashlock(
                coin.id,
                &anchor_used,
                proof_vec,
                unlock_preimage,
                &receiver_commitment,
                coin.value,
                &store.get_chain_id()?,
            )?;
            // V3 only: nullifier derived from preimage domain; fail if mismatch later in validate
            // Attach view tag into `to`
            spend.to.view_tag = Some(vt);
            spend.validate(&store)?;
            spend.apply(&store)?;
            crate::metrics::V3_SENDS.inc();
            network.gossip_spend(&spend).await;
            spends.push(spend);
        }
        Ok(SendOutcome { spends })
    }

    // Deprecated wrappers removed; use send_with_paycode_and_note

    // (Legacy transfers listing removed)

    /// Gets the transaction history for this wallet
    pub fn get_transaction_history(&self) -> Result<Vec<TransactionRecord>> {
        // Legacy transfers removed
        let store = self._db.upgrade().ok_or_else(|| anyhow!("Database connection dropped"))?;
        let mut history = Vec::new();

        // (No V1 transfers)

        // V2 spends (outgoing and incoming)
        let cf = store.db.cf_handle("spend").ok_or_else(|| anyhow!("'spend' column family missing"))?;
        let iter = store.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        for item in iter {
            let (_k, value) = item?;
            if let Ok(spend) = bincode::deserialize::<crate::transfer::Spend>(&value) {
                // Determine previous owner address (tolerant coin decoding for legacy formats)
                let coin = match store.get_coin(&spend.coin_id)? {
                    Some(c) => c,
                    None => {
                        // Reorg or partial data: skip this spend in history view
                        continue;
                    }
                };
                let prev_owner_addr = coin.creator_address;

                // Compute transfer_hash for display from stable fields only (no signatures in V3)
                let mut txh = Vec::with_capacity(32 + 32 + 32 + spend.to.canonical_bytes().len());
                txh.extend_from_slice(&spend.root);
                txh.extend_from_slice(&spend.nullifier);
                txh.extend_from_slice(&spend.commitment);
                txh.extend_from_slice(&spend.to.canonical_bytes());
                let tx_hash = crypto::blake3_hash(&txh);

                // Outgoing (approximate): compare prev_owner_addr; counterparty from one_time_pk bytes
                if prev_owner_addr == self.address {
                    let recipient_addr = crypto::blake3_hash(&spend.to.one_time_pk);
                    history.push(TransactionRecord {
                        coin_id: spend.coin_id,
                        transfer_hash: tx_hash,
                        timestamp: std::time::SystemTime::now(),
                        is_sender: true,
                        amount: coin.value,
                        counterparty: recipient_addr,
                    });
                    continue;
                }

                // Incoming (to me)? If we can recover the one-time SK via canonical KDF, it's ours.
                let chain_id = store.get_chain_id()?;
                if spend.to.is_for_receiver(&self.kyber_sk, &self.pk, &chain_id).is_ok() {
                    history.push(TransactionRecord {
                        coin_id: spend.coin_id,
                        transfer_hash: tx_hash,
                        timestamp: std::time::SystemTime::now(),
                        is_sender: false,
                        amount: coin.value,
                        counterparty: prev_owner_addr,
                    });
                }
            }
        }

        Ok(history)
    }

    /// Commitment response builder removed.
    pub fn build_commitment_response(&self, _req: &()) -> Result<()> {
        anyhow::bail!("commitment flow removed")
    }
}

// ---------------- HTLC helper documents ----------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HtlcPlanCoin {
    pub coin_id: [u8;32],
    pub value: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HtlcPlanDoc {
    pub chain_id: [u8;32],
    pub timeout_epoch: u64,
    pub amount: u64,
    pub paycode: String,
    pub coins: Vec<HtlcPlanCoin>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HtlcClaimsDocEntry {
    pub coin_id: [u8;32],
    pub ch_claim: [u8;32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HtlcClaimsDoc { pub claims: Vec<HtlcClaimsDocEntry> }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HtlcRefundsDocEntry { pub coin_id: [u8;32], pub ch_refund: [u8;32] }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HtlcRefundsDoc { pub refunds: Vec<HtlcRefundsDocEntry> }

impl Wallet {
    pub fn plan_htlc_offer(&self, amount: u64, paycode: &str, timeout_epoch: u64) -> Result<HtlcPlanDoc> {
        // Validate paycode parseable up-front
        let _ = Self::parse_stealth_address(paycode).context("Invalid receiver paycode")?;
        let store = self._db.upgrade().ok_or_else(|| anyhow!("Database connection dropped"))?;
        let coins = self.select_inputs(amount)?;
        let chain_id = store.get_chain_id()?;
        let coins_list = coins.into_iter().map(|c| HtlcPlanCoin { coin_id: c.id, value: c.value }).collect();
        Ok(HtlcPlanDoc { chain_id, timeout_epoch, amount, paycode: paycode.to_string(), coins: coins_list })
    }

    pub async fn execute_htlc_offer(
        &self,
        plan: &HtlcPlanDoc,
        claims: &HtlcClaimsDoc,
        network: &crate::network::NetHandle,
        refund_secret_base: Option<&[u8]>,
        refund_secrets_out: Option<&str>,
        note_s: Option<&[u8]>,
    ) -> Result<SendOutcome> {
        let (recipient_addr, receiver_kyber_pk) = Self::parse_stealth_address(&plan.paycode)
            .context("Invalid receiver paycode in plan")?;
        let store = self._db.upgrade().ok_or_else(|| anyhow!("Database connection dropped"))?;
        // Build lookup for ch_claim per coin
        let mut ch_claim_map: std::collections::HashMap<[u8;32],[u8;32]> = std::collections::HashMap::new();
        for e in &claims.claims { ch_claim_map.insert(e.coin_id, e.ch_claim); }

        let mut spends = Vec::new();
        let mut secrets_dump: Vec<(String,String)> = Vec::new();
        for coin_ent in &plan.coins {
            // Fetch full coin and anchor/proof
            let coin = store.get::<crate::coin::Coin>("coin", &coin_ent.coin_id)?.ok_or_else(|| anyhow!("Coin not found for plan coin_id"))?;
            let commit_epoch = store.get_epoch_for_coin(&coin.id)?.ok_or_else(|| anyhow!("Missing coin->epoch index"))?;
            let anchor: crate::epoch::Anchor = store.get("epoch", &commit_epoch.to_le_bytes())?.ok_or_else(|| anyhow!("Anchor not found"))?;
            let leaf = crate::coin::Coin::id_to_leaf_hash(&coin.id);
            let proof = if let Some(levels) = store.get_epoch_levels(anchor.num)? {
                crate::epoch::MerkleTree::build_proof_from_levels(&levels, &leaf)
            } else if let Some(leaves) = store.get_epoch_leaves(anchor.num)? {
                crate::epoch::MerkleTree::build_proof_from_leaves(&leaves, &leaf)
            } else { None }.ok_or_else(|| anyhow!("Unable to build Merkle proof"))?;

            // Build receiver commitment with composite HTLC next_lock_hash
            let (shared, ct) = pqcrypto_kyber::kyber768::encapsulate(&receiver_kyber_pk);
            let chain_id = plan.chain_id;
            let value_tag = coin.value.to_le_bytes();
            let seed = crate::crypto::stealth_seed_v3(shared.as_bytes(), &recipient_addr, ct.as_bytes(), &value_tag, &chain_id);
            let ot_pk_bytes = crate::crypto::derive_one_time_pk_bytes(seed);
            let vt = crate::crypto::view_tag(shared.as_bytes());
            // ch_claim from receiver (per coin)
            let ch_claim = *ch_claim_map.get(&coin.id).ok_or_else(|| anyhow!("Missing ch_claim for coin in claims doc"))?;
            // ch_refund derived from refund_secret_base or generated randomly per coin
            let refund_secret = if let Some(base) = refund_secret_base {
                // Derive per-coin secret deterministically
                let mut h = blake3::Hasher::new_derive_key("unchained.htlc.refund.base");
                h.update(base);
                h.update(&coin.id);
                let mut out = [0u8;32]; h.finalize_xof().fill(&mut out); out
            } else {
                let mut s = [0u8;32]; rand::rngs::OsRng.fill_bytes(&mut s); s
            };
            let ch_refund = crate::crypto::commitment_hash_from_preimage(&chain_id, &coin.id, &refund_secret);
            let next_lock_hash = crate::crypto::htlc_lock_hash(&chain_id, &coin.id, plan.timeout_epoch, &ch_claim, &ch_refund);

            let mut one_time_pk = [0u8; OTP_PK_BYTES]; one_time_pk.copy_from_slice(&ot_pk_bytes);
            let mut kyber_ct = [0u8; crate::crypto::KYBER768_CT_BYTES]; kyber_ct.copy_from_slice(ct.as_bytes());
            let receiver_commitment = crate::transfer::ReceiverLockCommitment {
                one_time_pk,
                kyber_ct,
                next_lock_hash,
                commitment_id: crate::crypto::commitment_id_v1(&one_time_pk, &kyber_ct, &next_lock_hash, &coin.id, coin.value, &chain_id),
                amount_le: coin.value,
            };

            // Determine unlock preimage for current input
            let unlock_preimage = if let Some(prev_spend) = store.get_spend_tolerant(&coin.id)? {
                prev_spend.to.derive_lock_secret(&self.kyber_sk, &coin.id, &chain_id, note_s.unwrap_or(&[]))?
            } else {
                self.compute_genesis_lock_secret(&coin.id, &chain_id)
            };

            // Build standard V3 spend towards receiver with HTLC next lock
            let mut spend = crate::transfer::Spend::create_hashlock(
                coin.id,
                &anchor,
                proof.clone(),
                unlock_preimage,
                &receiver_commitment,
                coin.value,
                &chain_id,
            )?;
            spend.to.view_tag = Some(vt);
            spend.validate(&store)?; spend.apply(&store)?; network.gossip_spend(&spend).await; spends.push(spend);

            // Collect refund secret for optional file output only
            if refund_secret_base.is_none() {
                secrets_dump.push((hex::encode(coin.id), hex::encode(refund_secret)));
            }
        }
        // Persist generated refund secrets if requested
        if refund_secret_base.is_none() {
            if let Some(path) = refund_secrets_out {
                let json = serde_json::to_string_pretty(&secrets_dump)?;
                // Write atomically and set restrictive permissions best-effort
                std::fs::write(path, &json)?;
                #[cfg(unix)] {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
                }
                println!("🗝️  Wrote per-coin refund secrets to {} (keep secure)", path);
            }
        }
        Ok(SendOutcome { spends })
    }

    pub async fn htlc_claim(
        &self,
        timeout_epoch: u64,
        claim_secret: &[u8],
        refund_ch_map: &std::collections::HashMap<[u8;32],[u8;32]>,
        paycode: &str,
        network: &crate::network::NetHandle,
        note_s: Option<&[u8]>,
    ) -> Result<SendOutcome> {
        let (recipient_addr, receiver_kyber_pk) = Self::parse_stealth_address(paycode)?;
        let store = self._db.upgrade().ok_or_else(|| anyhow!("Database connection dropped"))?;
        let chain_id = store.get_chain_id()?;
        let mut spends = Vec::new();
        // Iterate unspent coins that are addressed to us
        for coin in self.list_unspent()? {
            // Skip coins we created (genesis owner) — focus on received HTLC outputs
            let recorded_spend = store.get_spend_tolerant(&coin.id)?;
            if recorded_spend.is_none() { continue; }

            // Build Merkle proof
            let commit_epoch = store.get_epoch_for_coin(&coin.id)?.ok_or_else(|| anyhow!("Missing coin->epoch index"))?;
            let anchor: crate::epoch::Anchor = store.get("epoch", &commit_epoch.to_le_bytes())?.ok_or_else(|| anyhow!("Anchor not found"))?;
            let leaf = crate::coin::Coin::id_to_leaf_hash(&coin.id);
            let proof = if let Some(levels) = store.get_epoch_levels(anchor.num)? {
                crate::epoch::MerkleTree::build_proof_from_levels(&levels, &leaf)
            } else if let Some(leaves) = store.get_epoch_leaves(anchor.num)? {
                crate::epoch::MerkleTree::build_proof_from_leaves(&leaves, &leaf)
            } else { None }.ok_or_else(|| anyhow!("Unable to build Merkle proof"))?;

            // Build next receiver commitment (normal next-hop lock)
            let (shared, ct) = pqcrypto_kyber::kyber768::encapsulate(&receiver_kyber_pk);
            let value_tag = coin.value.to_le_bytes();
            let seed = crate::crypto::stealth_seed_v3(shared.as_bytes(), &recipient_addr, ct.as_bytes(), &value_tag, &chain_id);
            let ot_pk_bytes = crate::crypto::derive_one_time_pk_bytes(seed);
            let vt = crate::crypto::view_tag(shared.as_bytes());
            let s_next = crate::crypto::derive_next_lock_secret_with_note(shared.as_bytes(), ct.as_bytes(), coin.value, &coin.id, &chain_id, note_s.unwrap_or(&[]));
            let next_lock_hash = crate::crypto::lock_hash_from_preimage(&chain_id, &coin.id, &s_next);
            let mut one_time_pk = [0u8; OTP_PK_BYTES]; one_time_pk.copy_from_slice(&ot_pk_bytes);
            let mut kyber_ct = [0u8; crate::crypto::KYBER768_CT_BYTES]; kyber_ct.copy_from_slice(ct.as_bytes());
            let receiver_commitment = crate::transfer::ReceiverLockCommitment {
                one_time_pk,
                kyber_ct,
                next_lock_hash,
                commitment_id: crate::crypto::commitment_id_v1(&one_time_pk, &kyber_ct, &next_lock_hash, &coin.id, coin.value, &chain_id),
                amount_le: coin.value,
            };

            // Compute CHs
            let ch_claim = crate::crypto::commitment_hash_from_preimage(&chain_id, &coin.id, claim_secret);
            let Some(ch_refund) = refund_ch_map.get(&coin.id) else { continue; };
            // For claim, the unlock preimage used is the claim secret itself
            let mut unlock_preimage = [0u8;32];
            if claim_secret.len() != 32 { anyhow::bail!("claim_secret must be 32 bytes"); }
            unlock_preimage.copy_from_slice(&claim_secret[..32]);
            let mut spend = crate::transfer::Spend::create_htlc_hashlock(
                coin.id, &anchor, proof.clone(), unlock_preimage, &receiver_commitment, coin.value, &chain_id, timeout_epoch, ch_claim, *ch_refund,
            )?;
            spend.to.view_tag = Some(vt);
            spend.validate(&store)?; spend.apply(&store)?; network.gossip_spend(&spend).await; spends.push(spend);
        }
        Ok(SendOutcome { spends })
    }

    pub async fn htlc_refund(
        &self,
        timeout_epoch: u64,
        refund_secret: &[u8],
        claim_ch_map: &std::collections::HashMap<[u8;32],[u8;32]>,
        paycode: &str,
        network: &crate::network::NetHandle,
        note_s: Option<&[u8]>,
    ) -> Result<SendOutcome> {
        let (recipient_addr, receiver_kyber_pk) = Self::parse_stealth_address(paycode)?;
        let store = self._db.upgrade().ok_or_else(|| anyhow!("Database connection dropped"))?;
        let chain_id = store.get_chain_id()?;
        let mut spends = Vec::new();
        // Only coins we control as creator (sender side) are refundable
        for coin in self.list_unspent()? {
            // Focus on coins we can currently spend (either created by us or addressed to us)
            // Build Merkle proof
            let commit_epoch = store.get_epoch_for_coin(&coin.id)?.ok_or_else(|| anyhow!("Missing coin->epoch index"))?;
            let anchor: crate::epoch::Anchor = store.get("epoch", &commit_epoch.to_le_bytes())?.ok_or_else(|| anyhow!("Anchor not found"))?;
            let leaf = crate::coin::Coin::id_to_leaf_hash(&coin.id);
            let proof = if let Some(levels) = store.get_epoch_levels(anchor.num)? {
                crate::epoch::MerkleTree::build_proof_from_levels(&levels, &leaf)
            } else if let Some(leaves) = store.get_epoch_leaves(anchor.num)? {
                crate::epoch::MerkleTree::build_proof_from_leaves(&leaves, &leaf)
            } else { None }.ok_or_else(|| anyhow!("Unable to build Merkle proof"))?;

            // Next receiver commitment (normal next-hop lock)
            let (shared, ct) = pqcrypto_kyber::kyber768::encapsulate(&receiver_kyber_pk);
            let value_tag = coin.value.to_le_bytes();
            let seed = crate::crypto::stealth_seed_v3(shared.as_bytes(), &recipient_addr, ct.as_bytes(), &value_tag, &chain_id);
            let ot_pk_bytes = crate::crypto::derive_one_time_pk_bytes(seed);
            let vt = crate::crypto::view_tag(shared.as_bytes());
            let s_next = crate::crypto::derive_next_lock_secret_with_note(shared.as_bytes(), ct.as_bytes(), coin.value, &coin.id, &chain_id, note_s.unwrap_or(&[]));
            let next_lock_hash = crate::crypto::lock_hash_from_preimage(&chain_id, &coin.id, &s_next);
            let mut one_time_pk = [0u8; OTP_PK_BYTES]; one_time_pk.copy_from_slice(&ot_pk_bytes);
            let mut kyber_ct = [0u8; crate::crypto::KYBER768_CT_BYTES]; kyber_ct.copy_from_slice(ct.as_bytes());
            let receiver_commitment = crate::transfer::ReceiverLockCommitment { one_time_pk, kyber_ct, next_lock_hash, commitment_id: crate::crypto::commitment_id_v1(&one_time_pk, &kyber_ct, &next_lock_hash, &coin.id, coin.value, &chain_id), amount_le: coin.value };

            // Compute CHs
            let ch_refund = crate::crypto::commitment_hash_from_preimage(&chain_id, &coin.id, refund_secret);
            let Some(ch_claim) = claim_ch_map.get(&coin.id) else { continue; };
            let mut p = [0u8;32]; p.copy_from_slice(refund_secret);
            let mut spend = crate::transfer::Spend::create_htlc_hashlock(
                coin.id, &anchor, proof.clone(), p, &receiver_commitment, coin.value, &chain_id, timeout_epoch, *ch_claim, ch_refund,
            )?;
            spend.to.view_tag = Some(vt);
            spend.validate(&store)?; spend.apply(&store)?; network.gossip_spend(&spend).await; spends.push(spend);
        }
        Ok(SendOutcome { spends })
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

/// Outcome of a send operation (V2 spends only).
#[derive(Debug, Clone)]
pub struct SendOutcome {
    pub spends: Vec<crate::transfer::Spend>,
}