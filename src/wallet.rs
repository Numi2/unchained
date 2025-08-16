use crate::{
    storage::Store,
    crypto::{self, Address, DILITHIUM3_PK_BYTES, DILITHIUM3_SK_BYTES, KYBER768_PK_BYTES, KYBER768_SK_BYTES},
};
use pqcrypto_dilithium::dilithium3::{
    PublicKey, SecretKey, DetachedSignature, verify_detached_signature, detached_sign,
};
use pqcrypto_kyber::kyber768::{PublicKey as KyberPk, SecretKey as KyberSk};
use pqcrypto_traits::kem::PublicKey as KyberPkTrait; // enables KyberPk::from_bytes()
use pqcrypto_traits::kem::SecretKey as KyberSkTrait; // enables KyberSk::as_bytes()/from_bytes()
use pqcrypto_traits::sign::DetachedSignature as _;
use base64::Engine;
use serde::{Serialize, Deserialize};

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
use std::collections::HashSet;
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
    // Stealth Address: authenticated Kyber key distribution
    // ---------------------------------------------------------------------
    // Format (bincode then base64-url):
    // { version: u8=1, recipient_addr: [u8;32], dili_pk: [u8;DILITHIUM3_PK_BYTES], kyber_pk: [u8;crypto::KYBER768_PK_BYTES], sig: Dilithium sig over ("stealth_addr_v1" || addr || kyber_pk) }

    pub fn export_stealth_address(&self) -> String {
        let mut to_sign = Vec::with_capacity(16 + 32 + self.kyber_pk.as_bytes().len());
        to_sign.extend_from_slice(b"stealth_addr_v1");
        to_sign.extend_from_slice(&self.address);
        to_sign.extend_from_slice(self.kyber_pk.as_bytes());
        let sig = detached_sign(&to_sign, &self.sk);
        let doc = StealthAddressDoc {
            version: 1,
            recipient_addr: self.address,
            dili_pk: self.pk.as_bytes().to_vec(),
            kyber_pk: self.kyber_pk.as_bytes().to_vec(),
            sig: sig.as_bytes().to_vec(),
        };
        let bytes = bincode::serialize(&doc).expect("serialize stealth address");
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    pub fn parse_and_verify_stealth_address(addr_str: &str) -> Result<(Address, PublicKey, KyberPk)> {
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
        let doc: StealthAddressDoc = bincode::deserialize(&bytes)
            .map_err(|_| anyhow!("Invalid stealth address payload"))?;
        if doc.version != 1 { bail!("Unsupported stealth address version"); }
        let dili_pk = PublicKey::from_bytes(&doc.dili_pk)
            .map_err(|_| anyhow!("Invalid Dilithium PK in stealth address"))?;
        let kyber_pk = KyberPk::from_bytes(&doc.kyber_pk)
            .map_err(|_| anyhow!("Invalid Kyber PK in stealth address"))?;
        let mut to_verify = Vec::with_capacity(16 + 32 + doc.kyber_pk.len());
        to_verify.extend_from_slice(b"stealth_addr_v1");
        to_verify.extend_from_slice(&doc.recipient_addr);
        to_verify.extend_from_slice(&doc.kyber_pk);
        let sig = DetachedSignature::from_bytes(&doc.sig)
            .map_err(|_| anyhow!("Invalid signature in stealth address"))?;
        verify_detached_signature(&sig, &to_verify, &dili_pk)
            .map_err(|_| anyhow!("Stealth address signature verification failed"))?;
        Ok((doc.recipient_addr, dili_pk, kyber_pk))
    }

    // ---------------------------------------------------------------------
    // 🪙 UTXO helpers
    // ---------------------------------------------------------------------
    /// Returns all coins currently owned by this wallet that are **unspent**.
    /// Rules:
    /// - Exclude coins that already have a V2 spend recorded
    /// - If no legacy transfer exists: creator still owns it (creator_address == self.address)
    /// - If a legacy transfer exists: we own it if we can recover the one-time SK from its stealth output
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
                // If there is a V2 spend recorded, the current owner is the recipient of that spend
                if let Some(sp) = store.get::<crate::transfer::Spend>("spend", &coin.id)? {
                    let chain_id = store.get_chain_id()?;
                    if sp.to.try_recover_one_time_sk(&self.kyber_sk, &self.pk, &chain_id).is_ok() {
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
            if let Ok(sk) = spend.to.try_recover_one_time_sk(&self.kyber_sk, &self.pk, &chain_id) {
                // Persist OTP SK for this output (idempotent)
                let pk_hash = crate::crypto::blake3_hash(&spend.to.one_time_pk);
                store.put_otp_sk_if_absent(&pk_hash, sk.as_bytes())?;
                store.put_otp_index(&coin.id, &pk_hash)?;
                // Invariants: coin exists; spending updates are already recorded under CFs
                // Nothing to write here; scanning functions will reflect ownership.
                // Log once for visibility
                println!("📥 Detected incoming spend for me: coin {} value {}", hex::encode(coin.id), coin.value);
            }
        }
        Ok(())
    }

    /// Sum of `value` across all coins where current owner is this wallet
    /// Prefers V2 spends chain when present; otherwise uses legacy transfer.
    pub fn balance(&self) -> Result<u64> {
        let store = self
            ._db
            .upgrade()
            .ok_or_else(|| anyhow!("Database connection dropped"))?;

        let cf = store
            .db
            .cf_handle("coin")
            .ok_or_else(|| anyhow!("'coin' column family missing"))?;
        let iter = store.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut sum: u64 = 0;
        for item in iter {
            let (_key, value) = item?;
            if let Ok(coin) = crate::coin::decode_coin(&value) {
                // If there is a V2 spend recorded, the owner is the recipient of the spend's stealth
                let v2: Option<crate::transfer::Spend> = store.get("spend", &coin.id)?;
                if let Some(sp) = v2 {
                    let chain_id = store.get_chain_id()?;
                    if let Ok(_sk) = sp.to.try_recover_one_time_sk(&self.kyber_sk, &self.pk, &chain_id) {
                        sum = sum.saturating_add(coin.value);
                    }
                    continue;
                }
                // Else genesis owner is the creator
                if coin.creator_address == self.address {
                    sum = sum.saturating_add(coin.value);
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

    /// Deprecated: Use `send_to_stealth_address`.
    pub async fn send_transfer(
        &self,
        _to: crate::crypto::Address,
        _amount: u64,
        _network: &crate::network::NetHandle,
    ) -> Result<Vec<crate::transfer::Spend>> {
        Err(anyhow!("send_transfer(Address, ...) is deprecated. Use send_to_stealth_address(stealth_address, amount, network)"))
    }

    /// Sends stealth **V2 Spends** to a recipient using a signed stealth address string.
    pub async fn send_to_stealth_address(
        &self,
        stealth_address_str: &str,
        amount: u64,
        network: &crate::network::NetHandle,
    ) -> Result<SendOutcome> {
        let (_recipient_addr, recipient_dili_pk, recipient_kyber_pk) = Self::parse_and_verify_stealth_address(stealth_address_str)?;
        let store = self
            ._db
            .upgrade()
            .ok_or_else(|| anyhow!("Database connection dropped"))?;
        let coins_to_spend = self.select_inputs(amount)?;
        let mut spends = Vec::new();

        for coin in coins_to_spend {
            // Always prefer V2 spend flow. If no previous transfer, validate against coin.creator_pk.
            // 1) Try building a Merkle proof locally from stored epoch data.
            // Resolve the epoch that committed this coin; do not use coin.epoch_hash (parent anchor hash)
            let commit_epoch = store
                .get_epoch_for_coin(&coin.id)?
                .ok_or_else(|| anyhow!("Missing coin->epoch index for committed coin"))?;
            let local_anchor: crate::epoch::Anchor = store
                .get("epoch", &commit_epoch.to_le_bytes())?
                .ok_or_else(|| anyhow!("Anchor not found for committed epoch"))?;
            let leaf = crate::coin::Coin::id_to_leaf_hash(&coin.id);
            let mut anchor_used: crate::epoch::Anchor = local_anchor.clone();
            let mut proof_used: Option<Vec<([u8; 32], bool)>> = None;

            if let Some(leaves) = store.get_epoch_leaves(local_anchor.num)? {
                if leaves.binary_search(&leaf).is_ok() {
                    if let Some(p) = crate::epoch::MerkleTree::build_proof_from_leaves(&leaves, &leaf) {
                        if crate::epoch::MerkleTree::verify_proof(&leaf, &p, &local_anchor.merkle_root) {
                            proof_used = Some(p);
                        }
                    }
                }
            }
            if proof_used.is_none() {
                if let Ok(selected_ids) = store.get_selected_coin_ids_for_epoch(local_anchor.num) {
                    let set: HashSet<[u8; 32]> = HashSet::from_iter(selected_ids.into_iter());
                    if set.contains(&coin.id) {
                        if let Some(p) = crate::epoch::MerkleTree::build_proof(&set, &coin.id) {
                            if crate::epoch::MerkleTree::verify_proof(&leaf, &p, &local_anchor.merkle_root) {
                                proof_used = Some(p);
                            }
                        }
                    }
                }
            }

            // 1c) Last-resort local reconstruction: scan confirmed coins for this epoch and
            //     reconstruct the selected set deterministically. Only trust if complete.
            if proof_used.is_none() {
                if let Ok(all_confirmed) = store.iterate_coins() {
                    let mut ids: Vec<[u8;32]> = all_confirmed
                        .into_iter()
                        .filter(|c| c.epoch_hash == local_anchor.hash)
                        .map(|c| c.id)
                        .collect();
                    if ids.len() as u32 == local_anchor.coin_count {
                        let set: HashSet<[u8;32]> = HashSet::from_iter(ids.drain(..));
                        if set.contains(&coin.id) {
                            if let Some(p) = crate::epoch::MerkleTree::build_proof(&set, &coin.id) {
                                if crate::epoch::MerkleTree::verify_proof(&leaf, &p, &local_anchor.merkle_root) {
                                    proof_used = Some(p);
                                }
                            }
                        }
                    }
                }
            }

            // 2) If local proof unavailable, request and validate from the network with a deadline.
            if proof_used.is_none() {
                let mut proof_rx = network.proof_subscribe();
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
                // Proactively request sorted epoch leaves to help peers serve proofs deterministically
                network.request_epoch_leaves(local_anchor.num).await;
                network.request_coin_proof(coin.id).await;
                loop {
                    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                    if remaining.is_zero() { return Err(anyhow!("Timed out waiting for valid coin proof")); }
                    match tokio::time::timeout(remaining, proof_rx.recv()).await {
                        Ok(Ok(resp)) => {
                            if resp.coin.id != coin.id { continue; }
                            // Require exact epoch anchor match (hash and root)
                            if resp.anchor.hash != local_anchor.hash { continue; }
                            if local_anchor.merkle_root != resp.anchor.merkle_root { continue; }
                            if crate::epoch::MerkleTree::verify_proof(&leaf, &resp.proof, &resp.anchor.merkle_root) {
                                anchor_used = resp.anchor;
                                proof_used = Some(resp.proof);
                                break;
                            } else {
                                network.request_coin_proof(coin.id).await;
                                // Also re-ask for leaves in case peers lack them
                                network.request_epoch_leaves(local_anchor.num).await;
                                // Attempt local reconstruction again in case we fetched fresh leaves
                                if let Ok(Some(leaves)) = store.get_epoch_leaves(local_anchor.num) {
                                    if leaves.binary_search(&leaf).is_ok() {
                                        if let Some(p) = crate::epoch::MerkleTree::build_proof_from_leaves(&leaves, &leaf) {
                                            if crate::epoch::MerkleTree::verify_proof(&leaf, &p, &local_anchor.merkle_root) {
                                                proof_used = Some(p);
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        _ => { return Err(anyhow!("Timed out waiting for valid coin proof")); }
                    }
                }
            }

            // Determine current owner (pk, sk): prefer last V2 spend's OTP key, else genesis creator
            let (owner_pk, owner_sk) = {
                // If we have an OTP index entry, use it; otherwise attempt recovery for last spend; fallback to genesis owner
                let last_spend: Option<crate::transfer::Spend> = store.get("spend", &coin.id)?;
                if let Some(sp) = last_spend {
                    // Owner is OTP pk from last spend
                    let pk = PublicKey::from_bytes(&sp.to.one_time_pk)
                        .context("Invalid one-time pk in last spend")?;
                    // Try fetch persisted SK
                    if let Some(pk_hash) = store.get_otp_pk_hash_for_coin(&coin.id)? {
                        if let Some(sk_bytes) = store.get_otp_sk(&pk_hash)? {
                            let sk = SecretKey::from_bytes(&sk_bytes)
                                .map_err(|_| anyhow!("Corrupted stored OTP SK for coin"))?;
                            (pk, sk)
                        } else {
                            // Derive on-the-fly and persist
                            let chain_id = store.get_chain_id()?;
                            let sk = sp.to.try_recover_one_time_sk(&self.kyber_sk, &self.pk, &chain_id)
                                .context("Failed to derive OTP SK for our coin")?;
                            let pk_hash = crate::crypto::blake3_hash(&sp.to.one_time_pk);
                            store.put_otp_sk_if_absent(&pk_hash, sk.as_bytes())?;
                            store.put_otp_index(&coin.id, &pk_hash)?;
                            (pk, sk)
                        }
                    } else {
                        // No index; derive and persist
                        let chain_id = store.get_chain_id()?;
                        let sk = sp.to.try_recover_one_time_sk(&self.kyber_sk, &self.pk, &chain_id)
                            .context("Failed to derive OTP SK for our coin")?;
                        let pk_hash = crate::crypto::blake3_hash(&sp.to.one_time_pk);
                        store.put_otp_sk_if_absent(&pk_hash, sk.as_bytes())?;
                        store.put_otp_index(&coin.id, &pk_hash)?;
                        (pk, sk)
                    }
                } else if coin.creator_address == self.address {
                    (self.pk.clone(), self.sk.clone())
                } else {
                    // Not owned by this wallet
                    continue;
                }
            };

            // Build and broadcast V2 Spend
            let spend = crate::transfer::Spend::create(
                coin.id,
                &anchor_used,
                proof_used.expect("proof must be present after local or network path"),
                &owner_pk,               // NEW: pass public key for nullifier_v2 computation
                &owner_sk,
                &recipient_dili_pk,
                &recipient_kyber_pk,
                coin.value,
                &store.get_chain_id()?,
            )?;
            // Encryption already canonical in Spend::create
            spend.validate(&store)?;
            spend.apply(&store)?;
            network.gossip_spend(&spend).await;
            spends.push(spend);
        }
        Ok(SendOutcome { spends })
    }

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
                // Determine previous owner address
                let coin = match store.get::<crate::coin::Coin>("coin", &spend.coin_id)? {
                    Some(c) => c,
                    None => {
                        // Reorg or partial data: skip this spend in history view
                        continue;
                    }
                };
                let prev_owner_addr = coin.creator_address;

                // Compute transfer_hash for display as H(auth_bytes)
                let tx_hash = crypto::blake3_hash(&spend.auth_bytes());

                // Outgoing
                if prev_owner_addr == self.address {
                    // Counterparty is recipient address derived from one_time_pk
                    let pk = pqcrypto_dilithium::dilithium3::PublicKey::from_bytes(&spend.to.one_time_pk)?;
                    let recipient_addr = crypto::address_from_pk(&pk);
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
                if let Ok(_sk) = spend.to.try_recover_one_time_sk(&self.kyber_sk, &self.pk, &chain_id) {
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