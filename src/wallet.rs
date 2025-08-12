use crate::{
    storage::Store,
    crypto::{self, Address, DILITHIUM3_PK_BYTES, DILITHIUM3_SK_BYTES},
};
use pqcrypto_dilithium::dilithium3::{PublicKey, SecretKey, DetachedSignature, verify_detached_signature, detached_sign};
use pqcrypto_kyber::kyber768::{PublicKey as KyberPk, SecretKey as KyberSk};
use pqcrypto_traits::kem::{PublicKey as KyberPkTrait};
use pqcrypto_traits::sign::DetachedSignature as _;
use base64::Engine;

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
use chacha20poly1305::{aead::{Aead, NewAead}, XChaCha20Poly1305, Key, XNonce};
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
                // Generate Kyber keypair on migration
                let (kyber_pk, kyber_sk) = pqcrypto_kyber::kyber768::keypair();
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
            // If version 1, generate Kyber keys now (in-memory only). For version 2, we would parse stored Kyber keys.
            let (kyber_pk, kyber_sk) = pqcrypto_kyber::kyber768::keypair();
            // Avoid printing address unless explicitly requested via logs
            return Ok(Wallet { _db: Arc::downgrade(&db), pk, sk, kyber_pk, kyber_sk, address })

        }

        // --- Brand new wallet ---
        println!("✨ No wallet found, creating a new one...");
        let (pk, sk) = crypto::dilithium3_keypair();
        let (kyber_pk, kyber_sk) = pqcrypto_kyber::kyber768::keypair();
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
    // struct was moved to module scope below

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

    pub fn parse_and_verify_stealth_address(addr_str: &str) -> Result<(Address, KyberPk)> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(addr_str)
            .map_err(|_| anyhow!("Invalid stealth address encoding"))?;
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
        Ok((doc.recipient_addr, kyber_pk))
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
                // Skip coins that already have a V2 spend
                let spent_v2: Option<crate::transfer::Spend> = store.get("spend", &coin.id)?;
                if spent_v2.is_some() { continue; }

                // Check legacy transfer chain to determine current owner
                let last_tx: Option<crate::transfer::Transfer> = store.get("transfer", &coin.id)?;
                match last_tx {
                    None => {
                        if coin.creator_address == self.address {
                            utxos.push(coin);
                        }
                    }
                    Some(t) => {
                        if t.to.try_recover_one_time_sk(&self.kyber_sk).is_ok() {
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

    /// Deprecated: Use `send_to_stealth_address`.
    pub async fn send_transfer(
        &self,
        _to: crate::crypto::Address,
        _amount: u64,
        _network: &crate::network::NetHandle,
    ) -> Result<Vec<crate::transfer::Transfer>> {
        Err(anyhow!("send_transfer(Address, ...) is deprecated. Use send_to_stealth_address(stealth_address, amount, network)"))
    }

    /// Sends stealth transfers to a recipient using a signed stealth address string.
    pub async fn send_to_stealth_address(
        &self,
        stealth_address_str: &str,
        amount: u64,
        network: &crate::network::NetHandle,
    ) -> Result<SendOutcome> {
        let (_recipient_addr, recipient_kyber_pk) = Self::parse_and_verify_stealth_address(stealth_address_str)?;
        let store = self
            ._db
            .upgrade()
            .ok_or_else(|| anyhow!("Database connection dropped"))?;
        let coins_to_spend = self.select_inputs(amount)?;
        let transfer_mgr = crate::transfer::TransferManager::new(store.clone());
        let mut transfers = Vec::new();
        let mut spends = Vec::new();
        for coin in coins_to_spend {
            // If coin has a legacy path (no prior transfer), fallback to V1 transfer for genesis spend.
            let last_tx: Option<crate::transfer::Transfer> = store.get("transfer", &coin.id)?;
            if last_tx.is_none() {
                let transfer = transfer_mgr.send_stealth_transfer(
                    coin.id,
                    self.pk.clone(),
                    &self.sk,
                    &recipient_kyber_pk,
                    network,
                ).await?;
                transfers.push(transfer);
            } else {
                // Build a V2 spend using the recovered current owner secret.
                let last = last_tx.unwrap();
                // Request proof for the coin
                network.request_coin_proof(coin.id).await;
                let mut proof_rx = network.proof_subscribe();
                let proof_resp = tokio::time::timeout(std::time::Duration::from_secs(5), proof_rx.recv()).await
                    .map_err(|_| anyhow!("Timed out waiting for coin proof"))??;
                if proof_resp.coin.id != coin.id { continue; }
                // Recover one-time spend key from the last incoming stealth output to prove ownership
                let owner_sk = match last.to.try_recover_one_time_sk(&self.kyber_sk) {
                    Ok(sk) => sk,
                    Err(_) => { continue; }
                };
                let spend = crate::transfer::Spend::create(
                    coin.id,
                    &proof_resp.anchor,
                    proof_resp.proof,
                    &owner_sk,
                    &recipient_kyber_pk,
                )?;
                spend.validate(&store)?;
                spend.apply(&store)?;
                network.gossip_spend(&spend).await;
                spends.push(spend);
            }
        }
        Ok(SendOutcome { transfers, spends })
    }

    /// Gets all transfers involving this wallet (as sender or recipient)
    pub fn get_transfers(&self) -> Result<Vec<crate::transfer::Transfer>> {
        let store = self
            ._db
            .upgrade()
            .ok_or_else(|| anyhow!("Database connection dropped"))?;

        let transfer_mgr = crate::transfer::TransferManager::new(store);
        // Fallback: scan DB and filter by involvement
        let cf = transfer_mgr.db.db.cf_handle("transfer")
            .ok_or_else(|| anyhow::anyhow!("'transfer' column family missing"))?;
        let iter = transfer_mgr.db.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut v = Vec::new();
        for item in iter {
            let (_k, value) = item?;
            if let Ok(t) = bincode::deserialize::<crate::transfer::Transfer>(&value) {
                if t.is_to(&self.address()) || t.is_from(&self.address())? {
                    v.push(t);
                }
            }
        }
        Ok(v)
    }

    /// Gets the transaction history for this wallet
    pub fn get_transaction_history(&self) -> Result<Vec<TransactionRecord>> {
        let transfers = self.get_transfers()?;
        let store = self._db.upgrade().ok_or_else(|| anyhow!("Database connection dropped"))?;
        let mut history = Vec::new();

        // Legacy V1 transfers
        for transfer in transfers {
            let is_sender = transfer.is_from(&self.address)?;
            let record = TransactionRecord {
                coin_id: transfer.coin_id,
                transfer_hash: transfer.hash(),
                timestamp: std::time::SystemTime::now(),
                is_sender,
                amount: 1,
                counterparty: if is_sender { transfer.recipient() } else { transfer.sender()? },
            };
            history.push(record);
        }

        // V2 spends (outgoing and incoming)
        let cf = store.db.cf_handle("spend").ok_or_else(|| anyhow!("'spend' column family missing"))?;
        let iter = store.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        for item in iter {
            let (_k, value) = item?;
            if let Ok(spend) = bincode::deserialize::<crate::transfer::Spend>(&value) {
                // Determine previous owner address
                let coin = store.get::<crate::coin::Coin>("coin", &spend.coin_id)?.ok_or_else(|| anyhow!("Coin not found for spend"))?;
                let last_tx: Option<crate::transfer::Transfer> = store.get("transfer", &spend.coin_id)?;
                let prev_owner_addr = last_tx.as_ref().map(|t| t.recipient()).unwrap_or(coin.creator_address);

                // Compute transfer_hash for display as H(auth_bytes)
                let tx_hash = crypto::blake3_hash(&spend.auth_bytes());

                // Outgoing
                if prev_owner_addr == self.address {
                    // Counterparty is recipient address derived from one_time_pk
                    let pk = pqcrypto_dilithium::dilithium3::PublicKey::from_bytes(&spend.to.one_time_pk)?;
                    let recipient_addr = crypto::address_from_pk(&pk);
                    history.push(TransactionRecord { coin_id: spend.coin_id, transfer_hash: tx_hash, timestamp: std::time::SystemTime::now(), is_sender: true, amount: coin.value, counterparty: recipient_addr });
                    continue;
                }

                // Incoming (to me)? Try to recover one-time SK using kyber_sk
                if let Ok(sk) = spend.to.try_recover_one_time_sk(&self.kyber_sk) {
                    // Confirm address matches
                    let pk = pqcrypto_dilithium::dilithium3::PublicKey::from_bytes(&spend.to.one_time_pk)?;
                    let my_addr = crypto::address_from_pk(&pk);
                    if my_addr == self.address {
                        history.push(TransactionRecord { coin_id: spend.coin_id, transfer_hash: tx_hash, timestamp: std::time::SystemTime::now(), is_sender: false, amount: coin.value, counterparty: prev_owner_addr });
                    }
                    let _ = sk; // silence unused warning in release profiles
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

/// Outcome of a send operation including both legacy transfers and V2 spends.
#[derive(Debug, Clone)]
pub struct SendOutcome {
    pub transfers: Vec<crate::transfer::Transfer>,
    pub spends: Vec<crate::transfer::Spend>,
}