use crate::{
    canonical,
    consensus::ValidatorId,
    crypto::{
        self, Address, TaggedKemPublicKey, TaggedSigningPublicKey, ML_KEM_768_PK_BYTES,
        ML_KEM_768_SK_BYTES,
    },
    node_control::{NodeControlClient, NodeControlStateEnvelope, ShieldedRuntimeSnapshot},
    proof,
    protocol::CURRENT as PROTOCOL,
    shielded,
    storage::WalletStore,
    transaction::{
        ClaimUnbonding, OrdinaryPrivateTransfer, PrivateDelegation, PrivateUndelegation,
        SharedStateAction, ShieldedOutput, ShieldedOutputPlaintext, Tx,
    },
};
use aws_lc_rs::unstable::signature::PqdsaKeyPair;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientHandle {
    pub chain_id: [u8; 32],
    pub signing_pk: TaggedSigningPublicKey,
    #[serde(with = "BigArray")]
    pub receive_key_id: [u8; 32],
    pub kem_pk: TaggedKemPublicKey,
    pub issued_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub sig: Vec<u8>,
}
use anyhow::{anyhow, bail, Context, Result};
use argon2::{Argon2, Params};
use chacha20poly1305::{
    aead::{Aead, NewAead},
    Key, XChaCha20Poly1305, XNonce,
};
use std::sync::Arc;
// no AEAD usage in deterministic OTP flow
use atty;
use rand::rngs::OsRng;
use rand::RngCore;
use rpassword;

const WALLET_SECRET_KEY: &[u8] = b"default_keypair";
const WALLET_FORMAT_MAGIC: &[u8; 4] = b"UCW4";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const WALLET_FORMAT_VERSION: u8 = 1;
// Tunable KDF parameters for wallet encryption
const WALLET_KDF_MEM_KIB: u32 = 256 * 1024; // 256 MiB
const WALLET_KDF_TIME_COST: u32 = 3; // iterations
const SHIELDED_SYNC_ROUND_KEY: &[u8] = b"shielded_sync_round";
const SHIELDED_REFRESH_OFFSET_DOMAIN: &str = "unchained-wallet-shielded-refresh-offset-v1";
const SHIELDED_COVER_COMMIT_DOMAIN: &str = "unchained-wallet-shielded-cover-commitment-v1";
const SHIELDED_COVER_NULLIFIER_DOMAIN: &str = "unchained-wallet-shielded-cover-nullifier-v1";
const SHIELDED_STORE_MAGIC: &[u8; 4] = b"UCS4";
const SHIELDED_STORE_VERSION: u8 = 1;
const SHIELDED_STORE_DOMAIN: &str = "unchained-wallet-shielded-store-v1";
const SHIELDED_SEND_SEED_DOMAIN: &str = "unchained-wallet-shielded-send-seed-v1";
const SHIELDED_OUTPUT_ENTROPY_DOMAIN: &str = "unchained-wallet-shielded-output-entropy-v1";
const RECEIVE_KEY_LIFETIME_MS: u64 = 7 * 24 * 60 * 60 * 1000;
const RECEIVE_KEY_ID_DOMAIN: &str = "unchained-wallet-receive-key-id-v1";

#[derive(Serialize, Deserialize)]
struct WalletSecrets {
    signing_key_pkcs8: Vec<u8>,
    #[serde(with = "BigArray")]
    lock_seed: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OwnedShieldedNoteSource {
    Genesis { coin_id: [u8; 32] },
    Received { tx_id: [u8; 32], output_index: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OwnedShieldedNote {
    pub note: shielded::ShieldedNote,
    pub note_key: [u8; 32],
    pub checkpoint: shielded::HistoricalUnspentCheckpoint,
    pub checkpoint_accumulator: Option<proof::CheckpointAccumulatorProof>,
    pub source: OwnedShieldedNoteSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct SentShieldedTxRecord {
    tx_id: [u8; 32],
    commit_epoch: u64,
    amount: u64,
    fee_amount: u64,
    counterparty: Address,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ReceiveKeyRecord {
    #[serde(with = "BigArray")]
    pub key_id: [u8; 32],
    #[serde(with = "BigArray")]
    pub chain_id: [u8; 32],
    #[serde(with = "BigArray")]
    pub kem_sk: [u8; ML_KEM_768_SK_BYTES],
    #[serde(with = "BigArray")]
    pub kem_pk: [u8; ML_KEM_768_PK_BYTES],
    pub issued_unix_ms: u64,
    pub expires_unix_ms: u64,
}

#[derive(Debug, Clone)]
struct WalletReceiveKeyMaterial {
    key_id: [u8; 32],
    kem_pk: TaggedKemPublicKey,
    #[allow(dead_code)]
    issued_unix_ms: u64,
    #[allow(dead_code)]
    expires_unix_ms: u64,
    kem_sk: [u8; ML_KEM_768_SK_BYTES],
}

pub struct Wallet {
    wallet_db: Arc<WalletStore>,
    node_client: Option<NodeControlClient>,
    signing_pk: TaggedSigningPublicKey,
    signing_key: PqdsaKeyPair,
    lock_seed: [u8; 32],
    address: Address,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ShieldedOutputEntropy {
    note_key: [u8; 32],
    rho: [u8; 32],
    note_randomizer: [u8; 32],
    encapsulation_seed: [u8; proof_core::SHIELDED_OUTPUT_ENCAPSULATION_SEED_LEN],
    nonce: [u8; 24],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreparedShieldedTxStateBinding {
    chain_id: [u8; 32],
    current_nullifier_epoch: u64,
    note_tree_root: [u8; 32],
    root_ledger_digest: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct PreparedShieldedTx {
    state_binding: PreparedShieldedTxStateBinding,
    witness: proof_core::ProofShieldedTxWitness,
    nullifiers: Vec<[u8; 32]>,
    outputs: Vec<ShieldedOutput>,
    selected_notes: Vec<OwnedShieldedNote>,
    recipient_address: Address,
    current_epoch: u64,
    amount: u64,
}

#[derive(Debug, Clone)]
pub struct PreparedPrivateDelegation {
    state_binding: PreparedShieldedTxStateBinding,
    witness: proof_core::ProofPrivateDelegationWitness,
    nullifiers: Vec<[u8; 32]>,
    outputs: Vec<ShieldedOutput>,
    selected_notes: Vec<OwnedShieldedNote>,
    validator_id: ValidatorId,
}

#[derive(Debug, Clone)]
pub struct PreparedPrivateUndelegation {
    state_binding: PreparedShieldedTxStateBinding,
    witness: proof_core::ProofPrivateUndelegationWitness,
    nullifiers: Vec<[u8; 32]>,
    outputs: Vec<ShieldedOutput>,
    selected_notes: Vec<OwnedShieldedNote>,
    validator_id: ValidatorId,
}

#[derive(Debug, Clone)]
pub struct PreparedUnbondingClaim {
    state_binding: PreparedShieldedTxStateBinding,
    witness: proof_core::ProofShieldedTxWitness,
    nullifiers: Vec<[u8; 32]>,
    outputs: Vec<ShieldedOutput>,
    selected_notes: Vec<OwnedShieldedNote>,
}

impl PreparedShieldedTx {
    pub fn witness(&self) -> &proof_core::ProofShieldedTxWitness {
        &self.witness
    }

    pub fn output_count(&self) -> usize {
        self.outputs.len()
    }

    pub fn input_count(&self) -> usize {
        self.nullifiers.len()
    }

    pub fn tx_with_proof(&self, proof: Vec<u8>) -> Tx {
        Tx::new(
            self.nullifiers.clone(),
            self.outputs.clone(),
            self.witness.fee_amount,
            proof,
        )
    }
}

impl PreparedPrivateDelegation {
    pub fn witness(&self) -> &proof_core::ProofPrivateDelegationWitness {
        &self.witness
    }

    pub fn tx_with_proof(&self, proof: Vec<u8>) -> Tx {
        Tx::new_shared_state(
            SharedStateAction::PrivateDelegation(PrivateDelegation {
                validator_id: self.validator_id,
                transfer: OrdinaryPrivateTransfer {
                    nullifiers: self.nullifiers.clone(),
                    outputs: self.outputs.clone(),
                    fee_amount: self.witness.shielded.fee_amount,
                    proof,
                },
            }),
            Vec::new(),
        )
    }
}

impl PreparedPrivateUndelegation {
    pub fn witness(&self) -> &proof_core::ProofPrivateUndelegationWitness {
        &self.witness
    }

    pub fn tx_with_proof(&self, proof: Vec<u8>) -> Tx {
        Tx::new_shared_state(
            SharedStateAction::PrivateUndelegation(PrivateUndelegation {
                validator_id: self.validator_id,
                transfer: OrdinaryPrivateTransfer {
                    nullifiers: self.nullifiers.clone(),
                    outputs: self.outputs.clone(),
                    fee_amount: self.witness.shielded.fee_amount,
                    proof,
                },
            }),
            Vec::new(),
        )
    }
}

impl PreparedUnbondingClaim {
    pub fn witness(&self) -> &proof_core::ProofShieldedTxWitness {
        &self.witness
    }

    pub fn tx_with_proof(&self, proof: Vec<u8>) -> Tx {
        Tx::new_shared_state(
            SharedStateAction::ClaimUnbonding(ClaimUnbonding {
                transfer: OrdinaryPrivateTransfer {
                    nullifiers: self.nullifiers.clone(),
                    outputs: self.outputs.clone(),
                    fee_amount: self.witness.fee_amount,
                    proof,
                },
            }),
            Vec::new(),
        )
    }
}

impl Wallet {
    fn now_unix_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0)
    }

    fn derive_receive_key_id(
        chain_id: &[u8; 32],
        kem_pk: &TaggedKemPublicKey,
        issued_unix_ms: u64,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(RECEIVE_KEY_ID_DOMAIN);
        hasher.update(chain_id);
        hasher.update(kem_pk.as_slice());
        hasher.update(&issued_unix_ms.to_le_bytes());
        *hasher.finalize().as_bytes()
    }

    fn receive_key_record_to_material(record: &ReceiveKeyRecord) -> WalletReceiveKeyMaterial {
        WalletReceiveKeyMaterial {
            key_id: record.key_id,
            kem_pk: TaggedKemPublicKey::from_ml_kem_768_array(record.kem_pk),
            issued_unix_ms: record.issued_unix_ms,
            expires_unix_ms: record.expires_unix_ms,
            kem_sk: record.kem_sk,
        }
    }

    #[cfg(test)]
    fn load_receive_key_record(
        &self,
        store: &WalletStore,
        key_id: &[u8; 32],
    ) -> Result<Option<ReceiveKeyRecord>> {
        let cf = store
            .db
            .cf_handle("wallet_receive_key")
            .ok_or_else(|| anyhow!("'wallet_receive_key' column family missing"))?;
        match store.db.get_cf(cf, key_id)? {
            Some(bytes) => {
                let plaintext = self.decrypt_shielded_state(&bytes)?;
                Ok(Some(bincode::deserialize(&plaintext)?))
            }
            None => Ok(None),
        }
    }

    fn iterate_receive_key_records(&self, store: &WalletStore) -> Result<Vec<ReceiveKeyRecord>> {
        let cf = store
            .db
            .cf_handle("wallet_receive_key")
            .ok_or_else(|| anyhow!("'wallet_receive_key' column family missing"))?;
        let iter = store.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut keys = Vec::new();
        for item in iter {
            let (_key, value) = item?;
            let plaintext = self.decrypt_shielded_state(&value)?;
            keys.push(bincode::deserialize(&plaintext)?);
        }
        Ok(keys)
    }

    fn delete_receive_key_record(&self, store: &WalletStore, key_id: &[u8; 32]) -> Result<()> {
        let cf = store
            .db
            .cf_handle("wallet_receive_key")
            .ok_or_else(|| anyhow!("'wallet_receive_key' column family missing"))?;
        store.db.delete_cf(cf, key_id)?;
        Ok(())
    }

    fn store_receive_key_record(
        &self,
        store: &WalletStore,
        record: &ReceiveKeyRecord,
    ) -> Result<()> {
        let cf = store
            .db
            .cf_handle("wallet_receive_key")
            .ok_or_else(|| anyhow!("'wallet_receive_key' column family missing"))?;
        let plaintext = bincode::serialize(record)?;
        let encrypted = self.encrypt_shielded_state(&plaintext)?;
        store.db.put_cf(cf, &record.key_id, encrypted)?;
        Ok(())
    }

    fn generate_receive_key_record(
        &self,
        chain_id: [u8; 32],
        issued_unix_ms: u64,
        expires_unix_ms: u64,
    ) -> ReceiveKeyRecord {
        let (kem_sk, kem_pk) = crypto::ml_kem_768_generate();
        let key_id = Self::derive_receive_key_id(&chain_id, &kem_pk, issued_unix_ms);
        ReceiveKeyRecord {
            key_id,
            chain_id,
            kem_sk: crypto::ml_kem_768_secret_key_to_bytes(&kem_sk),
            kem_pk: kem_pk.bytes,
            issued_unix_ms,
            expires_unix_ms,
        }
    }

    fn build_recipient_handle(
        &self,
        chain_id: [u8; 32],
        record: &ReceiveKeyRecord,
    ) -> Result<RecipientHandle> {
        let kem_pk = TaggedKemPublicKey::from_ml_kem_768_array(record.kem_pk);
        let msg = canonical::encode_recipient_handle_signable(
            &chain_id,
            &self.signing_pk,
            &record.key_id,
            &kem_pk,
            record.issued_unix_ms,
            record.expires_unix_ms,
        )?;
        let sig = crypto::ml_dsa_65_sign(&self.signing_key, &msg)?;
        Ok(RecipientHandle {
            chain_id,
            signing_pk: self.signing_pk.clone(),
            receive_key_id: record.key_id,
            kem_pk,
            issued_unix_ms: record.issued_unix_ms,
            expires_unix_ms: record.expires_unix_ms,
            sig,
        })
    }

    fn prune_expired_receive_key_records(&self, store: &WalletStore) -> Result<()> {
        let now_unix_ms = Self::now_unix_ms();
        let expired = self
            .iterate_receive_key_records(store)?
            .into_iter()
            .filter(|record| now_unix_ms >= record.expires_unix_ms)
            .map(|record| record.key_id)
            .collect::<Vec<_>>();
        for key_id in expired {
            self.delete_receive_key_record(store, &key_id)?;
        }
        Ok(())
    }

    fn mint_receive_key_record(
        &self,
        store: &WalletStore,
        chain_id: [u8; 32],
    ) -> Result<ReceiveKeyRecord> {
        self.prune_expired_receive_key_records(store)?;
        let issued_unix_ms = Self::now_unix_ms();
        let expires_unix_ms = issued_unix_ms.saturating_add(RECEIVE_KEY_LIFETIME_MS);
        let record = self.generate_receive_key_record(chain_id, issued_unix_ms, expires_unix_ms);
        self.store_receive_key_record(store, &record)?;
        Ok(record)
    }

    fn mint_internal_receive_kem_public_key_for_chain(
        &self,
        chain_id: [u8; 32],
    ) -> Result<TaggedKemPublicKey> {
        let wallet_store = self.wallet_store()?;
        let record = self.mint_receive_key_record(wallet_store.as_ref(), chain_id)?;
        Ok(TaggedKemPublicKey::from_ml_kem_768_array(record.kem_pk))
    }

    fn mint_recipient_handle_for_chain(&self, chain_id: [u8; 32]) -> Result<String> {
        let wallet_store = self.wallet_store()?;
        let record = self.mint_receive_key_record(wallet_store.as_ref(), chain_id)?;
        serde_json::to_string(&self.build_recipient_handle(chain_id, &record)?)
            .context("serialize recipient handle")
    }

    fn receive_key_materials(&self, store: &WalletStore) -> Result<Vec<WalletReceiveKeyMaterial>> {
        self.prune_expired_receive_key_records(store)?;
        let now_unix_ms = Self::now_unix_ms();
        let mut materials = self
            .iterate_receive_key_records(store)?
            .into_iter()
            .filter(|record| now_unix_ms < record.expires_unix_ms)
            .map(|record| Self::receive_key_record_to_material(&record))
            .collect::<Vec<_>>();
        materials.sort_by(|left, right| {
            right
                .issued_unix_ms
                .cmp(&left.issued_unix_ms)
                .then(right.key_id.cmp(&left.key_id))
        });
        Ok(materials)
    }

    fn require_node_client(&self) -> Result<&NodeControlClient> {
        self.node_client
            .as_ref()
            .ok_or_else(|| anyhow!("wallet requires an active node control client"))
    }

    fn wallet_store(&self) -> Result<Arc<WalletStore>> {
        Ok(self.wallet_db.clone())
    }

    pub fn with_node_client(mut self, node_client: NodeControlClient) -> Self {
        self.node_client = Some(node_client);
        self
    }

    fn current_node_state(&self) -> Result<NodeControlStateEnvelope> {
        self.require_node_client()?.state()
    }

    fn effective_chain_id(&self) -> Result<[u8; 32]> {
        Ok(self.current_node_state()?.state.shielded_runtime.chain_id)
    }

    fn shielded_runtime_snapshot(&self) -> Result<ShieldedRuntimeSnapshot> {
        Ok(self.current_node_state()?.state.shielded_runtime)
    }

    fn root_ledger_digest(ledger: &shielded::NullifierRootLedger) -> Result<[u8; 32]> {
        Ok(crate::crypto::blake3_hash(
            &canonical::encode_nullifier_root_ledger(ledger)?,
        ))
    }

    pub(crate) fn node_client(&self) -> Result<NodeControlClient> {
        Ok(self.require_node_client()?.clone())
    }

    fn state_binding_from_snapshot(
        snapshot: &ShieldedRuntimeSnapshot,
    ) -> Result<PreparedShieldedTxStateBinding> {
        Ok(PreparedShieldedTxStateBinding {
            chain_id: snapshot.chain_id,
            current_nullifier_epoch: snapshot.current_nullifier_epoch,
            note_tree_root: snapshot.note_tree.root(),
            root_ledger_digest: Self::root_ledger_digest(&snapshot.root_ledger)?,
        })
    }

    fn load_or_create_private_inner(wallet_db: Arc<WalletStore>) -> Result<Self> {
        // Helper to obtain a pass-phrase depending on environment
        fn obtain_passphrase(prompt: &str) -> Result<String> {
            if let Ok(p) = std::env::var("WALLET_PASSPHRASE") {
                return Ok(p);
            }
            if atty::is(atty::Stream::Stdin) {
                let pw =
                    rpassword::prompt_password(prompt).context("Failed to read pass-phrase")?;
                Ok(pw)
            } else {
                // Non-interactive (prod/CI): require env var, fail fast if missing
                std::env::var("WALLET_PASSPHRASE")
                    .map_err(|_| anyhow!("WALLET_PASSPHRASE is required in non-interactive mode"))
            }
        }

        if let Some(encoded) = wallet_db.get_raw_bytes("wallet_secret", WALLET_SECRET_KEY)? {
            if encoded.len() < WALLET_FORMAT_MAGIC.len() + 1 + SALT_LEN + NONCE_LEN {
                bail!("Unsupported wallet encoding");
            }
            if &encoded[..WALLET_FORMAT_MAGIC.len()] != WALLET_FORMAT_MAGIC {
                bail!("Unsupported wallet format; create a fresh wallet for the unified receive-handle architecture");
            }
            let version = encoded[WALLET_FORMAT_MAGIC.len()];
            if version != WALLET_FORMAT_VERSION {
                bail!("Unsupported wallet version: {}", version);
            }

            let salt_start = WALLET_FORMAT_MAGIC.len() + 1;
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

            let secrets: WalletSecrets = bincode::deserialize(&decrypted)
                .map_err(|_| anyhow!("Corrupted wallet payload"))?;
            let signing_key = crypto::ml_dsa_65_keypair_from_pkcs8(&secrets.signing_key_pkcs8)?;
            let signing_pk = crypto::ml_dsa_65_public_key(&signing_key);
            let mut key_zero = key;
            key_zero.iter_mut().for_each(|b| *b = 0);

            return Ok(Wallet {
                wallet_db,
                node_client: None,
                signing_pk: signing_pk.clone(),
                signing_key,
                lock_seed: secrets.lock_seed,
                address: crypto::address_from_pk(&signing_pk),
            });
        }

        println!("✨ No wallet found, creating a new one...");
        let passphrase = obtain_passphrase("Set a pass-phrase for your new wallet: ")?;
        let mut salt = [0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let signing_key = crypto::ml_dsa_65_generate()?;
        let signing_pk = crypto::ml_dsa_65_public_key(&signing_key);
        let address = crypto::address_from_pk(&signing_pk);
        let mut lock_seed = [0u8; 32];
        OsRng.fill_bytes(&mut lock_seed);

        let mut key = [0u8; 32];
        let params = Params::new(WALLET_KDF_MEM_KIB, WALLET_KDF_TIME_COST, 1, None)
            .map_err(|e| anyhow!("Invalid Argon2id params: {}", e))?;
        Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
            .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
            .map_err(|e| anyhow!("Argon2id key derivation failed: {}", e))?;

        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let secrets = WalletSecrets {
            signing_key_pkcs8: crypto::ml_dsa_65_keypair_to_pkcs8(&signing_key)?,
            lock_seed,
        };
        let plaintext = bincode::serialize(&secrets)?;
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), plaintext.as_ref())
            .map_err(|e| anyhow!("Failed to encrypt secret payload: {}", e))?;
        key.iter_mut().for_each(|b| *b = 0);

        let mut encoded = Vec::with_capacity(
            WALLET_FORMAT_MAGIC.len() + 1 + SALT_LEN + NONCE_LEN + ciphertext.len(),
        );
        encoded.extend_from_slice(WALLET_FORMAT_MAGIC);
        encoded.push(WALLET_FORMAT_VERSION);
        encoded.extend_from_slice(&salt);
        encoded.extend_from_slice(&nonce);
        encoded.extend_from_slice(&ciphertext);

        wallet_db.put_raw_bytes("wallet_secret", WALLET_SECRET_KEY, &encoded)?;
        println!("✅ New wallet created and saved");
        Ok(Wallet {
            wallet_db,
            node_client: None,
            signing_pk,
            signing_key,
            lock_seed,
            address,
        })
    }

    /// Loads the private wallet material without opening the chain database.
    /// Use this for runtimes that only need signing identity and lock derivation.
    pub fn load_or_create_private(wallet_db: Arc<WalletStore>) -> Result<Self> {
        Self::load_or_create_private_inner(wallet_db)
    }

    pub fn address(&self) -> Address {
        self.address
    }

    /// Gets the public key
    pub fn public_key(&self) -> &TaggedSigningPublicKey {
        &self.signing_pk
    }

    /// INTERNAL: compute genesis lock secret deterministically for a coin we created.
    pub fn compute_genesis_lock_secret(
        &self,
        coin_id: &[u8; 32],
        chain_id32: &[u8; 32],
    ) -> [u8; 32] {
        crate::crypto::derive_genesis_lock_secret(&self.lock_seed, coin_id, chain_id32)
    }

    fn shielded_storage_key(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(SHIELDED_STORE_DOMAIN);
        hasher.update(&self.lock_seed);
        hasher.update(&self.address);
        *hasher.finalize().as_bytes()
    }

    fn encrypt_shielded_state(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut key = self.shielded_storage_key();
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), plaintext)
            .map_err(|_| anyhow!("failed to encrypt shielded wallet state"))?;
        key.iter_mut().for_each(|byte| *byte = 0);

        let mut encoded =
            Vec::with_capacity(SHIELDED_STORE_MAGIC.len() + 1 + NONCE_LEN + ciphertext.len());
        encoded.extend_from_slice(SHIELDED_STORE_MAGIC);
        encoded.push(SHIELDED_STORE_VERSION);
        encoded.extend_from_slice(&nonce);
        encoded.extend_from_slice(&ciphertext);
        Ok(encoded)
    }

    fn decrypt_shielded_state(&self, encoded: &[u8]) -> Result<Vec<u8>> {
        let min_len = SHIELDED_STORE_MAGIC.len() + 1 + NONCE_LEN;
        if encoded.len() < min_len {
            bail!("shielded wallet state is truncated");
        }
        if &encoded[..SHIELDED_STORE_MAGIC.len()] != SHIELDED_STORE_MAGIC {
            bail!("unsupported shielded wallet state format");
        }
        if encoded[SHIELDED_STORE_MAGIC.len()] != SHIELDED_STORE_VERSION {
            bail!("unsupported shielded wallet state version");
        }

        let nonce_start = SHIELDED_STORE_MAGIC.len() + 1;
        let nonce_end = nonce_start + NONCE_LEN;
        let nonce = &encoded[nonce_start..nonce_end];
        let ciphertext = &encoded[nonce_end..];

        let mut key = self.shielded_storage_key();
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        let plaintext = cipher
            .decrypt(XNonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow!("failed to decrypt shielded wallet state"))?;
        key.iter_mut().for_each(|byte| *byte = 0);
        Ok(plaintext)
    }

    fn store_owned_note_record(
        &self,
        store: &WalletStore,
        owned: &OwnedShieldedNote,
    ) -> Result<()> {
        let cf = store
            .db
            .cf_handle("shielded_owned_note")
            .ok_or_else(|| anyhow!("'shielded_owned_note' column family missing"))?;
        let plaintext = bincode::serialize(owned)?;
        let encrypted = self.encrypt_shielded_state(&plaintext)?;
        store.db.put_cf(cf, &owned.note.commitment, encrypted)?;
        Ok(())
    }

    fn load_owned_note_record(
        &self,
        store: &WalletStore,
        note_commitment: &[u8; 32],
    ) -> Result<Option<OwnedShieldedNote>> {
        let cf = store
            .db
            .cf_handle("shielded_owned_note")
            .ok_or_else(|| anyhow!("'shielded_owned_note' column family missing"))?;
        match store.db.get_cf(cf, note_commitment)? {
            Some(bytes) => {
                let plaintext = self.decrypt_shielded_state(&bytes)?;
                Ok(Some(bincode::deserialize(&plaintext)?))
            }
            None => Ok(None),
        }
    }

    fn iterate_owned_note_records(&self, store: &WalletStore) -> Result<Vec<OwnedShieldedNote>> {
        let cf = store
            .db
            .cf_handle("shielded_owned_note")
            .ok_or_else(|| anyhow!("'shielded_owned_note' column family missing"))?;
        let iter = store.db.iterator_cf(cf, rocksdb::IteratorMode::Start);
        let mut notes = Vec::new();
        for item in iter {
            let (_key, value) = item?;
            let plaintext = self.decrypt_shielded_state(&value)?;
            notes.push(bincode::deserialize(&plaintext)?);
        }
        Ok(notes)
    }

    fn store_checkpoint_record(
        &self,
        store: &WalletStore,
        checkpoint: &shielded::HistoricalUnspentCheckpoint,
    ) -> Result<()> {
        let cf = store
            .db
            .cf_handle("shielded_checkpoint")
            .ok_or_else(|| anyhow!("'shielded_checkpoint' column family missing"))?;
        let plaintext = canonical::encode_historical_unspent_checkpoint(checkpoint)?;
        let encrypted = self.encrypt_shielded_state(&plaintext)?;
        store
            .db
            .put_cf(cf, &checkpoint.note_commitment, encrypted)?;
        Ok(())
    }

    // ---------------------------------------------------------------------
    // Single-use receive handles
    // ---------------------------------------------------------------------
    pub fn export_address(&self) -> Result<String> {
        self.export_address_for_chain(self.effective_chain_id()?)
    }

    fn export_address_for_chain(&self, chain_id: [u8; 32]) -> Result<String> {
        self.mint_recipient_handle_for_chain(chain_id)
    }

    pub fn export_stealth_address(&self) -> Result<String> {
        self.export_address()
    }

    pub fn parse_address(
        addr_str: &str,
    ) -> Result<(Address, TaggedSigningPublicKey, TaggedKemPublicKey)> {
        let handle = Self::parse_recipient_handle_document(addr_str)?;
        Ok((
            crate::crypto::address_from_pk(&handle.signing_pk),
            handle.signing_pk,
            handle.kem_pk,
        ))
    }

    pub fn parse_stealth_address(
        addr_str: &str,
    ) -> Result<(Address, TaggedSigningPublicKey, TaggedKemPublicKey)> {
        Self::parse_address(addr_str)
    }

    fn parse_recipient_handle(
        &self,
        handle: &str,
    ) -> Result<(
        Address,
        TaggedSigningPublicKey,
        TaggedKemPublicKey,
        [u8; 32],
    )> {
        let chain_id = self.effective_chain_id()?;
        self.parse_recipient_handle_for_chain(handle, chain_id)
    }

    fn parse_recipient_handle_for_chain(
        &self,
        handle: &str,
        chain_id: [u8; 32],
    ) -> Result<(
        Address,
        TaggedSigningPublicKey,
        TaggedKemPublicKey,
        [u8; 32],
    )> {
        let handle = Self::parse_recipient_handle_document(handle)?;
        if handle.chain_id != chain_id {
            bail!("recipient handle chain_id mismatch");
        }
        Ok((
            crate::crypto::address_from_pk(&handle.signing_pk),
            handle.signing_pk,
            handle.kem_pk,
            handle.receive_key_id,
        ))
    }

    pub fn validate_recipient_handle(&self, handle: &str) -> Result<()> {
        self.parse_recipient_handle(handle).map(|_| ())
    }

    fn parse_recipient_handle_document(handle_str: &str) -> Result<RecipientHandle> {
        let trimmed = handle_str.trim();
        if !(trimmed.starts_with('{') && trimmed.ends_with('}')) {
            bail!("recipient handle must be a signed JSON document");
        }
        let handle: RecipientHandle =
            serde_json::from_str(trimmed).context("invalid recipient handle JSON")?;
        if handle.expires_unix_ms <= handle.issued_unix_ms {
            bail!("recipient handle expiration must be after issuance");
        }
        if Self::now_unix_ms() >= handle.expires_unix_ms {
            bail!("recipient handle has expired");
        }
        let msg = canonical::encode_recipient_handle_signable(
            &handle.chain_id,
            &handle.signing_pk,
            &handle.receive_key_id,
            &handle.kem_pk,
            handle.issued_unix_ms,
            handle.expires_unix_ms,
        )?;
        handle.signing_pk.verify(&msg, &handle.sig)?;
        Ok(handle)
    }

    fn materialize_owned_genesis_notes(&self, snapshot: &ShieldedRuntimeSnapshot) -> Result<()> {
        let wallet_store = self.wallet_store()?;
        for (birth_epoch, coin) in &snapshot.committed_coins {
            if coin.creator_address != self.address {
                continue;
            }
            let (note, note_key, checkpoint) =
                shielded::deterministic_genesis_note(coin, *birth_epoch, &snapshot.chain_id);
            if self
                .load_owned_note_record(wallet_store.as_ref(), &note.commitment)?
                .is_none()
            {
                let owned = OwnedShieldedNote {
                    note: note.clone(),
                    note_key,
                    checkpoint,
                    checkpoint_accumulator: None,
                    source: OwnedShieldedNoteSource::Genesis { coin_id: coin.id },
                };
                self.store_owned_note_record(wallet_store.as_ref(), &owned)?;
                self.store_checkpoint_record(wallet_store.as_ref(), &owned.checkpoint)?;
            }
        }
        Ok(())
    }

    fn decrypt_shielded_output(
        &self,
        output: &ShieldedOutput,
    ) -> Result<Option<(ShieldedOutputPlaintext, [u8; 32])>> {
        let wallet_store = self.wallet_store()?;
        for material in self.receive_key_materials(wallet_store.as_ref())? {
            let shared = crypto::ml_kem_768_decapsulate(
                &crypto::ml_kem_768_secret_key_from_bytes(&material.kem_sk),
                &output.kem_ct,
            )?;
            if crypto::view_tag(&shared) != output.view_tag {
                continue;
            }

            let cipher = XChaCha20Poly1305::new(Key::from_slice(&shared));
            let plaintext = match cipher.decrypt(
                XNonce::from_slice(&output.nonce),
                output.ciphertext.as_ref(),
            ) {
                Ok(plaintext) => plaintext,
                Err(_) => continue,
            };
            let decoded = proof::output_plaintext_from_proof(
                &bincode::deserialize::<proof_core::ProofShieldedOutputPlaintext>(&plaintext)
                    .map_err(|err| anyhow!("failed to decode shielded output payload: {err}"))?,
            )?;
            if decoded.note.commitment != output.note_commitment {
                bail!("shielded output plaintext commitment mismatch");
            }
            if decoded.note.owner_signing_pk != self.signing_pk
                || decoded.note.owner_kem_pk != material.kem_pk
            {
                continue;
            }
            if shielded::note_key_commitment(&decoded.note_key) != decoded.note.note_key_commitment
            {
                bail!("shielded output note key does not match the commitment");
            }
            return Ok(Some((decoded, material.key_id)));
        }
        Ok(None)
    }

    fn rescan_shielded_outputs(&self, snapshot: &ShieldedRuntimeSnapshot) -> Result<()> {
        let wallet_store = self.wallet_store()?;
        for (tx_id, output_index, output) in &snapshot.shielded_outputs {
            let Some((plaintext, _receive_key_id)) = self.decrypt_shielded_output(&output)? else {
                continue;
            };
            if self
                .load_owned_note_record(wallet_store.as_ref(), &output.note_commitment)?
                .is_some()
            {
                continue;
            }
            let owned = OwnedShieldedNote {
                note: plaintext.note.clone(),
                note_key: plaintext.note_key,
                checkpoint: plaintext.checkpoint,
                checkpoint_accumulator: None,
                source: OwnedShieldedNoteSource::Received {
                    tx_id: *tx_id,
                    output_index: *output_index,
                },
            };
            self.store_owned_note_record(wallet_store.as_ref(), &owned)?;
            self.store_checkpoint_record(wallet_store.as_ref(), &owned.checkpoint)?;
        }
        Ok(())
    }

    fn sync_owned_shielded_notes_with_snapshot(
        &self,
        snapshot: &ShieldedRuntimeSnapshot,
    ) -> Result<()> {
        self.materialize_owned_genesis_notes(&snapshot)?;
        self.rescan_shielded_outputs(&snapshot)?;
        Ok(())
    }

    fn sync_owned_shielded_notes(&self) -> Result<()> {
        let snapshot = self.shielded_runtime_snapshot()?;
        self.sync_owned_shielded_notes_with_snapshot(&snapshot)
    }

    pub fn sync_shielded_notes(&self) -> Result<()> {
        self.sync_owned_shielded_notes()
    }

    pub fn list_owned_shielded_notes(&self) -> Result<Vec<OwnedShieldedNote>> {
        self.load_owned_shielded_notes(true, true)
    }

    fn load_owned_shielded_notes(
        &self,
        sync: bool,
        unspent_only: bool,
    ) -> Result<Vec<OwnedShieldedNote>> {
        let wallet_store = self.wallet_store()?;
        if sync {
            self.sync_owned_shielded_notes()?;
        }
        self.load_owned_shielded_notes_local(wallet_store.as_ref(), unspent_only)
    }

    fn load_owned_shielded_notes_for_snapshot(
        &self,
        snapshot: &ShieldedRuntimeSnapshot,
        unspent_only: bool,
    ) -> Result<Vec<OwnedShieldedNote>> {
        let wallet_store = self.wallet_store()?;
        self.sync_owned_shielded_notes_with_snapshot(snapshot)?;
        self.load_owned_shielded_notes_local(wallet_store.as_ref(), unspent_only)
    }

    fn load_owned_shielded_notes_local(
        &self,
        wallet_store: &WalletStore,
        unspent_only: bool,
    ) -> Result<Vec<OwnedShieldedNote>> {
        let mut notes = self.iterate_owned_note_records(wallet_store)?;
        if unspent_only {
            notes.retain(|note| {
                self.is_owned_note_spent(wallet_store, &note.note.commitment)
                    .map(|spent| !spent)
                    .unwrap_or(false)
            });
        }
        notes.sort_by(|a, b| {
            b.note
                .birth_epoch
                .cmp(&a.note.birth_epoch)
                .then(b.note.commitment.cmp(&a.note.commitment))
        });
        Ok(notes)
    }

    fn retain_payment_notes(notes: &mut Vec<OwnedShieldedNote>) {
        notes.retain(|note| note.note.kind.is_payment());
    }

    fn retain_delegation_share_notes(
        notes: &mut Vec<OwnedShieldedNote>,
        validator_id: ValidatorId,
    ) {
        notes.retain(|note| note.note.kind.is_delegation_share_for(&validator_id.0));
    }

    fn retain_mature_unbonding_claim_notes(notes: &mut Vec<OwnedShieldedNote>, current_epoch: u64) {
        notes.retain(|note| {
            note.note
                .kind
                .unbonding_release_epoch()
                .map(|release_epoch| release_epoch <= current_epoch)
                .unwrap_or(false)
        });
    }

    fn validator_pool_from_state(
        state: &NodeControlStateEnvelope,
        validator_id: ValidatorId,
    ) -> Result<crate::staking::ValidatorPool> {
        state
            .state
            .consensus_status
            .registered_validator_pools
            .iter()
            .find(|pool| pool.validator.id == validator_id)
            .cloned()
            .ok_or_else(|| anyhow!("validator pool not found"))
    }

    fn build_fee_payment_from_snapshot_with_notes(
        &self,
        snapshot: &ShieldedRuntimeSnapshot,
        mut available_notes: Vec<OwnedShieldedNote>,
        fee_amount: u64,
    ) -> Result<PreparedShieldedTx> {
        Self::retain_payment_notes(&mut available_notes);
        let mut selected_notes = Vec::new();
        let mut total_selected = 0u64;
        for note in available_notes {
            total_selected = total_selected.saturating_add(note.note.value);
            selected_notes.push(note);
            if total_selected > fee_amount {
                break;
            }
        }
        if total_selected <= fee_amount {
            bail!(
                "insufficient funds for shielded shared-state fee payment: need value above fee {}, available {}",
                fee_amount,
                total_selected
            );
        }
        let total_selected = selected_notes
            .iter()
            .fold(0u64, |sum, note| sum.saturating_add(note.note.value));
        let state_binding = Self::state_binding_from_snapshot(snapshot)?;
        let current_epoch = snapshot.current_nullifier_epoch;
        let note_tree = &snapshot.note_tree;
        let tree_root = note_tree.root();
        let chain_id = snapshot.chain_id;
        let send_seed =
            self.derive_send_seed(&self.address, 0, fee_amount, current_epoch, &selected_notes);

        let mut input_witnesses = Vec::with_capacity(selected_notes.len());
        let mut nullifiers = Vec::with_capacity(selected_notes.len());
        for owned in &selected_notes {
            let membership_proof = note_tree
                .prove_membership(&owned.note.commitment)
                .ok_or_else(|| anyhow!("missing membership proof for shared-state fee note"))?;
            if membership_proof.root != tree_root {
                bail!("shielded note tree changed while building the shared-state fee payment");
            }
            let current_nullifier =
                owned
                    .note
                    .derive_evolving_nullifier(&owned.note_key, &chain_id, current_epoch)?;
            nullifiers.push(current_nullifier);
            input_witnesses.push(proof::input_witness_from_local(
                &owned.note,
                &owned.note_key,
                &membership_proof,
                &owned.checkpoint,
                owned.checkpoint_accumulator.as_ref(),
                &current_nullifier,
            ));
        }

        let mut outputs = Vec::new();
        let mut output_witnesses = Vec::new();
        let change = total_selected.saturating_sub(fee_amount);
        if change > 0 {
            let change_entropy = self.derive_output_entropy(&send_seed, 0);
            let change_receive_kem_pk =
                self.mint_internal_receive_kem_public_key_for_chain(snapshot.chain_id)?;
            let (change_output, change_plaintext, change_encapsulation_seed) = self
                .build_shielded_output(
                    self.signing_pk.clone(),
                    change_receive_kem_pk,
                    change,
                    current_epoch,
                    &change_entropy,
                )?;
            output_witnesses.push(proof::output_witness_from_local(
                &change_plaintext,
                &change_output,
                &change_encapsulation_seed,
            ));
            outputs.push(change_output);
        }

        let witness = proof_core::ProofShieldedTxWitness {
            chain_id,
            current_epoch,
            note_tree_root: tree_root,
            fee_amount,
            inputs: input_witnesses,
            outputs: output_witnesses,
        };
        Ok(PreparedShieldedTx {
            state_binding,
            witness,
            nullifiers,
            outputs,
            selected_notes,
            recipient_address: self.address,
            current_epoch,
            amount: 0,
        })
    }

    pub fn prepare_fee_payment_for_snapshot(
        &self,
        snapshot: &ShieldedRuntimeSnapshot,
        fee_amount: u64,
    ) -> Result<PreparedShieldedTx> {
        let available_notes = self.load_owned_shielded_notes_for_snapshot(snapshot, true)?;
        self.build_fee_payment_from_snapshot_with_notes(snapshot, available_notes, fee_amount)
    }

    fn prepare_owned_checkpoint_requests(
        &self,
        notes: &[OwnedShieldedNote],
        through_epoch: u64,
        chain_id: [u8; 32],
    ) -> Result<
        Vec<(
            usize,
            shielded::HistoricalUnspentCheckpoint,
            shielded::CheckpointExtensionRequest,
        )>,
    > {
        let mut prepared = Vec::new();
        for (note_index, owned) in notes.iter().enumerate() {
            let request_checkpoint = owned.checkpoint_accumulator.as_ref().map_or_else(
                || {
                    shielded::HistoricalUnspentCheckpoint::genesis(
                        owned.note.commitment,
                        owned.note.birth_epoch,
                    )
                },
                |_| owned.checkpoint.clone(),
            );
            let from_epoch = request_checkpoint.covered_through_epoch.saturating_add(1);
            if through_epoch < from_epoch {
                continue;
            }
            let mut queries = Vec::new();
            for epoch in from_epoch..=through_epoch {
                let nullifier =
                    owned
                        .note
                        .derive_evolving_nullifier(&owned.note_key, &chain_id, epoch)?;
                queries.push(shielded::EvolvingNullifierQuery { epoch, nullifier });
            }
            prepared.push((
                note_index,
                request_checkpoint.clone(),
                shielded::CheckpointExtensionRequest::with_random_blinding(
                    request_checkpoint,
                    queries,
                ),
            ));
        }
        Ok(prepared)
    }

    async fn refresh_owned_shielded_checkpoints_with_snapshot(
        &self,
        notes: &mut [OwnedShieldedNote],
        snapshot: &ShieldedRuntimeSnapshot,
        rotation_round: u64,
    ) -> Result<()> {
        let wallet_store = self.wallet_store()?;
        let current_epoch = snapshot.current_nullifier_epoch;
        let Some(through_epoch) = current_epoch.checked_sub(1) else {
            return Ok(());
        };
        let chain_id = snapshot.chain_id;

        let prepared_requests =
            self.prepare_owned_checkpoint_requests(notes, through_epoch, chain_id)?;
        let requests = prepared_requests
            .iter()
            .map(|(_, _, request)| request.clone())
            .collect::<Vec<_>>();

        if requests.is_empty() {
            return Ok(());
        }

        let extensions = self
            .require_node_client()?
            .request_historical_extensions(&requests, rotation_round)?;
        let ledger = &snapshot.root_ledger;

        for (request_index, (note_index, request_checkpoint, _)) in
            prepared_requests.into_iter().enumerate()
        {
            if !extensions[request_index].strata.is_empty() {
                let accumulator = proof::prove_checkpoint_accumulator(
                    &request_checkpoint,
                    &extensions[request_index],
                    notes[note_index].checkpoint_accumulator.as_ref(),
                )?;
                notes[note_index].checkpoint =
                    request_checkpoint.apply_accumulator(&accumulator.journal, &ledger)?;
                notes[note_index].checkpoint_accumulator = Some(accumulator);
            }
            self.store_owned_note_record(wallet_store.as_ref(), &notes[note_index])?;
            self.store_checkpoint_record(wallet_store.as_ref(), &notes[note_index].checkpoint)?;
        }
        Ok(())
    }

    fn next_shielded_sync_round(&self, store: &WalletStore) -> Result<u64> {
        let round = store
            .get::<u64>("meta", SHIELDED_SYNC_ROUND_KEY)?
            .unwrap_or(0);
        store.put("meta", SHIELDED_SYNC_ROUND_KEY, &round.saturating_add(1))?;
        Ok(round)
    }

    pub fn fixed_cadence_refresh_offset_secs(&self, interval_secs: u64) -> u64 {
        if interval_secs <= 1 {
            return 0;
        }
        let mut hasher = blake3::Hasher::new_derive_key(SHIELDED_REFRESH_OFFSET_DOMAIN);
        hasher.update(&self.address);
        let digest = hasher.finalize();
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&digest.as_bytes()[..8]);
        u64::from_le_bytes(bytes) % interval_secs
    }

    fn build_cover_checkpoint_requests(
        &self,
        current_epoch: u64,
        rotation_round: u64,
        span_templates: &[usize],
        count: usize,
    ) -> Vec<shielded::CheckpointExtensionRequest> {
        let Some(through_epoch) = current_epoch.checked_sub(1) else {
            return Vec::new();
        };
        let count = count.max(1);
        let earliest_epoch = through_epoch.saturating_sub(
            crate::protocol::CURRENT
                .archive_retention_horizon_epochs
                .saturating_sub(1),
        );
        let epoch_span = through_epoch
            .saturating_sub(earliest_epoch)
            .saturating_add(1)
            .max(1);
        let max_cover_len = epoch_span
            .min(crate::protocol::CURRENT.max_historical_nullifier_batch as u64)
            .max(1);
        let mut requests = Vec::with_capacity(count);
        for index in 0..count {
            let desired_cover_len = if span_templates.is_empty() {
                let mut span_hasher =
                    blake3::Hasher::new_derive_key(SHIELDED_REFRESH_OFFSET_DOMAIN);
                span_hasher.update(b"cover-span");
                span_hasher.update(&self.address);
                span_hasher.update(&rotation_round.to_le_bytes());
                span_hasher.update(&(index as u64).to_le_bytes());
                let mut span_bytes = [0u8; 8];
                span_bytes.copy_from_slice(&span_hasher.finalize().as_bytes()[..8]);
                1usize + (u64::from_le_bytes(span_bytes) % max_cover_len) as usize
            } else {
                span_templates[index % span_templates.len()].max(1)
            };
            let cover_len = desired_cover_len.min(max_cover_len as usize).max(1);
            let start_slots = epoch_span
                .saturating_sub(cover_len as u64)
                .saturating_add(1);
            let mut epoch_hasher = blake3::Hasher::new_derive_key(SHIELDED_REFRESH_OFFSET_DOMAIN);
            epoch_hasher.update(b"cover-start");
            epoch_hasher.update(&self.address);
            epoch_hasher.update(&rotation_round.to_le_bytes());
            epoch_hasher.update(&(index as u64).to_le_bytes());
            let mut epoch_bytes = [0u8; 8];
            epoch_bytes.copy_from_slice(&epoch_hasher.finalize().as_bytes()[..8]);
            let cover_epoch = earliest_epoch + (u64::from_le_bytes(epoch_bytes) % start_slots);

            let mut commitment_hasher =
                blake3::Hasher::new_derive_key(SHIELDED_COVER_COMMIT_DOMAIN);
            commitment_hasher.update(&self.address);
            commitment_hasher.update(&rotation_round.to_le_bytes());
            commitment_hasher.update(&(index as u64).to_le_bytes());
            commitment_hasher.update(&cover_epoch.to_le_bytes());
            commitment_hasher.update(&(cover_len as u64).to_le_bytes());
            let cover_commitment = *commitment_hasher.finalize().as_bytes();

            let queries = (0..cover_len)
                .map(|offset| {
                    let epoch = cover_epoch.saturating_add(offset as u64);
                    let mut nullifier_hasher =
                        blake3::Hasher::new_derive_key(SHIELDED_COVER_NULLIFIER_DOMAIN);
                    nullifier_hasher.update(&self.address);
                    nullifier_hasher.update(&rotation_round.to_le_bytes());
                    nullifier_hasher.update(&(index as u64).to_le_bytes());
                    nullifier_hasher.update(&epoch.to_le_bytes());
                    nullifier_hasher.update(&(offset as u64).to_le_bytes());
                    shielded::EvolvingNullifierQuery {
                        epoch,
                        nullifier: *nullifier_hasher.finalize().as_bytes(),
                    }
                })
                .collect::<Vec<_>>();
            let mut presentation_hasher =
                blake3::Hasher::new_derive_key(SHIELDED_COVER_COMMIT_DOMAIN);
            presentation_hasher.update(b"presentation");
            presentation_hasher.update(&self.address);
            presentation_hasher.update(&rotation_round.to_le_bytes());
            presentation_hasher.update(&(index as u64).to_le_bytes());
            presentation_hasher.update(&cover_epoch.to_le_bytes());
            presentation_hasher.update(&(cover_len as u64).to_le_bytes());
            requests.push(shielded::CheckpointExtensionRequest::new(
                shielded::HistoricalUnspentCheckpoint::genesis(cover_commitment, cover_epoch),
                queries,
                *presentation_hasher.finalize().as_bytes(),
            ));
        }
        requests
    }

    pub async fn run_oblivious_refresh_cycle(&self) -> Result<()> {
        let wallet_store = self.wallet_store()?;
        let node_state = self.current_node_state()?;
        let snapshot = node_state.state.shielded_runtime;
        let mut notes = self.load_owned_shielded_notes_for_snapshot(&snapshot, true)?;
        let current_epoch = snapshot.current_nullifier_epoch;
        let rotation_round = self.next_shielded_sync_round(wallet_store.as_ref())?;
        let cover_span_templates = current_epoch
            .checked_sub(1)
            .map(|through_epoch| {
                self.prepare_owned_checkpoint_requests(&notes, through_epoch, snapshot.chain_id)
                    .map(|prepared| {
                        prepared
                            .into_iter()
                            .map(|(_, _, request)| request.queries.len())
                            .collect::<Vec<_>>()
                    })
            })
            .transpose()?
            .unwrap_or_default();
        if !notes.is_empty() {
            self.refresh_owned_shielded_checkpoints_with_snapshot(
                &mut notes,
                &snapshot,
                rotation_round,
            )
            .await?;
        }
        let cover_requests = self.build_cover_checkpoint_requests(
            current_epoch,
            rotation_round,
            &cover_span_templates,
            crate::protocol::CURRENT.oblivious_sync_cover_queries as usize,
        );
        if !cover_requests.is_empty() {
            let _ = self
                .require_node_client()?
                .request_historical_extensions(&cover_requests, rotation_round)?;
        }
        Ok(())
    }

    fn derive_send_seed(
        &self,
        recipient_address: &Address,
        primary_amount: u64,
        fee_amount: u64,
        current_epoch: u64,
        selected_notes: &[OwnedShieldedNote],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(SHIELDED_SEND_SEED_DOMAIN);
        hasher.update(&self.lock_seed);
        hasher.update(&self.address);
        hasher.update(recipient_address);
        hasher.update(&primary_amount.to_le_bytes());
        hasher.update(&fee_amount.to_le_bytes());
        hasher.update(&current_epoch.to_le_bytes());
        hasher.update(&(selected_notes.len() as u64).to_le_bytes());
        for note in selected_notes {
            hasher.update(&note.note.commitment);
            hasher.update(&note.note_key);
            hasher.update(&note.note.value.to_le_bytes());
            hasher.update(&note.note.birth_epoch.to_le_bytes());
        }
        *hasher.finalize().as_bytes()
    }

    fn derive_output_entropy(
        &self,
        send_seed: &[u8; 32],
        output_index: u32,
    ) -> ShieldedOutputEntropy {
        let mut hasher = blake3::Hasher::new_derive_key(SHIELDED_OUTPUT_ENTROPY_DOMAIN);
        hasher.update(send_seed);
        hasher.update(&output_index.to_le_bytes());
        let mut xof = hasher.finalize_xof();
        let mut note_key = [0u8; 32];
        let mut rho = [0u8; 32];
        let mut note_randomizer = [0u8; 32];
        let mut encapsulation_seed = [0u8; proof_core::SHIELDED_OUTPUT_ENCAPSULATION_SEED_LEN];
        let mut nonce = [0u8; 24];
        xof.fill(&mut note_key);
        xof.fill(&mut rho);
        xof.fill(&mut note_randomizer);
        xof.fill(&mut encapsulation_seed);
        xof.fill(&mut nonce);
        ShieldedOutputEntropy {
            note_key,
            rho,
            note_randomizer,
            encapsulation_seed,
            nonce,
        }
    }

    fn build_shielded_output(
        &self,
        owner_signing_pk: TaggedSigningPublicKey,
        owner_kem_pk: TaggedKemPublicKey,
        value: u64,
        birth_epoch: u64,
        entropy: &ShieldedOutputEntropy,
    ) -> Result<(
        ShieldedOutput,
        ShieldedOutputPlaintext,
        [u8; proof_core::SHIELDED_OUTPUT_ENCAPSULATION_SEED_LEN],
    )> {
        self.build_shielded_output_with_kind(
            shielded::ShieldedNoteKind::Payment,
            owner_signing_pk,
            owner_kem_pk,
            value,
            birth_epoch,
            entropy,
        )
    }

    fn build_shielded_output_with_kind(
        &self,
        kind: shielded::ShieldedNoteKind,
        owner_signing_pk: TaggedSigningPublicKey,
        owner_kem_pk: TaggedKemPublicKey,
        value: u64,
        birth_epoch: u64,
        entropy: &ShieldedOutputEntropy,
    ) -> Result<(
        ShieldedOutput,
        ShieldedOutputPlaintext,
        [u8; proof_core::SHIELDED_OUTPUT_ENCAPSULATION_SEED_LEN],
    )> {
        let note = shielded::ShieldedNote::new_with_kind(
            kind,
            value,
            birth_epoch,
            owner_signing_pk,
            owner_kem_pk.clone(),
            entropy.note_key,
            entropy.rho,
            entropy.note_randomizer,
        );
        let checkpoint =
            shielded::HistoricalUnspentCheckpoint::genesis(note.commitment, birth_epoch);
        let payload = ShieldedOutputPlaintext {
            note: note.clone(),
            note_key: entropy.note_key,
            checkpoint,
        };
        let payload_bytes = bincode::serialize(&proof::output_plaintext_to_proof(&payload))
            .map_err(|err| anyhow!("failed to encode shielded output payload: {err}"))?;
        let (kem_ct, shared) =
            owner_kem_pk.encapsulate_deterministic(&entropy.encapsulation_seed)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&shared));
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&entropy.nonce), payload_bytes.as_ref())
            .map_err(|e| anyhow!("failed to encrypt shielded output: {}", e))?;
        Ok((
            ShieldedOutput {
                note_commitment: note.commitment,
                kem_ct,
                nonce: entropy.nonce,
                view_tag: crypto::view_tag(&shared),
                ciphertext,
            },
            payload,
            entropy.encapsulation_seed,
        ))
    }

    fn store_sent_tx_record(
        &self,
        store: &WalletStore,
        tx_id: &[u8; 32],
        commit_epoch: u64,
        amount: u64,
        fee_amount: u64,
        counterparty: Address,
    ) -> Result<()> {
        store.put(
            "wallet_sent_tx",
            tx_id,
            &SentShieldedTxRecord {
                tx_id: *tx_id,
                commit_epoch,
                amount,
                fee_amount,
                counterparty,
            },
        )
    }

    fn sent_tx_records(&self, store: &WalletStore) -> Result<Vec<SentShieldedTxRecord>> {
        let sent_cf = store
            .db
            .cf_handle("wallet_sent_tx")
            .ok_or_else(|| anyhow!("'wallet_sent_tx' column family missing"))?;
        let iter = store.db.iterator_cf(sent_cf, rocksdb::IteratorMode::Start);
        let mut records = Vec::new();
        for item in iter {
            let (_key, value) = item?;
            records.push(bincode::deserialize::<SentShieldedTxRecord>(&value)?);
        }
        Ok(records)
    }

    fn mark_owned_note_spent(
        &self,
        store: &WalletStore,
        note_commitment: &[u8; 32],
        current_nullifier: &[u8; 32],
    ) -> Result<()> {
        store.put_raw_bytes("wallet_spent_note", note_commitment, current_nullifier)
    }

    fn is_owned_note_spent(&self, store: &WalletStore, note_commitment: &[u8; 32]) -> Result<bool> {
        Ok(store
            .get_raw_bytes("wallet_spent_note", note_commitment)?
            .is_some())
    }

    pub fn scan_tx_for_me(&self, tx: &Tx) -> Result<()> {
        let wallet_store = self.wallet_store()?;
        let tx_id = tx.id()?;
        for (output_index, output) in tx.outputs().iter().enumerate() {
            let Some((plaintext, _receive_key_id)) = self.decrypt_shielded_output(output)? else {
                continue;
            };
            if self
                .load_owned_note_record(wallet_store.as_ref(), &output.note_commitment)?
                .is_some()
            {
                continue;
            }
            let owned = OwnedShieldedNote {
                note: plaintext.note.clone(),
                note_key: plaintext.note_key,
                checkpoint: plaintext.checkpoint,
                checkpoint_accumulator: None,
                source: OwnedShieldedNoteSource::Received {
                    tx_id,
                    output_index: output_index as u32,
                },
            };
            self.store_owned_note_record(wallet_store.as_ref(), &owned)?;
            self.store_checkpoint_record(wallet_store.as_ref(), &owned.checkpoint)?;
        }
        Ok(())
    }

    pub fn balance(&self) -> Result<u64> {
        let node_state = self.current_node_state()?;
        let mut notes =
            self.load_owned_shielded_notes_for_snapshot(&node_state.state.shielded_runtime, true)?;
        Self::retain_payment_notes(&mut notes);
        Ok(notes
            .into_iter()
            .fold(0u64, |sum, note| sum.saturating_add(note.note.value)))
    }

    /// Prepares a canonical shielded transaction and witness without proving it.
    pub async fn prepare_fee_payment(&self, fee_amount: u64) -> Result<PreparedShieldedTx> {
        let node_state = self.current_node_state()?;
        let snapshot = node_state.state.shielded_runtime;
        let mut available_notes = self.load_owned_shielded_notes_for_snapshot(&snapshot, true)?;
        Self::retain_payment_notes(&mut available_notes);
        let rotation_round = self.next_shielded_sync_round(self.wallet_store()?.as_ref())?;
        self.refresh_owned_shielded_checkpoints_with_snapshot(
            &mut available_notes,
            &snapshot,
            rotation_round,
        )
        .await?;
        self.build_fee_payment_from_snapshot_with_notes(&snapshot, available_notes, fee_amount)
    }

    /// Prepares a canonical shielded transaction and witness without proving it.
    pub async fn prepare_shielded_send(
        &self,
        recipient_handle: &str,
        amount: u64,
    ) -> Result<PreparedShieldedTx> {
        let node_state = self.current_node_state()?;
        let snapshot = node_state.state.shielded_runtime;
        let (_recipient_addr, recipient_signing_pk, receiver_kem_pk, _receive_key_id) = self
            .parse_recipient_handle_for_chain(recipient_handle, snapshot.chain_id)
            .context("Invalid receiver handle")?;
        let recipient_address = recipient_signing_pk.address();
        let mut available_notes = self.load_owned_shielded_notes_for_snapshot(&snapshot, true)?;
        Self::retain_payment_notes(&mut available_notes);
        let rotation_round = self.next_shielded_sync_round(self.wallet_store()?.as_ref())?;
        self.refresh_owned_shielded_checkpoints_with_snapshot(
            &mut available_notes,
            &snapshot,
            rotation_round,
        )
        .await?;
        let fee_amount = crate::transaction::ordinary_private_transfer_fee_amount();
        let required_total = amount
            .checked_add(fee_amount)
            .ok_or_else(|| anyhow!("ordinary private transfer total exceeds u64"))?;
        let selected_notes = {
            let mut selected = Vec::new();
            let mut total = 0u64;
            for note in available_notes {
                total = total.saturating_add(note.note.value);
                selected.push(note);
                if total >= required_total {
                    break;
                }
            }
            if total < required_total {
                bail!(
                    "Insufficient funds: requested {} plus fee {}, available {}",
                    amount,
                    fee_amount,
                    total
                );
            }
            selected
        };
        let total_selected = selected_notes
            .iter()
            .fold(0u64, |sum, note| sum.saturating_add(note.note.value));

        let state_binding = Self::state_binding_from_snapshot(&snapshot)?;
        let current_epoch = snapshot.current_nullifier_epoch;
        let note_tree = &snapshot.note_tree;
        let tree_root = note_tree.root();
        let chain_id = snapshot.chain_id;
        let send_seed = self.derive_send_seed(
            &recipient_address,
            amount,
            fee_amount,
            current_epoch,
            &selected_notes,
        );

        let mut input_witnesses = Vec::with_capacity(selected_notes.len());
        let mut nullifiers = Vec::with_capacity(selected_notes.len());
        for owned in &selected_notes {
            let membership_proof = note_tree
                .prove_membership(&owned.note.commitment)
                .ok_or_else(|| anyhow!("missing membership proof for owned shielded note"))?;
            if membership_proof.root != tree_root {
                bail!("shielded note tree changed while building the spend");
            }
            let current_nullifier =
                owned
                    .note
                    .derive_evolving_nullifier(&owned.note_key, &chain_id, current_epoch)?;
            nullifiers.push(current_nullifier);
            input_witnesses.push(proof::input_witness_from_local(
                &owned.note,
                &owned.note_key,
                &membership_proof,
                &owned.checkpoint,
                owned.checkpoint_accumulator.as_ref(),
                &current_nullifier,
            ));
        }

        let mut outputs = Vec::new();
        let mut output_witnesses = Vec::new();
        let recipient_entropy = self.derive_output_entropy(&send_seed, 0);
        let (recipient_output, recipient_plaintext, recipient_encapsulation_seed) = self
            .build_shielded_output(
                recipient_signing_pk,
                receiver_kem_pk,
                amount,
                current_epoch,
                &recipient_entropy,
            )?;
        output_witnesses.push(proof::output_witness_from_local(
            &recipient_plaintext,
            &recipient_output,
            &recipient_encapsulation_seed,
        ));
        outputs.push(recipient_output);

        let change = total_selected.saturating_sub(required_total);
        if change > 0 {
            let change_entropy = self.derive_output_entropy(&send_seed, 1);
            let change_receive_kem_pk =
                self.mint_internal_receive_kem_public_key_for_chain(snapshot.chain_id)?;
            let (change_output, change_plaintext, change_encapsulation_seed) = self
                .build_shielded_output(
                    self.signing_pk.clone(),
                    change_receive_kem_pk,
                    change,
                    current_epoch,
                    &change_entropy,
                )?;
            output_witnesses.push(proof::output_witness_from_local(
                &change_plaintext,
                &change_output,
                &change_encapsulation_seed,
            ));
            outputs.push(change_output);
        }

        let witness = proof_core::ProofShieldedTxWitness {
            chain_id,
            current_epoch,
            note_tree_root: tree_root,
            fee_amount,
            inputs: input_witnesses,
            outputs: output_witnesses,
        };
        Ok(PreparedShieldedTx {
            state_binding,
            witness,
            nullifiers,
            outputs,
            selected_notes,
            recipient_address,
            current_epoch,
            amount,
        })
    }

    pub async fn prepare_private_delegation(
        &self,
        validator_id: ValidatorId,
        amount: u64,
    ) -> Result<PreparedPrivateDelegation> {
        let node_state = self.current_node_state()?;
        let pool = Self::validator_pool_from_state(&node_state, validator_id)?;
        let delegation_preview = pool.preview_delegation(amount)?;
        let snapshot = node_state.state.shielded_runtime;
        let mut available_notes = self.load_owned_shielded_notes_for_snapshot(&snapshot, true)?;
        Self::retain_payment_notes(&mut available_notes);
        let rotation_round = self.next_shielded_sync_round(self.wallet_store()?.as_ref())?;
        self.refresh_owned_shielded_checkpoints_with_snapshot(
            &mut available_notes,
            &snapshot,
            rotation_round,
        )
        .await?;
        let fee_amount = PROTOCOL.private_delegation_fee;
        let required_total = amount
            .checked_add(fee_amount)
            .ok_or_else(|| anyhow!("private delegation total exceeds u64"))?;

        let selected_notes = {
            let mut selected = Vec::new();
            let mut total = 0u64;
            for note in available_notes {
                total = total.saturating_add(note.note.value);
                selected.push(note);
                if total >= required_total {
                    break;
                }
            }
            if total < required_total {
                bail!(
                    "Insufficient funds for delegation: requested {} plus fee {}, available {}",
                    amount,
                    fee_amount,
                    total
                );
            }
            selected
        };
        let total_selected = selected_notes
            .iter()
            .fold(0u64, |sum, note| sum.saturating_add(note.note.value));

        let state_binding = Self::state_binding_from_snapshot(&snapshot)?;
        let current_epoch = snapshot.current_nullifier_epoch;
        let note_tree = &snapshot.note_tree;
        let tree_root = note_tree.root();
        let chain_id = snapshot.chain_id;
        let send_seed = self.derive_send_seed(
            &self.address(),
            amount,
            fee_amount,
            current_epoch,
            &selected_notes,
        );

        let mut input_witnesses = Vec::with_capacity(selected_notes.len());
        let mut nullifiers = Vec::with_capacity(selected_notes.len());
        for owned in &selected_notes {
            let membership_proof = note_tree
                .prove_membership(&owned.note.commitment)
                .ok_or_else(|| anyhow!("missing membership proof for owned shielded note"))?;
            if membership_proof.root != tree_root {
                bail!("shielded note tree changed while building the delegation");
            }
            let current_nullifier =
                owned
                    .note
                    .derive_evolving_nullifier(&owned.note_key, &chain_id, current_epoch)?;
            nullifiers.push(current_nullifier);
            input_witnesses.push(proof::input_witness_from_local(
                &owned.note,
                &owned.note_key,
                &membership_proof,
                &owned.checkpoint,
                owned.checkpoint_accumulator.as_ref(),
                &current_nullifier,
            ));
        }

        let mut outputs = Vec::new();
        let mut output_witnesses = Vec::new();
        let delegated_entropy = self.derive_output_entropy(&send_seed, 0);
        let delegated_receive_kem_pk =
            self.mint_internal_receive_kem_public_key_for_chain(snapshot.chain_id)?;
        let (delegated_output, delegated_plaintext, delegated_seed) = self
            .build_shielded_output_with_kind(
                shielded::ShieldedNoteKind::DelegationShare {
                    validator_id: validator_id.0,
                },
                self.signing_pk.clone(),
                delegated_receive_kem_pk,
                delegation_preview.minted_shares,
                current_epoch,
                &delegated_entropy,
            )?;
        output_witnesses.push(proof::output_witness_from_local(
            &delegated_plaintext,
            &delegated_output,
            &delegated_seed,
        ));
        outputs.push(delegated_output);

        let change = total_selected.saturating_sub(required_total);
        if change > 0 {
            let change_entropy = self.derive_output_entropy(&send_seed, 1);
            let change_receive_kem_pk =
                self.mint_internal_receive_kem_public_key_for_chain(snapshot.chain_id)?;
            let (change_output, change_plaintext, change_seed) = self.build_shielded_output(
                self.signing_pk.clone(),
                change_receive_kem_pk,
                change,
                current_epoch,
                &change_entropy,
            )?;
            output_witnesses.push(proof::output_witness_from_local(
                &change_plaintext,
                &change_output,
                &change_seed,
            ));
            outputs.push(change_output);
        }

        let witness = proof_core::ProofPrivateDelegationWitness {
            shielded: proof_core::ProofShieldedTxWitness {
                chain_id,
                current_epoch,
                note_tree_root: tree_root,
                fee_amount,
                inputs: input_witnesses,
                outputs: output_witnesses,
            },
            validator_id: validator_id.0,
            delegated_output_index: 0,
            delegated_amount: delegation_preview.delegated_amount,
        };

        Ok(PreparedPrivateDelegation {
            state_binding,
            witness,
            nullifiers,
            outputs,
            selected_notes,
            validator_id,
        })
    }

    pub async fn prepare_private_undelegation(
        &self,
        validator_id: ValidatorId,
        share_amount: u64,
    ) -> Result<PreparedPrivateUndelegation> {
        let node_state = self.current_node_state()?;
        let pool = Self::validator_pool_from_state(&node_state, validator_id)?;
        let snapshot = node_state.state.shielded_runtime;
        let undelegation_preview = pool.preview_undelegation(
            share_amount,
            snapshot.current_nullifier_epoch,
            PROTOCOL.stake_unbonding_epochs,
        )?;
        let mut available_notes = self.load_owned_shielded_notes_for_snapshot(&snapshot, true)?;
        Self::retain_delegation_share_notes(&mut available_notes, validator_id);
        let rotation_round = self.next_shielded_sync_round(self.wallet_store()?.as_ref())?;
        self.refresh_owned_shielded_checkpoints_with_snapshot(
            &mut available_notes,
            &snapshot,
            rotation_round,
        )
        .await?;
        let fee_amount = PROTOCOL.private_undelegation_fee;
        if undelegation_preview.claim_amount <= fee_amount {
            bail!(
                "undelegation claim value {} is not sufficient to cover fee {}",
                undelegation_preview.claim_amount,
                fee_amount
            );
        }

        let selected_notes = {
            let mut selected = Vec::new();
            let mut total = 0u64;
            for note in available_notes {
                total = total.saturating_add(note.note.value);
                selected.push(note);
                if total >= share_amount {
                    break;
                }
            }
            if total < share_amount {
                bail!(
                    "Insufficient delegation shares for undelegation: requested {}, available {}",
                    share_amount,
                    total
                );
            }
            selected
        };
        let total_selected_shares = selected_notes
            .iter()
            .fold(0u64, |sum, note| sum.saturating_add(note.note.value));

        let state_binding = Self::state_binding_from_snapshot(&snapshot)?;
        let current_epoch = snapshot.current_nullifier_epoch;
        let note_tree = &snapshot.note_tree;
        let tree_root = note_tree.root();
        let chain_id = snapshot.chain_id;
        let send_seed = self.derive_send_seed(
            &self.address(),
            share_amount,
            fee_amount,
            current_epoch,
            &selected_notes,
        );

        let mut input_witnesses = Vec::with_capacity(selected_notes.len());
        let mut nullifiers = Vec::with_capacity(selected_notes.len());
        for owned in &selected_notes {
            let membership_proof = note_tree
                .prove_membership(&owned.note.commitment)
                .ok_or_else(|| anyhow!("missing membership proof for owned shielded note"))?;
            if membership_proof.root != tree_root {
                bail!("shielded note tree changed while building the undelegation");
            }
            let current_nullifier =
                owned
                    .note
                    .derive_evolving_nullifier(&owned.note_key, &chain_id, current_epoch)?;
            nullifiers.push(current_nullifier);
            input_witnesses.push(proof::input_witness_from_local(
                &owned.note,
                &owned.note_key,
                &membership_proof,
                &owned.checkpoint,
                owned.checkpoint_accumulator.as_ref(),
                &current_nullifier,
            ));
        }

        let mut outputs = Vec::new();
        let mut output_witnesses = Vec::new();
        let claim_entropy = self.derive_output_entropy(&send_seed, 0);
        let claim_receive_kem_pk =
            self.mint_internal_receive_kem_public_key_for_chain(snapshot.chain_id)?;
        let (claim_output, claim_plaintext, claim_seed) = self.build_shielded_output_with_kind(
            shielded::ShieldedNoteKind::UnbondingClaim {
                validator_id: validator_id.0,
                release_epoch: undelegation_preview.release_epoch,
            },
            self.signing_pk.clone(),
            claim_receive_kem_pk,
            undelegation_preview
                .claim_amount
                .checked_sub(fee_amount)
                .ok_or_else(|| anyhow!("undelegation claim fee exceeds the redeemed amount"))?,
            current_epoch,
            &claim_entropy,
        )?;
        output_witnesses.push(proof::output_witness_from_local(
            &claim_plaintext,
            &claim_output,
            &claim_seed,
        ));
        outputs.push(claim_output);

        let change_shares = total_selected_shares.saturating_sub(share_amount);
        if change_shares > 0 {
            let change_entropy = self.derive_output_entropy(&send_seed, 1);
            let change_receive_kem_pk =
                self.mint_internal_receive_kem_public_key_for_chain(snapshot.chain_id)?;
            let (change_output, change_plaintext, change_seed) = self
                .build_shielded_output_with_kind(
                    shielded::ShieldedNoteKind::DelegationShare {
                        validator_id: validator_id.0,
                    },
                    self.signing_pk.clone(),
                    change_receive_kem_pk,
                    change_shares,
                    current_epoch,
                    &change_entropy,
                )?;
            output_witnesses.push(proof::output_witness_from_local(
                &change_plaintext,
                &change_output,
                &change_seed,
            ));
            outputs.push(change_output);
        }

        let witness = proof_core::ProofPrivateUndelegationWitness {
            shielded: proof_core::ProofShieldedTxWitness {
                chain_id,
                current_epoch,
                note_tree_root: tree_root,
                fee_amount,
                inputs: input_witnesses,
                outputs: output_witnesses,
            },
            validator_id: validator_id.0,
            claim_output_index: 0,
            gross_claim_amount: undelegation_preview.claim_amount,
        };

        Ok(PreparedPrivateUndelegation {
            state_binding,
            witness,
            nullifiers,
            outputs,
            selected_notes,
            validator_id,
        })
    }

    pub async fn prepare_unbonding_claims(&self) -> Result<PreparedUnbondingClaim> {
        let node_state = self.current_node_state()?;
        let snapshot = node_state.state.shielded_runtime;
        let mut available_notes = self.load_owned_shielded_notes_for_snapshot(&snapshot, true)?;
        Self::retain_mature_unbonding_claim_notes(
            &mut available_notes,
            snapshot.current_nullifier_epoch,
        );
        let rotation_round = self.next_shielded_sync_round(self.wallet_store()?.as_ref())?;
        self.refresh_owned_shielded_checkpoints_with_snapshot(
            &mut available_notes,
            &snapshot,
            rotation_round,
        )
        .await?;
        if available_notes.is_empty() {
            bail!("no mature unbonding claims are available");
        }

        let total_claim_amount = available_notes
            .iter()
            .fold(0u64, |sum, note| sum.saturating_add(note.note.value));
        let fee_amount = PROTOCOL.unbonding_claim_fee;
        if total_claim_amount <= fee_amount {
            bail!(
                "mature unbonding claim value {} is not sufficient to cover fee {}",
                total_claim_amount,
                fee_amount
            );
        }
        let state_binding = Self::state_binding_from_snapshot(&snapshot)?;
        let current_epoch = snapshot.current_nullifier_epoch;
        let note_tree = &snapshot.note_tree;
        let tree_root = note_tree.root();
        let chain_id = snapshot.chain_id;
        let send_seed = self.derive_send_seed(
            &self.address(),
            total_claim_amount,
            fee_amount,
            current_epoch,
            &available_notes,
        );

        let mut input_witnesses = Vec::with_capacity(available_notes.len());
        let mut nullifiers = Vec::with_capacity(available_notes.len());
        for owned in &available_notes {
            let membership_proof = note_tree
                .prove_membership(&owned.note.commitment)
                .ok_or_else(|| anyhow!("missing membership proof for owned shielded note"))?;
            if membership_proof.root != tree_root {
                bail!("shielded note tree changed while building the unbonding claim");
            }
            let current_nullifier =
                owned
                    .note
                    .derive_evolving_nullifier(&owned.note_key, &chain_id, current_epoch)?;
            nullifiers.push(current_nullifier);
            input_witnesses.push(proof::input_witness_from_local(
                &owned.note,
                &owned.note_key,
                &membership_proof,
                &owned.checkpoint,
                owned.checkpoint_accumulator.as_ref(),
                &current_nullifier,
            ));
        }

        let payout_entropy = self.derive_output_entropy(&send_seed, 0);
        let payout_receive_kem_pk =
            self.mint_internal_receive_kem_public_key_for_chain(snapshot.chain_id)?;
        let (payout_output, payout_plaintext, payout_seed) = self.build_shielded_output(
            self.signing_pk.clone(),
            payout_receive_kem_pk,
            total_claim_amount
                .checked_sub(fee_amount)
                .ok_or_else(|| anyhow!("unbonding claim fee exceeds the payout amount"))?,
            current_epoch,
            &payout_entropy,
        )?;
        let witness = proof_core::ProofShieldedTxWitness {
            chain_id,
            current_epoch,
            note_tree_root: tree_root,
            fee_amount,
            inputs: input_witnesses,
            outputs: vec![proof::output_witness_from_local(
                &payout_plaintext,
                &payout_output,
                &payout_seed,
            )],
        };

        Ok(PreparedUnbondingClaim {
            state_binding,
            witness,
            nullifiers,
            outputs: vec![payout_output],
            selected_notes: available_notes,
        })
    }

    pub async fn submit_prepared_shielded_send(
        &self,
        prepared: PreparedShieldedTx,
        proof_bytes: Vec<u8>,
    ) -> Result<SendOutcome> {
        let wallet_store = self.wallet_store()?;
        let current_state = self.current_node_state()?;
        let current_binding =
            Self::state_binding_from_snapshot(&current_state.state.shielded_runtime)?;
        if current_binding != prepared.state_binding {
            bail!(
                "prepared shielded transaction is stale; canonical shielded state changed, re-prepare the send"
            );
        }
        let tx = Tx::new(
            prepared.nullifiers.clone(),
            prepared.outputs,
            prepared.witness.fee_amount,
            proof_bytes,
        );
        let tx_id = self.require_node_client()?.submit_tx(&tx)?;
        for (owned, nullifier) in prepared
            .selected_notes
            .iter()
            .zip(prepared.nullifiers.iter())
        {
            self.mark_owned_note_spent(wallet_store.as_ref(), &owned.note.commitment, nullifier)?;
        }
        self.store_sent_tx_record(
            wallet_store.as_ref(),
            &tx_id,
            prepared.current_epoch,
            prepared.amount,
            prepared.witness.fee_amount,
            prepared.recipient_address,
        )?;
        self.scan_tx_for_me(&tx)?;
        crate::metrics::V3_SENDS.inc();

        Ok(SendOutcome {
            tx_id,
            fee_amount: prepared.witness.fee_amount,
            input_count: tx.input_count(),
            output_count: tx.output_count(),
        })
    }

    pub async fn submit_prepared_private_delegation(
        &self,
        prepared: PreparedPrivateDelegation,
        proof_bytes: Vec<u8>,
    ) -> Result<[u8; 32]> {
        let wallet_store = self.wallet_store()?;
        let current_state = self.current_node_state()?;
        let current_binding =
            Self::state_binding_from_snapshot(&current_state.state.shielded_runtime)?;
        if current_binding != prepared.state_binding {
            bail!(
                "prepared private delegation is stale; canonical shielded state changed, re-prepare the delegation"
            );
        }
        let tx = prepared.tx_with_proof(proof_bytes);
        let tx_id = self.require_node_client()?.submit_tx(&tx)?;
        for (owned, nullifier) in prepared
            .selected_notes
            .iter()
            .zip(prepared.nullifiers.iter())
        {
            self.mark_owned_note_spent(wallet_store.as_ref(), &owned.note.commitment, nullifier)?;
        }
        self.scan_tx_for_me(&tx)?;
        Ok(tx_id)
    }

    pub async fn submit_prepared_private_undelegation(
        &self,
        prepared: PreparedPrivateUndelegation,
        proof_bytes: Vec<u8>,
    ) -> Result<[u8; 32]> {
        let wallet_store = self.wallet_store()?;
        let current_state = self.current_node_state()?;
        let current_binding =
            Self::state_binding_from_snapshot(&current_state.state.shielded_runtime)?;
        if current_binding != prepared.state_binding {
            bail!(
                "prepared private undelegation is stale; canonical shielded state changed, re-prepare the undelegation"
            );
        }
        let tx = prepared.tx_with_proof(proof_bytes);
        let tx_id = self.require_node_client()?.submit_tx(&tx)?;
        for (owned, nullifier) in prepared
            .selected_notes
            .iter()
            .zip(prepared.nullifiers.iter())
        {
            self.mark_owned_note_spent(wallet_store.as_ref(), &owned.note.commitment, nullifier)?;
        }
        self.scan_tx_for_me(&tx)?;
        Ok(tx_id)
    }

    pub async fn submit_prepared_unbonding_claim(
        &self,
        prepared: PreparedUnbondingClaim,
        proof_bytes: Vec<u8>,
    ) -> Result<[u8; 32]> {
        let wallet_store = self.wallet_store()?;
        let current_state = self.current_node_state()?;
        let current_binding =
            Self::state_binding_from_snapshot(&current_state.state.shielded_runtime)?;
        if current_binding != prepared.state_binding {
            bail!(
                "prepared unbonding claim is stale; canonical shielded state changed, re-prepare the claim"
            );
        }
        let tx = prepared.tx_with_proof(proof_bytes);
        let tx_id = self.require_node_client()?.submit_tx(&tx)?;
        for (owned, nullifier) in prepared
            .selected_notes
            .iter()
            .zip(prepared.nullifiers.iter())
        {
            self.mark_owned_note_spent(wallet_store.as_ref(), &owned.note.commitment, nullifier)?;
        }
        self.scan_tx_for_me(&tx)?;
        Ok(tx_id)
    }

    /// Sends a canonical shielded transaction to a verified recipient handle.
    pub async fn send_to_recipient_handle(
        &self,
        recipient_handle: &str,
        amount: u64,
    ) -> Result<SendOutcome> {
        let prepared = self.prepare_shielded_send(recipient_handle, amount).await?;
        let (receipt, _journal) = proof::prove_shielded_tx(prepared.witness())?;
        self.submit_prepared_shielded_send(prepared, proof::receipt_to_bytes(&receipt)?)
            .await
    }

    /// Simple wrapper: pay using a recipient handle.
    pub async fn pay(&self, to: &str, amount: u64) -> Result<SendOutcome> {
        self.send_to_recipient_handle(to, amount).await
    }

    pub async fn delegate_to_validator(
        &self,
        validator_id: ValidatorId,
        amount: u64,
    ) -> Result<[u8; 32]> {
        let prepared = self
            .prepare_private_delegation(validator_id, amount)
            .await?;
        let (receipt, _journal) = proof::prove_private_delegation(prepared.witness())?;
        self.submit_prepared_private_delegation(prepared, proof::receipt_to_bytes(&receipt)?)
            .await
    }

    pub async fn undelegate_from_validator(
        &self,
        validator_id: ValidatorId,
        share_amount: u64,
    ) -> Result<[u8; 32]> {
        let prepared = self
            .prepare_private_undelegation(validator_id, share_amount)
            .await?;
        let (receipt, _journal) = proof::prove_private_undelegation(prepared.witness())?;
        self.submit_prepared_private_undelegation(prepared, proof::receipt_to_bytes(&receipt)?)
            .await
    }

    pub async fn claim_mature_unbondings(&self) -> Result<[u8; 32]> {
        let prepared = self.prepare_unbonding_claims().await?;
        let (receipt, _journal) = proof::prove_unbonding_claim(prepared.witness())?;
        self.submit_prepared_unbonding_claim(prepared, proof::receipt_to_bytes(&receipt)?)
            .await
    }

    /// Gets the transaction history for this wallet
    pub fn get_transaction_history(&self) -> Result<Vec<TransactionRecord>> {
        let store = self.wallet_store()?;
        let node_state = self.current_node_state()?;
        self.sync_owned_shielded_notes_with_snapshot(&node_state.state.shielded_runtime)?;
        self.transaction_history_from_local(store.as_ref())
    }

    fn transaction_history_from_local(
        &self,
        store: &WalletStore,
    ) -> Result<Vec<TransactionRecord>> {
        let mut history = Vec::new();

        for record in self.sent_tx_records(store)? {
            history.push(TransactionRecord {
                coin_id: record.tx_id,
                transfer_hash: record.tx_id,
                commit_epoch: record.commit_epoch,
                is_sender: true,
                amount: record.amount,
                fee_amount: record.fee_amount,
                counterparty: record.counterparty,
            });
        }

        for owned in self.iterate_owned_note_records(store)? {
            if let OwnedShieldedNoteSource::Received { tx_id, .. } = owned.source {
                history.push(TransactionRecord {
                    coin_id: owned.note.commitment,
                    transfer_hash: tx_id,
                    commit_epoch: owned.note.birth_epoch,
                    is_sender: false,
                    amount: owned.note.value,
                    fee_amount: 0,
                    counterparty: [0u8; 32],
                });
            }
        }

        history.sort_by(|a, b| {
            b.commit_epoch
                .cmp(&a.commit_epoch)
                .then(b.coin_id.cmp(&a.coin_id))
        });
        Ok(history)
    }

    pub(crate) fn observed_state_for_snapshot(
        &self,
        snapshot: &ShieldedRuntimeSnapshot,
    ) -> Result<WalletObservedState> {
        let wallet_store = self.wallet_store()?;
        let notes = self.load_owned_shielded_notes_for_snapshot(snapshot, true)?;
        let history = self.transaction_history_from_local(wallet_store.as_ref())?;
        Ok(WalletObservedState {
            address: self.address,
            chain_id: snapshot.chain_id,
            current_nullifier_epoch: snapshot.current_nullifier_epoch,
            balance: notes
                .iter()
                .fold(0u64, |sum, note| sum.saturating_add(note.note.value)),
            spendable_outputs: notes.len(),
            history,
        })
    }
}

/// Represents a transaction record for wallet history
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionRecord {
    pub coin_id: [u8; 32],
    pub transfer_hash: [u8; 32],
    pub commit_epoch: u64,
    pub is_sender: bool,
    pub amount: u64,
    pub fee_amount: u64,
    pub counterparty: crate::crypto::Address,
}

/// Outcome of a canonical shielded send operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SendOutcome {
    pub tx_id: [u8; 32],
    pub fee_amount: u64,
    pub input_count: usize,
    pub output_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletObservedState {
    pub address: Address,
    pub chain_id: [u8; 32],
    pub current_nullifier_epoch: u64,
    pub balance: u64,
    pub spendable_outputs: usize,
    pub history: Vec<TransactionRecord>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    struct EnvGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(previous) = self.previous.take() {
                std::env::set_var(self.key, previous);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    #[test]
    fn shielded_wallet_state_is_encrypted_at_rest() -> Result<()> {
        let _passphrase = EnvGuard::set("WALLET_PASSPHRASE", "unit-test-wallet-passphrase");
        let tempdir = TempDir::new()?;
        let wallet_store = Arc::new(WalletStore::open(&tempdir.path().to_string_lossy())?);
        let wallet = Wallet::load_or_create_private(wallet_store.clone())?;
        let (_unused_sk, note_kem_pk) = crypto::ml_kem_768_generate();

        let note = shielded::ShieldedNote::new(
            7,
            3,
            wallet.public_key().clone(),
            note_kem_pk,
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
        );
        let owned = OwnedShieldedNote {
            note: note.clone(),
            note_key: [1u8; 32],
            checkpoint: shielded::HistoricalUnspentCheckpoint::genesis(note.commitment, 3),
            checkpoint_accumulator: None,
            source: OwnedShieldedNoteSource::Genesis { coin_id: [9u8; 32] },
        };

        wallet.store_owned_note_record(wallet_store.as_ref(), &owned)?;
        wallet.store_checkpoint_record(wallet_store.as_ref(), &owned.checkpoint)?;

        let notes_cf = wallet_store
            .db
            .cf_handle("shielded_owned_note")
            .ok_or_else(|| anyhow!("'shielded_owned_note' column family missing"))?;
        let raw_note = wallet_store
            .db
            .get_cf(notes_cf, &owned.note.commitment)?
            .ok_or_else(|| anyhow!("missing encrypted owned note"))?;
        assert!(bincode::deserialize::<OwnedShieldedNote>(&raw_note).is_err());

        let checkpoints_cf = wallet_store
            .db
            .cf_handle("shielded_checkpoint")
            .ok_or_else(|| anyhow!("'shielded_checkpoint' column family missing"))?;
        let raw_checkpoint = wallet_store
            .db
            .get_cf(checkpoints_cf, &owned.note.commitment)?
            .ok_or_else(|| anyhow!("missing encrypted checkpoint"))?;
        assert!(canonical::decode_historical_unspent_checkpoint(&raw_checkpoint).is_err());

        assert_eq!(
            wallet
                .load_owned_note_record(wallet_store.as_ref(), &owned.note.commitment)?
                .ok_or_else(|| anyhow!("missing decrypted owned note"))?,
            owned
        );
        assert_eq!(
            wallet
                .iterate_owned_note_records(wallet_store.as_ref())?
                .into_iter()
                .next()
                .ok_or_else(|| anyhow!("missing decrypted owned note iteration"))?,
            owned
        );
        Ok(())
    }

    #[test]
    fn exported_receive_handles_are_single_use_and_signed() -> Result<()> {
        let _passphrase = EnvGuard::set("WALLET_PASSPHRASE", "unit-test-wallet-passphrase");
        let tempdir = TempDir::new()?;
        let wallet_store = Arc::new(WalletStore::open(&tempdir.path().to_string_lossy())?);
        let wallet = Wallet::load_or_create_private(wallet_store.clone())?;
        let chain_id = [7u8; 32];

        let handle_a = wallet.export_address_for_chain(chain_id)?;
        let handle_b = wallet.export_address_for_chain(chain_id)?;
        let doc_a = Wallet::parse_recipient_handle_document(&handle_a)?;
        let doc_b = Wallet::parse_recipient_handle_document(&handle_b)?;

        assert_eq!(doc_a.chain_id, chain_id);
        assert_eq!(doc_a.chain_id, doc_b.chain_id);
        assert_eq!(doc_a.signing_pk, doc_b.signing_pk);
        assert_ne!(doc_a.receive_key_id, doc_b.receive_key_id);
        assert_ne!(doc_a.kem_pk, doc_b.kem_pk);
        assert!(doc_a.expires_unix_ms > doc_a.issued_unix_ms);
        assert!(doc_b.expires_unix_ms > doc_b.issued_unix_ms);
        assert!(wallet
            .load_receive_key_record(wallet_store.as_ref(), &doc_a.receive_key_id)?
            .is_some());
        assert!(wallet
            .load_receive_key_record(wallet_store.as_ref(), &doc_b.receive_key_id)?
            .is_some());
        Ok(())
    }

    #[test]
    fn expired_receive_keys_are_pruned_before_new_handles_are_minted() -> Result<()> {
        let _passphrase = EnvGuard::set("WALLET_PASSPHRASE", "unit-test-wallet-passphrase");
        let tempdir = TempDir::new()?;
        let wallet_store = Arc::new(WalletStore::open(&tempdir.path().to_string_lossy())?);
        let wallet = Wallet::load_or_create_private(wallet_store.clone())?;
        let chain_id = [9u8; 32];

        let original_handle = wallet.export_address_for_chain(chain_id)?;
        let original_doc = Wallet::parse_recipient_handle_document(&original_handle)?;
        let mut expired = wallet
            .load_receive_key_record(wallet_store.as_ref(), &original_doc.receive_key_id)?
            .ok_or_else(|| anyhow!("missing receive key record"))?;
        expired.expires_unix_ms = 0;
        wallet.store_receive_key_record(wallet_store.as_ref(), &expired)?;

        let rotated_handle = wallet.export_address_for_chain(chain_id)?;
        let rotated_doc = Wallet::parse_recipient_handle_document(&rotated_handle)?;
        assert_ne!(original_doc.receive_key_id, rotated_doc.receive_key_id);
        assert!(wallet
            .load_receive_key_record(wallet_store.as_ref(), &original_doc.receive_key_id)?
            .is_none());
        assert!(wallet
            .load_receive_key_record(wallet_store.as_ref(), &rotated_doc.receive_key_id)?
            .is_some());
        Ok(())
    }
}
