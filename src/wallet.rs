use crate::{
    canonical,
    crypto::{
        self, Address, MlKem768SecretKey, TaggedKemPublicKey, TaggedSigningPublicKey,
        ML_KEM_768_PK_BYTES, ML_KEM_768_SK_BYTES,
    },
    node_control::{NodeControlClient, NodeControlStateEnvelope, ShieldedRuntimeSnapshot},
    proof, shielded,
    storage::WalletStore,
    transaction::{ShieldedOutput, ShieldedOutputPlaintext, Tx},
};
use aws_lc_rs::unstable::signature::PqdsaKeyPair;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDocV2 {
    pub version: u8,
    pub chain_id: [u8; 32],
    pub signing_pk: TaggedSigningPublicKey,
    pub kem_pk: TaggedKemPublicKey,
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
const WALLET_FORMAT_MAGIC: &[u8; 4] = b"UCW3";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const WALLET_VERSION_STANDARDIZED: u8 = 3;
const KEY_DOC_VERSION: u8 = 2;
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

#[derive(Serialize, Deserialize)]
struct WalletSecretsV3 {
    signing_key_pkcs8: Vec<u8>,
    #[serde(with = "BigArray")]
    kem_sk: [u8; ML_KEM_768_SK_BYTES],
    #[serde(with = "BigArray")]
    kem_pk: [u8; ML_KEM_768_PK_BYTES],
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
    counterparty: Address,
}

pub struct Wallet {
    wallet_db: Arc<WalletStore>,
    node_client: Option<NodeControlClient>,
    signing_pk: TaggedSigningPublicKey,
    signing_key: PqdsaKeyPair,
    kem_pk: TaggedKemPublicKey,
    kem_sk: MlKem768SecretKey,
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
        Tx::new(self.nullifiers.clone(), self.outputs.clone(), proof)
    }
}

impl Wallet {
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
                bail!("Unsupported wallet format; remove the old wallet and create a fresh ML-DSA/ML-KEM wallet");
            }
            let version = encoded[WALLET_FORMAT_MAGIC.len()];
            if version != WALLET_VERSION_STANDARDIZED {
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

            let secrets: WalletSecretsV3 = bincode::deserialize(&decrypted)
                .map_err(|_| anyhow!("Corrupted wallet payload"))?;
            let signing_key = crypto::ml_dsa_65_keypair_from_pkcs8(&secrets.signing_key_pkcs8)?;
            let signing_pk = crypto::ml_dsa_65_public_key(&signing_key);
            let kem_sk = crypto::ml_kem_768_secret_key_from_bytes(&secrets.kem_sk);
            let kem_pk = TaggedKemPublicKey::from_ml_kem_768_array(secrets.kem_pk);
            let mut key_zero = key;
            key_zero.iter_mut().for_each(|b| *b = 0);

            return Ok(Wallet {
                wallet_db,
                node_client: None,
                signing_pk: signing_pk.clone(),
                signing_key,
                kem_pk,
                kem_sk,
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
        let (kem_sk, kem_pk) = crypto::ml_kem_768_generate();
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
        let secrets = WalletSecretsV3 {
            signing_key_pkcs8: crypto::ml_dsa_65_keypair_to_pkcs8(&signing_key)?,
            kem_sk: crypto::ml_kem_768_secret_key_to_bytes(&kem_sk),
            kem_pk: kem_pk.bytes,
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
        encoded.push(WALLET_VERSION_STANDARDIZED);
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
            kem_pk,
            kem_sk,
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
    pub fn kem_public_key(&self) -> &TaggedKemPublicKey {
        &self.kem_pk
    }
    pub fn kem_secret_key(&self) -> &MlKem768SecretKey {
        &self.kem_sk
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
    // Address export/import: authenticated ML-KEM key distribution
    // ---------------------------------------------------------------------
    // Recipient handles are signed KeyDoc JSON documents. Unsigned address blobs are no longer accepted.
    pub fn export_address(&self) -> Result<String> {
        self.export_address_for_chain(self.effective_chain_id()?)
    }

    fn export_address_for_chain(&self, chain_id: [u8; 32]) -> Result<String> {
        let msg = canonical::encode_key_doc_signable(
            KEY_DOC_VERSION,
            &chain_id,
            &self.signing_pk,
            &self.kem_pk,
        )?;
        let sig = crypto::ml_dsa_65_sign(&self.signing_key, &msg)?;
        let doc = KeyDocV2 {
            version: KEY_DOC_VERSION,
            chain_id,
            signing_pk: self.signing_pk.clone(),
            kem_pk: self.kem_pk.clone(),
            sig,
        };
        serde_json::to_string(&doc).context("serialize recipient KeyDoc")
    }

    pub fn export_stealth_address(&self) -> Result<String> {
        self.export_address()
    }

    pub fn parse_address(
        addr_str: &str,
    ) -> Result<(Address, TaggedSigningPublicKey, TaggedKemPublicKey)> {
        let s = addr_str.trim();
        if !(s.starts_with('{') && s.ends_with('}')) {
            bail!("Recipient handle must be a signed KeyDoc JSON document");
        }
        let doc: KeyDocV2 = serde_json::from_str(s).context("Invalid KeyDoc JSON")?;
        if doc.version != KEY_DOC_VERSION {
            bail!("Unsupported KeyDoc version: {}", doc.version);
        }
        let msg = canonical::encode_key_doc_signable(
            doc.version,
            &doc.chain_id,
            &doc.signing_pk,
            &doc.kem_pk,
        )?;
        doc.signing_pk.verify(&msg, &doc.sig)?;
        Ok((
            crate::crypto::address_from_pk(&doc.signing_pk),
            doc.signing_pk,
            doc.kem_pk,
        ))
    }

    pub fn parse_stealth_address(
        addr_str: &str,
    ) -> Result<(Address, TaggedSigningPublicKey, TaggedKemPublicKey)> {
        Self::parse_address(addr_str)
    }

    // Recipient documents are the only supported addressing surface.

    /// Accepts a recipient handle that can be either:
    /// - A KeyDoc JSON string with algorithm-tagged ML-DSA/ML-KEM bindings.
    /// Returns (recipient_addr, recipient_signing_pk, receiver_kem_pk) after full verification.
    fn parse_recipient_handle(
        &self,
        handle: &str,
    ) -> Result<(Address, TaggedSigningPublicKey, TaggedKemPublicKey)> {
        let chain_id = self.effective_chain_id()?;
        self.parse_recipient_handle_for_chain(handle, chain_id)
    }

    fn parse_recipient_handle_for_chain(
        &self,
        handle: &str,
        chain_id: [u8; 32],
    ) -> Result<(Address, TaggedSigningPublicKey, TaggedKemPublicKey)> {
        if let Ok((addr, signing_pk, kem_pk)) = Self::parse_address(handle) {
            let doc: KeyDocV2 =
                serde_json::from_str(handle.trim()).context("Invalid KeyDoc JSON")?;
            if doc.chain_id != chain_id {
                anyhow::bail!("KeyDoc chain_id mismatch");
            }
            return Ok((addr, signing_pk, kem_pk));
        }

        // Friendly hint for future paycode inputs without cached binding
        let s = handle.trim();
        if s.starts_with("ucsp1") {
            anyhow::bail!("Paycode detected but no cached binding. Paste the signed KeyDoc JSON.");
        }

        anyhow::bail!("Invalid recipient handle")
    }

    pub fn validate_recipient_handle(&self, handle: &str) -> Result<()> {
        self.parse_recipient_handle(handle).map(|_| ())
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
    ) -> Result<Option<ShieldedOutputPlaintext>> {
        let shared = crypto::ml_kem_768_decapsulate(&self.kem_sk, &output.kem_ct)?;
        if crypto::view_tag(&shared) != output.view_tag {
            return Ok(None);
        }

        let cipher = XChaCha20Poly1305::new(Key::from_slice(&shared));
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&output.nonce),
                output.ciphertext.as_ref(),
            )
            .map_err(|_| anyhow!("failed to decrypt shielded output payload"))?;
        let decoded = proof::output_plaintext_from_proof(
            &bincode::deserialize::<proof_core::ProofShieldedOutputPlaintext>(&plaintext)
                .map_err(|err| anyhow!("failed to decode shielded output payload: {err}"))?,
        )?;
        if decoded.note.commitment != output.note_commitment {
            bail!("shielded output plaintext commitment mismatch");
        }
        if decoded.note.owner_signing_pk != self.signing_pk
            || decoded.note.owner_kem_pk != self.kem_pk
        {
            return Ok(None);
        }
        if shielded::note_key_commitment(&decoded.note_key) != decoded.note.note_key_commitment {
            bail!("shielded output note key does not match the commitment");
        }
        Ok(Some(decoded))
    }

    fn rescan_shielded_outputs(&self, snapshot: &ShieldedRuntimeSnapshot) -> Result<()> {
        let wallet_store = self.wallet_store()?;
        for (tx_id, output_index, output) in &snapshot.shielded_outputs {
            let Some(plaintext) = self.decrypt_shielded_output(&output)? else {
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
        amount: u64,
        current_epoch: u64,
        selected_notes: &[OwnedShieldedNote],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(SHIELDED_SEND_SEED_DOMAIN);
        hasher.update(&self.lock_seed);
        hasher.update(&self.address);
        hasher.update(recipient_address);
        hasher.update(&amount.to_le_bytes());
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
        let note = shielded::ShieldedNote::new(
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
        counterparty: Address,
    ) -> Result<()> {
        store.put(
            "wallet_sent_tx",
            tx_id,
            &SentShieldedTxRecord {
                tx_id: *tx_id,
                commit_epoch,
                amount,
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
        for (output_index, output) in tx.outputs.iter().enumerate() {
            let Some(plaintext) = self.decrypt_shielded_output(output)? else {
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
        Ok(self
            .load_owned_shielded_notes_for_snapshot(&node_state.state.shielded_runtime, true)?
            .into_iter()
            .fold(0u64, |sum, note| sum.saturating_add(note.note.value)))
    }

    /// Prepares a canonical shielded transaction and witness without proving it.
    pub async fn prepare_shielded_send(
        &self,
        receiver_paycode: &str,
        amount: u64,
    ) -> Result<PreparedShieldedTx> {
        let node_state = self.current_node_state()?;
        let snapshot = node_state.state.shielded_runtime;
        let (_recipient_addr, recipient_signing_pk, receiver_kem_pk) = self
            .parse_recipient_handle_for_chain(receiver_paycode, snapshot.chain_id)
            .context("Invalid receiver handle")?;
        let recipient_address = recipient_signing_pk.address();
        let mut available_notes = self.load_owned_shielded_notes_for_snapshot(&snapshot, true)?;
        let rotation_round = self.next_shielded_sync_round(self.wallet_store()?.as_ref())?;
        self.refresh_owned_shielded_checkpoints_with_snapshot(
            &mut available_notes,
            &snapshot,
            rotation_round,
        )
        .await?;
        let selected_notes = {
            let mut selected = Vec::new();
            let mut total = 0u64;
            for note in available_notes {
                total = total.saturating_add(note.note.value);
                selected.push(note);
                if total >= amount {
                    break;
                }
            }
            if total < amount {
                bail!(
                    "Insufficient funds: requested {}, available {}",
                    amount,
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
        let send_seed =
            self.derive_send_seed(&recipient_address, amount, current_epoch, &selected_notes);

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

        let change = total_selected.saturating_sub(amount);
        if change > 0 {
            let change_entropy = self.derive_output_entropy(&send_seed, 1);
            let (change_output, change_plaintext, change_encapsulation_seed) = self
                .build_shielded_output(
                    self.signing_pk.clone(),
                    self.kem_pk.clone(),
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
        let tx = Tx::new(prepared.nullifiers.clone(), prepared.outputs, proof_bytes);
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
            prepared.recipient_address,
        )?;
        self.scan_tx_for_me(&tx)?;
        crate::metrics::V3_SENDS.inc();

        Ok(SendOutcome {
            tx_id,
            input_count: tx.nullifiers.len(),
            output_count: tx.outputs.len(),
        })
    }

    /// Sends a canonical shielded transaction to a verified recipient document.
    pub async fn send_with_paycode_and_note(
        &self,
        receiver_paycode: &str,
        amount: u64,
    ) -> Result<SendOutcome> {
        let prepared = self.prepare_shielded_send(receiver_paycode, amount).await?;
        let (receipt, _journal) = proof::prove_shielded_tx(prepared.witness())?;
        self.submit_prepared_shielded_send(prepared, proof::receipt_to_bytes(&receipt)?)
            .await
    }

    /// Simple wrapper: pay using a recipient handle (address or KeyDoc JSON) with empty note.
    pub async fn pay(&self, to: &str, amount: u64) -> Result<SendOutcome> {
        self.send_with_paycode_and_note(to, amount).await
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
            receive_handle: self.export_address_for_chain(snapshot.chain_id)?,
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
    pub counterparty: crate::crypto::Address,
}

/// Outcome of a canonical shielded send operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SendOutcome {
    pub tx_id: [u8; 32],
    pub input_count: usize,
    pub output_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletObservedState {
    pub receive_handle: String,
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

        let note = shielded::ShieldedNote::new(
            7,
            3,
            wallet.public_key().clone(),
            wallet.kem_public_key().clone(),
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
}
