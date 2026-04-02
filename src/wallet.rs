use crate::{
    canonical,
    crypto::{
        self, Address, MlKem768SecretKey, TaggedKemPublicKey, TaggedSigningPublicKey,
        ML_KEM_768_PK_BYTES, ML_KEM_768_SK_BYTES,
    },
    proof, shielded,
    storage::Store,
    transaction::{self, ShieldedOutput, ShieldedOutputPlaintext, Tx},
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

const WALLET_KEY: &[u8] = b"default_keypair";
const WALLET_FORMAT_MAGIC: &[u8; 4] = b"UCW3";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const WALLET_VERSION_STANDARDIZED: u8 = 3;
const KEY_DOC_VERSION: u8 = 2;
const SENT_TX_PREFIX: &[u8] = b"shielded_sent_tx/";
// Tunable KDF parameters for wallet encryption
const WALLET_KDF_MEM_KIB: u32 = 256 * 1024; // 256 MiB
const WALLET_KDF_TIME_COST: u32 = 3; // iterations

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
    _db: std::sync::Weak<Store>,
    signing_pk: TaggedSigningPublicKey,
    signing_key: PqdsaKeyPair,
    kem_pk: TaggedKemPublicKey,
    kem_sk: MlKem768SecretKey,
    lock_seed: [u8; 32],
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
                let pw =
                    rpassword::prompt_password(prompt).context("Failed to read pass-phrase")?;
                Ok(pw)
            } else {
                // Non-interactive (prod/CI): require env var, fail fast if missing
                std::env::var("WALLET_PASSPHRASE")
                    .map_err(|_| anyhow!("WALLET_PASSPHRASE is required in non-interactive mode"))
            }
        }

        if let Some(encoded) = db.get::<Vec<u8>>("wallet", WALLET_KEY)? {
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
                _db: Arc::downgrade(&db),
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

        db.put("wallet", WALLET_KEY, &encoded)?;
        println!("✅ New wallet created and saved");
        Ok(Wallet {
            _db: Arc::downgrade(&db),
            signing_pk,
            signing_key,
            kem_pk,
            kem_sk,
            lock_seed,
            address,
        })
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

    // ---------------------------------------------------------------------
    // Address export/import: authenticated ML-KEM key distribution
    // ---------------------------------------------------------------------
    // Recipient handles are signed KeyDoc JSON documents. Unsigned address blobs are no longer accepted.
    pub fn export_address(&self) -> Result<String> {
        let store = self
            ._db
            .upgrade()
            .ok_or_else(|| anyhow!("Database connection dropped"))?;
        let chain_id = store.get_chain_id()?;
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
        if let Ok((addr, signing_pk, kem_pk)) = Self::parse_address(handle) {
            let store = self
                ._db
                .upgrade()
                .ok_or_else(|| anyhow!("Database connection dropped"))?;
            let chain_id = store.get_chain_id()?;
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

    fn materialize_owned_genesis_notes(&self) -> Result<()> {
        let store = self
            ._db
            .upgrade()
            .ok_or_else(|| anyhow!("Database connection dropped"))?;
        transaction::ensure_shielded_runtime_state(store.as_ref())?;
        let chain_id = store.get_chain_id()?;
        for coin in store.iterate_coins()? {
            if coin.creator_address != self.address {
                continue;
            }
            let birth_epoch = store.get_epoch_for_coin(&coin.id)?.unwrap_or(0);
            let (note, note_key, checkpoint) =
                shielded::deterministic_genesis_note(&coin, birth_epoch, &chain_id);
            if store
                .load_shielded_owned_note::<OwnedShieldedNote>(&note.commitment)?
                .is_none()
            {
                let owned = OwnedShieldedNote {
                    note: note.clone(),
                    note_key,
                    checkpoint,
                    source: OwnedShieldedNoteSource::Genesis { coin_id: coin.id },
                };
                store.store_shielded_owned_note(&note.commitment, &owned)?;
                store.store_shielded_checkpoint(&owned.checkpoint)?;
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
        let decoded = canonical::decode_shielded_output_plaintext(&plaintext)?;
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

    fn rescan_shielded_outputs(&self) -> Result<()> {
        let store = self
            ._db
            .upgrade()
            .ok_or_else(|| anyhow!("Database connection dropped"))?;
        for (tx_id, output_index, output) in store.iterate_shielded_outputs()? {
            let Some(plaintext) = self.decrypt_shielded_output(&output)? else {
                continue;
            };
            if store
                .load_shielded_owned_note::<OwnedShieldedNote>(&output.note_commitment)?
                .is_some()
            {
                continue;
            }
            let owned = OwnedShieldedNote {
                note: plaintext.note.clone(),
                note_key: plaintext.note_key,
                checkpoint: plaintext.checkpoint,
                source: OwnedShieldedNoteSource::Received {
                    tx_id,
                    output_index,
                },
            };
            store.store_shielded_owned_note(&output.note_commitment, &owned)?;
            store.store_shielded_checkpoint(&owned.checkpoint)?;
        }
        Ok(())
    }

    fn sync_owned_shielded_notes(&self) -> Result<()> {
        self.materialize_owned_genesis_notes()?;
        self.rescan_shielded_outputs()?;
        Ok(())
    }

    pub fn sync_shielded_notes(&self) -> Result<()> {
        self.sync_owned_shielded_notes()
    }

    pub fn list_owned_shielded_notes(&self) -> Result<Vec<OwnedShieldedNote>> {
        let store = self
            ._db
            .upgrade()
            .ok_or_else(|| anyhow!("Database connection dropped"))?;
        self.sync_owned_shielded_notes()?;
        let mut notes = store.iterate_shielded_owned_notes::<OwnedShieldedNote>()?;
        notes.retain(|note| {
            store
                .is_shielded_note_spent(&note.note.commitment)
                .map(|spent| !spent)
                .unwrap_or(false)
        });
        notes.sort_by(|a, b| {
            b.note
                .birth_epoch
                .cmp(&a.note.birth_epoch)
                .then(b.note.commitment.cmp(&a.note.commitment))
        });
        Ok(notes)
    }

    fn select_shielded_notes(&self, amount: u64) -> Result<Vec<OwnedShieldedNote>> {
        let mut selected = Vec::new();
        let mut total = 0u64;
        for note in self.list_owned_shielded_notes()? {
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
        Ok(selected)
    }

    fn build_shielded_output(
        &self,
        owner_signing_pk: TaggedSigningPublicKey,
        owner_kem_pk: TaggedKemPublicKey,
        value: u64,
        birth_epoch: u64,
    ) -> Result<(ShieldedOutput, ShieldedOutputPlaintext)> {
        let mut note_key = [0u8; 32];
        let mut rho = [0u8; 32];
        let mut note_randomizer = [0u8; 32];
        OsRng.fill_bytes(&mut note_key);
        OsRng.fill_bytes(&mut rho);
        OsRng.fill_bytes(&mut note_randomizer);

        let note = shielded::ShieldedNote::new(
            value,
            birth_epoch,
            owner_signing_pk,
            owner_kem_pk.clone(),
            note_key,
            rho,
            note_randomizer,
        );
        let checkpoint =
            shielded::HistoricalUnspentCheckpoint::genesis(note.commitment, birth_epoch);
        let payload = ShieldedOutputPlaintext {
            note: note.clone(),
            note_key,
            checkpoint,
        };
        let payload_bytes = canonical::encode_shielded_output_plaintext(&payload)?;
        let (kem_ct, shared) = owner_kem_pk.encapsulate()?;
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&shared));
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), payload_bytes.as_ref())
            .map_err(|e| anyhow!("failed to encrypt shielded output: {}", e))?;
        Ok((
            ShieldedOutput {
                note_commitment: note.commitment,
                kem_ct,
                nonce,
                view_tag: crypto::view_tag(&shared),
                ciphertext,
            },
            payload,
        ))
    }

    fn store_sent_tx_record(
        &self,
        store: &Store,
        tx_id: &[u8; 32],
        commit_epoch: u64,
        amount: u64,
        counterparty: Address,
    ) -> Result<()> {
        let mut key = Vec::with_capacity(SENT_TX_PREFIX.len() + tx_id.len());
        key.extend_from_slice(SENT_TX_PREFIX);
        key.extend_from_slice(tx_id);
        store.put(
            "wallet",
            &key,
            &SentShieldedTxRecord {
                tx_id: *tx_id,
                commit_epoch,
                amount,
                counterparty,
            },
        )
    }

    fn sent_tx_records(&self, store: &Store) -> Result<Vec<SentShieldedTxRecord>> {
        let wallet_cf = store
            .db
            .cf_handle("wallet")
            .ok_or_else(|| anyhow!("'wallet' column family missing"))?;
        let iter = store
            .db
            .iterator_cf(wallet_cf, rocksdb::IteratorMode::Start);
        let mut records = Vec::new();
        for item in iter {
            let (key, value) = item?;
            if !key.starts_with(SENT_TX_PREFIX) {
                continue;
            }
            records.push(bincode::deserialize::<SentShieldedTxRecord>(&value)?);
        }
        Ok(records)
    }

    pub fn scan_tx_for_me(&self, tx: &Tx) -> Result<()> {
        let store = self
            ._db
            .upgrade()
            .ok_or_else(|| anyhow!("Database connection dropped"))?;
        let tx_id = tx.id()?;
        for (output_index, output) in tx.outputs.iter().enumerate() {
            let Some(plaintext) = self.decrypt_shielded_output(output)? else {
                continue;
            };
            if store
                .load_shielded_owned_note::<OwnedShieldedNote>(&output.note_commitment)?
                .is_some()
            {
                continue;
            }
            let owned = OwnedShieldedNote {
                note: plaintext.note.clone(),
                note_key: plaintext.note_key,
                checkpoint: plaintext.checkpoint,
                source: OwnedShieldedNoteSource::Received {
                    tx_id,
                    output_index: output_index as u32,
                },
            };
            store.store_shielded_owned_note(&output.note_commitment, &owned)?;
            store.store_shielded_checkpoint(&owned.checkpoint)?;
        }
        Ok(())
    }

    pub fn balance(&self) -> Result<u64> {
        Ok(self
            .list_owned_shielded_notes()?
            .into_iter()
            .fold(0u64, |sum, note| sum.saturating_add(note.note.value)))
    }

    /// Sends a canonical shielded transaction to a verified recipient document.
    pub async fn send_with_paycode_and_note(
        &self,
        receiver_paycode: &str,
        amount: u64,
        network: &crate::network::NetHandle,
    ) -> Result<SendOutcome> {
        let (_recipient_addr, recipient_signing_pk, receiver_kem_pk) = self
            .parse_recipient_handle(receiver_paycode)
            .context("Invalid receiver handle")?;
        let recipient_address = recipient_signing_pk.address();
        let store = self
            ._db
            .upgrade()
            .ok_or_else(|| anyhow!("Database connection dropped"))?;
        transaction::ensure_shielded_runtime_state(store.as_ref())?;
        self.sync_owned_shielded_notes()?;
        let selected_notes = self.select_shielded_notes(amount)?;
        let total_selected = selected_notes
            .iter()
            .fold(0u64, |sum, note| sum.saturating_add(note.note.value));

        let current_epoch = transaction::current_nullifier_epoch(store.as_ref())?;
        let history_through = current_epoch.checked_sub(1);
        let note_tree = store
            .load_shielded_note_tree()?
            .ok_or_else(|| anyhow!("missing shielded note tree"))?;
        let tree_root = note_tree.root();
        let chain_id = store.get_chain_id()?;

        let mut input_witnesses = Vec::with_capacity(selected_notes.len());
        let mut nullifiers = Vec::with_capacity(selected_notes.len());
        for owned in &selected_notes {
            let membership_proof = note_tree
                .prove_membership(&owned.note.commitment)
                .ok_or_else(|| anyhow!("missing membership proof for owned shielded note"))?;
            if membership_proof.root != tree_root {
                bail!("shielded note tree changed while building the spend");
            }
            let extension = transaction::build_local_historical_extension(
                store.as_ref(),
                &owned.note,
                &owned.note_key,
                &owned.checkpoint,
                history_through,
            )?;
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
                &extension,
                &current_nullifier,
            ));
        }

        let mut outputs = Vec::new();
        let mut output_witnesses = Vec::new();
        let (recipient_output, recipient_plaintext) = self.build_shielded_output(
            recipient_signing_pk,
            receiver_kem_pk,
            amount,
            current_epoch,
        )?;
        output_witnesses.push(proof::output_witness_from_local(
            &recipient_plaintext,
            &recipient_output,
        ));
        outputs.push(recipient_output);

        let change = total_selected.saturating_sub(amount);
        if change > 0 {
            let (change_output, change_plaintext) = self.build_shielded_output(
                self.signing_pk.clone(),
                self.kem_pk.clone(),
                change,
                current_epoch,
            )?;
            output_witnesses.push(proof::output_witness_from_local(
                &change_plaintext,
                &change_output,
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
        let (receipt, _journal) = proof::prove_shielded_tx(&witness)?;
        let tx = Tx::new(
            nullifiers.clone(),
            outputs,
            proof::receipt_to_bytes(&receipt)?,
        );

        let tx_id = tx.apply(store.as_ref())?;
        for (owned, nullifier) in selected_notes.iter().zip(nullifiers.iter()) {
            store.mark_shielded_note_spent(&owned.note.commitment, nullifier)?;
        }
        self.store_sent_tx_record(
            store.as_ref(),
            &tx_id,
            current_epoch,
            amount,
            recipient_address,
        )?;
        self.scan_tx_for_me(&tx)?;
        network.gossip_tx(&tx).await;
        crate::metrics::V3_SENDS.inc();

        Ok(SendOutcome {
            tx_id,
            input_count: tx.nullifiers.len(),
            output_count: tx.outputs.len(),
        })
    }

    // Deprecated wrappers removed; use send_with_paycode_and_note

    /// Simple wrapper: pay using a recipient handle (address or KeyDoc JSON) with empty note.
    pub async fn pay(
        &self,
        to: &str,
        amount: u64,
        network: &crate::network::NetHandle,
    ) -> Result<SendOutcome> {
        self.send_with_paycode_and_note(to, amount, network).await
    }

    /// Gets the transaction history for this wallet
    pub fn get_transaction_history(&self) -> Result<Vec<TransactionRecord>> {
        let store = self
            ._db
            .upgrade()
            .ok_or_else(|| anyhow!("Database connection dropped"))?;
        self.sync_owned_shielded_notes()?;
        let mut history = Vec::new();

        for record in self.sent_tx_records(store.as_ref())? {
            history.push(TransactionRecord {
                coin_id: record.tx_id,
                transfer_hash: record.tx_id,
                commit_epoch: record.commit_epoch,
                is_sender: true,
                amount: record.amount,
                counterparty: record.counterparty,
            });
        }

        for owned in store.iterate_shielded_owned_notes::<OwnedShieldedNote>()? {
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
}

/// Represents a transaction record for wallet history
#[derive(Debug, Clone)]
pub struct TransactionRecord {
    pub coin_id: [u8; 32],
    pub transfer_hash: [u8; 32],
    pub commit_epoch: u64,
    pub is_sender: bool,
    pub amount: u64,
    pub counterparty: crate::crypto::Address,
}

/// Outcome of a canonical shielded send operation.
#[derive(Debug, Clone)]
pub struct SendOutcome {
    pub tx_id: [u8; 32],
    pub input_count: usize,
    pub output_count: usize,
}
