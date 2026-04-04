use crate::{
    canonical,
    consensus::ValidatorId,
    crypto::{
        self, Address, TaggedKemPublicKey, TaggedSigningPublicKey, ML_KEM_768_CT_BYTES,
        ML_KEM_768_PK_BYTES, ML_KEM_768_SK_BYTES,
    },
    discovery::{self, DiscoveryClient, DiscoveryRecord, HandleResponsePlaintext},
    ingress::IngressClient,
    node_control::{
        CompactCommittedCoin, CompactShieldedOutput, CompactWalletSyncDelta, CompactWalletSyncHead,
        NodeControlClient, ShieldedRuntimeSnapshot, WalletSendRuntimeMaterial,
    },
    proof,
    proof_assistant::ProofAssistantClient,
    protocol::CURRENT as PROTOCOL,
    shielded,
    storage::WalletStore,
    transaction::{
        ClaimUnbonding, OrdinaryPrivateTransfer, PrivateDelegation, PrivateUndelegation,
        SharedStateAction, SharedStateControlDocument, ShieldedOutput, ShieldedOutputPlaintext, Tx,
    },
};
use aws_lc_rs::unstable::signature::PqdsaKeyPair;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use tokio::sync::broadcast;
use tokio::time::{self, Duration, MissedTickBehavior};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecipientHandle {
    pub chain_id: [u8; 32],
    pub signing_pk: TaggedSigningPublicKey,
    #[serde(with = "BigArray")]
    pub receive_key_id: [u8; 32],
    pub kem_pk: TaggedKemPublicKey,
    pub requested_amount: Option<u64>,
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
use std::collections::BTreeSet;
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
const SHIELDED_STORE_MAGIC: &[u8; 4] = b"UCS4";
const SHIELDED_STORE_VERSION: u8 = 1;
const SHIELDED_STORE_DOMAIN: &str = "unchained-wallet-shielded-store-v1";
const SHIELDED_SEND_SEED_DOMAIN: &str = "unchained-wallet-shielded-send-seed-v1";
const SHIELDED_OUTPUT_ENTROPY_DOMAIN: &str = "unchained-wallet-shielded-output-entropy-v1";
const RECEIVE_KEY_LIFETIME_MS: u64 = 7 * 24 * 60 * 60 * 1000;
const OFFLINE_DESCRIPTOR_ROTATION_WINDOW_DIVISOR: u64 = 2;
const OFFLINE_DESCRIPTOR_SCAN_RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1000;
const RECEIVE_KEY_ID_DOMAIN: &str = "unchained-wallet-receive-key-id-v1";
const INTERNAL_RECEIVE_KEY_DOMAIN: &str = "unchained-wallet-internal-receive-key-v1";
const LOCAL_ARCHIVE_PROVIDER_DOMAIN: &str = "unchained-wallet-local-archive-provider-v1";
const LOCAL_EXTENSION_BLINDING_DOMAIN: &str = "unchained-wallet-local-extension-blinding-v1";
const COMPACT_WALLET_SYNC_CURSOR_KEY: &[u8] = b"compact_wallet_sync_cursor";
const COMPACT_WALLET_SYNC_MAX_COINS_PER_REQUEST: u32 = 512;
const COMPACT_WALLET_SYNC_MAX_OUTPUTS_PER_REQUEST: u32 = 2048;

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
struct CompactWalletScanCursor {
    chain_id: [u8; 32],
    next_coin_index: u64,
    next_output_index: u64,
    synced_through_anchor_num: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
enum OfflineReceiveDescriptorState {
    Active,
    Retired,
    Compromised,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
enum ReceiveKeyModeRecord {
    FixedOwner {
        owner_signing_pk: TaggedSigningPublicKey,
    },
    OfflineDescriptor {
        #[serde(with = "BigArray")]
        descriptor_binding: [u8; 32],
        asset_policy: discovery::OfflineReceiveAssetPolicy,
        policy_flags: u64,
        state: OfflineReceiveDescriptorState,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ReceiveKeyRecord {
    #[serde(with = "BigArray")]
    pub key_id: [u8; 32],
    #[serde(with = "BigArray")]
    pub chain_id: [u8; 32],
    pub mode: ReceiveKeyModeRecord,
    #[serde(with = "BigArray")]
    pub kem_sk: [u8; ML_KEM_768_SK_BYTES],
    #[serde(with = "BigArray")]
    pub kem_pk: [u8; ML_KEM_768_PK_BYTES],
    pub issued_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub retention_expires_unix_ms: u64,
}

#[derive(Debug, Clone)]
enum WalletReceiveKeyMode {
    FixedOwner(TaggedSigningPublicKey),
    OfflineDescriptor { descriptor_binding: [u8; 32] },
}

#[derive(Debug, Clone)]
struct WalletReceiveKeyMaterial {
    key_id: [u8; 32],
    chain_id: [u8; 32],
    mode: WalletReceiveKeyMode,
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
    ingress_client: Option<IngressClient>,
    proof_assistant_client: Option<ProofAssistantClient>,
    discovery_client: Option<DiscoveryClient>,
    signing_key_pkcs8: Vec<u8>,
    signing_pk: TaggedSigningPublicKey,
    lock_seed: [u8; 32],
    address: Address,
}

#[derive(Debug, Clone)]
struct DiscoveryMailboxMaterial {
    locator: String,
    locator_id: [u8; 32],
    mailbox_id: [u8; 32],
    mailbox_auth_token: [u8; 32],
    mailbox_kem_sk: [u8; ML_KEM_768_SK_BYTES],
    mailbox_kem_pk: TaggedKemPublicKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocatorPublishMode {
    Automatic,
    ForceRotate,
    CompromiseRotate,
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

    pub fn tx_with_proof(&self, proof: proof::TransparentProof) -> Tx {
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

    pub fn tx_with_proof(&self, proof: proof::TransparentProof) -> Tx {
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

    pub fn tx_with_proof(&self, proof: proof::TransparentProof) -> Tx {
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

    pub fn tx_with_proof(&self, proof: proof::TransparentProof) -> Tx {
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

    fn offline_descriptor_retention_expires(expires_unix_ms: u64) -> u64 {
        expires_unix_ms.saturating_add(OFFLINE_DESCRIPTOR_SCAN_RETENTION_MS)
    }

    fn receive_key_record_to_material(record: &ReceiveKeyRecord) -> WalletReceiveKeyMaterial {
        WalletReceiveKeyMaterial {
            key_id: record.key_id,
            chain_id: record.chain_id,
            mode: match &record.mode {
                ReceiveKeyModeRecord::FixedOwner { owner_signing_pk } => {
                    WalletReceiveKeyMode::FixedOwner(owner_signing_pk.clone())
                }
                ReceiveKeyModeRecord::OfflineDescriptor {
                    descriptor_binding, ..
                } => WalletReceiveKeyMode::OfflineDescriptor {
                    descriptor_binding: *descriptor_binding,
                },
            },
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
    ) -> Result<(ReceiveKeyRecord, PqdsaKeyPair)> {
        let handle_signing_key = crypto::ml_dsa_65_generate()?;
        let handle_signing_pk = crypto::ml_dsa_65_public_key(&handle_signing_key);
        let (kem_sk, kem_pk) = crypto::ml_kem_768_generate();
        let key_id = Self::derive_receive_key_id(&chain_id, &kem_pk, issued_unix_ms);
        Ok((
            ReceiveKeyRecord {
                key_id,
                chain_id,
                mode: ReceiveKeyModeRecord::FixedOwner {
                    owner_signing_pk: handle_signing_pk,
                },
                kem_sk: crypto::ml_kem_768_secret_key_to_bytes(&kem_sk),
                kem_pk: kem_pk.bytes,
                issued_unix_ms,
                expires_unix_ms,
                retention_expires_unix_ms: expires_unix_ms,
            },
            handle_signing_key,
        ))
    }

    fn build_recipient_handle(
        chain_id: [u8; 32],
        record: &ReceiveKeyRecord,
        handle_signing_key: &PqdsaKeyPair,
        requested_amount: Option<u64>,
    ) -> Result<RecipientHandle> {
        let owner_signing_pk = match &record.mode {
            ReceiveKeyModeRecord::FixedOwner { owner_signing_pk } => owner_signing_pk,
            ReceiveKeyModeRecord::OfflineDescriptor { .. } => {
                bail!("offline receive descriptor key cannot be serialized as a recipient handle")
            }
        };
        let kem_pk = TaggedKemPublicKey::from_ml_kem_768_array(record.kem_pk);
        let msg = canonical::encode_recipient_handle_signable(
            &chain_id,
            owner_signing_pk,
            &record.key_id,
            &kem_pk,
            requested_amount,
            record.issued_unix_ms,
            record.expires_unix_ms,
        )?;
        let sig = crypto::ml_dsa_65_sign(handle_signing_key, &msg)?;
        Ok(RecipientHandle {
            chain_id,
            signing_pk: owner_signing_pk.clone(),
            receive_key_id: record.key_id,
            kem_pk,
            requested_amount,
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
            .filter(|record| now_unix_ms >= record.retention_expires_unix_ms)
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
    ) -> Result<(ReceiveKeyRecord, PqdsaKeyPair)> {
        self.prune_expired_receive_key_records(store)?;
        let issued_unix_ms = Self::now_unix_ms();
        let expires_unix_ms = issued_unix_ms.saturating_add(RECEIVE_KEY_LIFETIME_MS);
        let (record, handle_signing_key) =
            self.generate_receive_key_record(chain_id, issued_unix_ms, expires_unix_ms)?;
        self.store_receive_key_record(store, &record)?;
        Ok((record, handle_signing_key))
    }

    fn mint_internal_receive_kem_public_key_for_chain(
        &self,
        chain_id: [u8; 32],
        send_seed: &[u8; 32],
        output_index: u32,
        purpose: &[u8],
    ) -> Result<TaggedKemPublicKey> {
        let wallet_store = self.wallet_store()?;
        let record =
            self.derive_internal_receive_key_record(chain_id, send_seed, output_index, purpose);
        self.store_receive_key_record(wallet_store.as_ref(), &record)?;
        Ok(TaggedKemPublicKey::from_ml_kem_768_array(record.kem_pk))
    }

    fn mint_recipient_handle_for_chain(
        &self,
        chain_id: [u8; 32],
        requested_amount: Option<u64>,
    ) -> Result<String> {
        let wallet_store = self.wallet_store()?;
        let (record, handle_signing_key) =
            self.mint_receive_key_record(wallet_store.as_ref(), chain_id)?;
        serde_json::to_string(&Self::build_recipient_handle(
            chain_id,
            &record,
            &handle_signing_key,
            requested_amount,
        )?)
        .context("serialize recipient handle")
    }

    fn receive_key_materials(&self, store: &WalletStore) -> Result<Vec<WalletReceiveKeyMaterial>> {
        self.prune_expired_receive_key_records(store)?;
        let now_unix_ms = Self::now_unix_ms();
        let mut materials = self
            .iterate_receive_key_records(store)?
            .into_iter()
            .filter(|record| now_unix_ms < record.retention_expires_unix_ms)
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

    fn derive_internal_receive_key_record(
        &self,
        chain_id: [u8; 32],
        send_seed: &[u8; 32],
        output_index: u32,
        purpose: &[u8],
    ) -> ReceiveKeyRecord {
        let mut hasher = blake3::Hasher::new_derive_key(INTERNAL_RECEIVE_KEY_DOMAIN);
        hasher.update(&self.lock_seed);
        hasher.update(&self.address);
        hasher.update(&chain_id);
        hasher.update(send_seed);
        hasher.update(&output_index.to_le_bytes());
        hasher.update(&(purpose.len() as u64).to_le_bytes());
        hasher.update(purpose);
        let mut xof = hasher.finalize_xof();
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        xof.fill(&mut d);
        xof.fill(&mut z);
        let (kem_sk, kem_pk) = crypto::ml_kem_768_generate_deterministic(&d, &z);
        let issued_unix_ms = 0;
        let expires_unix_ms = u64::MAX;
        let key_id = Self::derive_receive_key_id(&chain_id, &kem_pk, issued_unix_ms);
        ReceiveKeyRecord {
            key_id,
            chain_id,
            mode: ReceiveKeyModeRecord::FixedOwner {
                owner_signing_pk: self.signing_pk.clone(),
            },
            kem_sk: crypto::ml_kem_768_secret_key_to_bytes(&kem_sk),
            kem_pk: kem_pk.bytes,
            issued_unix_ms,
            expires_unix_ms,
            retention_expires_unix_ms: u64::MAX,
        }
    }

    fn require_node_client(&self) -> Result<&NodeControlClient> {
        self.node_client
            .as_ref()
            .ok_or_else(|| anyhow!("wallet requires an active node control client"))
    }

    fn require_ingress_client(&self) -> Result<&IngressClient> {
        self.ingress_client.as_ref().ok_or_else(|| {
            anyhow!(
                "wallet requires an access relay and submission gateway; configure [ingress.wallet] and restart `unchained_wallet serve`"
            )
        })
    }

    fn wallet_store(&self) -> Result<Arc<WalletStore>> {
        Ok(self.wallet_db.clone())
    }

    pub fn with_node_client(mut self, node_client: NodeControlClient) -> Self {
        self.node_client = Some(node_client);
        self
    }

    pub fn with_ingress_client(mut self, ingress_client: IngressClient) -> Self {
        self.ingress_client = Some(ingress_client);
        self
    }

    pub fn with_proof_assistant_client(
        mut self,
        proof_assistant_client: ProofAssistantClient,
    ) -> Self {
        self.proof_assistant_client = Some(proof_assistant_client);
        self
    }

    pub fn with_discovery_client(mut self, discovery_client: DiscoveryClient) -> Self {
        self.discovery_client = Some(discovery_client);
        self
    }

    pub fn has_ingress_client(&self) -> bool {
        self.ingress_client.is_some()
    }

    pub fn has_proof_assistant_client(&self) -> bool {
        self.proof_assistant_client.is_some()
    }

    pub fn has_discovery_client(&self) -> bool {
        self.discovery_client.is_some()
    }

    fn require_discovery_client(&self) -> Result<&DiscoveryClient> {
        self.discovery_client.as_ref().ok_or_else(|| {
            anyhow!(
                "wallet requires a discovery service; configure [discovery.wallet].server and restart `unchained_wallet serve`"
            )
        })
    }

    fn effective_chain_id(&self) -> Result<[u8; 32]> {
        if let Some(node_client) = &self.node_client {
            return node_client.chain_id();
        }
        if let Some(ingress_client) = &self.ingress_client {
            return ingress_client.chain_id();
        }
        if let Some(proof_assistant_client) = &self.proof_assistant_client {
            return proof_assistant_client.chain_id();
        }
        if let Some(discovery_client) = &self.discovery_client {
            return discovery_client.chain_id();
        }
        bail!(
            "wallet requires node control, ingress, proof assistant, or discovery for chain binding"
        )
    }

    async fn wallet_send_runtime_material_async(&self) -> Result<WalletSendRuntimeMaterial> {
        if let Some(node_client) = &self.node_client {
            return node_client.wallet_send_runtime_material_async().await;
        }
        if let Some(ingress_client) = &self.ingress_client {
            return ingress_client.wallet_send_runtime_material().await;
        }
        bail!("wallet requires either node control or ingress for send runtime material")
    }

    async fn prove_shielded_tx_proof(
        &self,
        witness: &proof_core::ProofShieldedTxWitness,
    ) -> Result<proof::TransparentProof> {
        if let Some(proof_assistant_client) = &self.proof_assistant_client {
            return proof_assistant_client.prove_shielded_tx(witness).await;
        }
        let (proof, _journal) = proof::prove_shielded_tx(witness)?;
        Ok(proof)
    }

    async fn prove_private_delegation_proof(
        &self,
        witness: &proof_core::ProofPrivateDelegationWitness,
    ) -> Result<proof::TransparentProof> {
        if let Some(proof_assistant_client) = &self.proof_assistant_client {
            return proof_assistant_client
                .prove_private_delegation(witness)
                .await;
        }
        let (proof, _journal) = proof::prove_private_delegation(witness)?;
        Ok(proof)
    }

    async fn prove_private_undelegation_proof(
        &self,
        witness: &proof_core::ProofPrivateUndelegationWitness,
    ) -> Result<proof::TransparentProof> {
        if let Some(proof_assistant_client) = &self.proof_assistant_client {
            return proof_assistant_client
                .prove_private_undelegation(witness)
                .await;
        }
        let (proof, _journal) = proof::prove_private_undelegation(witness)?;
        Ok(proof)
    }

    async fn prove_unbonding_claim_proof(
        &self,
        witness: &proof_core::ProofShieldedTxWitness,
    ) -> Result<proof::TransparentProof> {
        if let Some(proof_assistant_client) = &self.proof_assistant_client {
            return proof_assistant_client.prove_unbonding_claim(witness).await;
        }
        let (proof, _journal) = proof::prove_unbonding_claim(witness)?;
        Ok(proof)
    }

    async fn prove_checkpoint_accumulator_with_backend(
        &self,
        checkpoint: &shielded::HistoricalUnspentCheckpoint,
        extension: &shielded::HistoricalUnspentExtension,
        prior: Option<&proof::CheckpointAccumulatorProof>,
    ) -> Result<proof::CheckpointAccumulatorProof> {
        if let Some(proof_assistant_client) = &self.proof_assistant_client {
            return proof_assistant_client
                .prove_checkpoint_accumulator(checkpoint, extension, prior)
                .await;
        }
        proof::prove_checkpoint_accumulator(checkpoint, extension, prior)
    }

    fn compact_wallet_sync_head(&self) -> Result<CompactWalletSyncHead> {
        if let Some(node_client) = &self.node_client {
            return node_client.compact_wallet_sync_head();
        }
        if let Some(ingress_client) = &self.ingress_client {
            return ingress_client.compact_wallet_sync_head_blocking();
        }
        bail!("wallet requires either node control or ingress for compact sync")
    }

    fn request_compact_wallet_sync_delta(
        &self,
        next_coin_index: u64,
        next_output_index: u64,
        max_coins: u32,
        max_outputs: u32,
    ) -> Result<CompactWalletSyncDelta> {
        if let Some(node_client) = &self.node_client {
            return node_client.request_compact_wallet_sync_delta(
                next_coin_index,
                next_output_index,
                max_coins,
                max_outputs,
            );
        }
        if let Some(ingress_client) = &self.ingress_client {
            return ingress_client.request_compact_wallet_sync_delta_blocking(
                next_coin_index,
                next_output_index,
                max_coins,
                max_outputs,
            );
        }
        bail!("wallet requires either node control or ingress for compact sync")
    }

    fn root_ledger_digest(ledger: &shielded::NullifierRootLedger) -> Result<[u8; 32]> {
        Ok(crate::crypto::blake3_hash(
            &canonical::encode_nullifier_root_ledger(ledger)?,
        ))
    }

    fn local_archive_provider_id(chain_id: &[u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(LOCAL_ARCHIVE_PROVIDER_DOMAIN);
        hasher.update(chain_id);
        *hasher.finalize().as_bytes()
    }

    fn local_extension_aggregate_blinding(
        chain_id: &[u8; 32],
        rotation_round: u64,
        request_binding: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(LOCAL_EXTENSION_BLINDING_DOMAIN);
        hasher.update(chain_id);
        hasher.update(&rotation_round.to_le_bytes());
        hasher.update(request_binding);
        *hasher.finalize().as_bytes()
    }

    pub(crate) fn node_client(&self) -> Result<NodeControlClient> {
        Ok(self.require_node_client()?.clone())
    }

    pub(crate) fn compact_wallet_sync_head_for_control(&self) -> Result<CompactWalletSyncHead> {
        self.compact_wallet_sync_head()
    }

    fn state_binding_from_runtime(
        chain_id: [u8; 32],
        current_nullifier_epoch: u64,
        note_tree: &shielded::NoteCommitmentTree,
        root_ledger: &shielded::NullifierRootLedger,
    ) -> Result<PreparedShieldedTxStateBinding> {
        Ok(PreparedShieldedTxStateBinding {
            chain_id,
            current_nullifier_epoch,
            note_tree_root: note_tree.root(),
            root_ledger_digest: Self::root_ledger_digest(root_ledger)?,
        })
    }

    fn state_binding_from_snapshot(
        snapshot: &ShieldedRuntimeSnapshot,
    ) -> Result<PreparedShieldedTxStateBinding> {
        Self::state_binding_from_runtime(
            snapshot.chain_id,
            snapshot.current_nullifier_epoch,
            &snapshot.note_tree,
            &snapshot.root_ledger,
        )
    }

    fn state_binding_from_send_material(
        material: &WalletSendRuntimeMaterial,
    ) -> Result<PreparedShieldedTxStateBinding> {
        Self::state_binding_from_runtime(
            material.compact_wallet_sync.chain_id,
            material.compact_wallet_sync.current_nullifier_epoch,
            &material.note_tree,
            &material.root_ledger,
        )
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
                ingress_client: None,
                proof_assistant_client: None,
                discovery_client: None,
                signing_key_pkcs8: secrets.signing_key_pkcs8,
                signing_pk: signing_pk.clone(),
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
            ingress_client: None,
            proof_assistant_client: None,
            discovery_client: None,
            signing_key_pkcs8: secrets.signing_key_pkcs8,
            signing_pk,
            lock_seed,
            address,
        })
    }

    /// Loads the private wallet material without opening the chain database.
    /// Use this for runtimes that only need signing identity and lock derivation.
    pub fn load_or_create_private(wallet_db: Arc<WalletStore>) -> Result<Self> {
        Self::load_or_create_private_inner(wallet_db)
    }

    pub fn from_private_material(
        wallet_db: Arc<WalletStore>,
        signing_key_pkcs8: &[u8],
        lock_seed: [u8; 32],
    ) -> Result<Self> {
        let signing_key = crypto::ml_dsa_65_keypair_from_pkcs8(signing_key_pkcs8)?;
        let signing_pk = crypto::ml_dsa_65_public_key(&signing_key);
        Ok(Wallet {
            wallet_db,
            node_client: None,
            ingress_client: None,
            proof_assistant_client: None,
            discovery_client: None,
            signing_key_pkcs8: signing_key_pkcs8.to_vec(),
            signing_pk: signing_pk.clone(),
            lock_seed,
            address: crypto::address_from_pk(&signing_pk),
        })
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
    fn looks_like_recipient_handle_document(value: &str) -> bool {
        let trimmed = value.trim();
        trimmed.starts_with('{') && trimmed.ends_with('}')
    }

    fn validate_recipient_handle_document_for_chain(
        handle: &RecipientHandle,
        chain_id: [u8; 32],
    ) -> Result<()> {
        if handle.chain_id != chain_id {
            bail!("recipient handle chain_id mismatch");
        }
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
            handle.requested_amount,
            handle.issued_unix_ms,
            handle.expires_unix_ms,
        )?;
        handle.signing_pk.verify(&msg, &handle.sig)?;
        Ok(())
    }

    fn discovery_mailbox_material_for_chain(
        &self,
        chain_id: [u8; 32],
    ) -> Result<DiscoveryMailboxMaterial> {
        let locator = discovery::locator_from_signing_pk(&self.signing_pk);
        let locator_id = discovery::parse_locator(&locator)?;
        let mailbox_id = discovery::mailbox_id_for_locator(&chain_id, &locator_id);
        let mailbox_auth_token =
            discovery::mailbox_auth_token(&self.lock_seed, &chain_id, &locator_id);
        let (mailbox_kem_sk, mailbox_kem_pk) =
            discovery::derive_mailbox_kem_keypair(&self.lock_seed, &self.address, &chain_id);
        Ok(DiscoveryMailboxMaterial {
            locator,
            locator_id,
            mailbox_id,
            mailbox_auth_token,
            mailbox_kem_sk,
            mailbox_kem_pk,
        })
    }

    fn mint_offline_receive_material_for_chain(
        &self,
        store: &WalletStore,
        chain_id: [u8; 32],
        record_ttl: Duration,
    ) -> Result<discovery::OfflineReceiveDescriptor> {
        let (scan_kem_sk, scan_kem_pk) = crypto::ml_kem_768_generate();
        let scan_kem_sk = crypto::ml_kem_768_secret_key_to_bytes(&scan_kem_sk);
        let descriptor = discovery::build_signed_offline_receive_descriptor(
            &self.signing_key_pkcs8,
            &self.signing_pk,
            chain_id,
            scan_kem_pk.clone(),
            discovery::OfflineReceiveAssetPolicy::BaseAssetOnly,
            0,
            record_ttl,
        )?;
        let key_id =
            Self::derive_receive_key_id(&chain_id, &scan_kem_pk, descriptor.issued_unix_ms);
        let scan_key_record = ReceiveKeyRecord {
            key_id,
            chain_id,
            mode: ReceiveKeyModeRecord::OfflineDescriptor {
                descriptor_binding: descriptor.descriptor_binding,
                asset_policy: descriptor.asset_policy.clone(),
                policy_flags: descriptor.policy_flags,
                state: OfflineReceiveDescriptorState::Active,
            },
            kem_sk: scan_kem_sk,
            kem_pk: scan_kem_pk.bytes,
            issued_unix_ms: descriptor.issued_unix_ms,
            expires_unix_ms: descriptor.expires_unix_ms,
            retention_expires_unix_ms: Self::offline_descriptor_retention_expires(
                descriptor.expires_unix_ms,
            ),
        };
        self.store_receive_key_record(store, &scan_key_record)?;
        Ok(descriptor)
    }

    fn transition_active_offline_receive_records_for_chain(
        &self,
        store: &WalletStore,
        chain_id: [u8; 32],
        next_state: OfflineReceiveDescriptorState,
    ) -> Result<()> {
        for mut record in self.iterate_receive_key_records(store)? {
            if record.chain_id != chain_id {
                continue;
            }
            let ReceiveKeyModeRecord::OfflineDescriptor { state, .. } = &mut record.mode else {
                continue;
            };
            if *state != OfflineReceiveDescriptorState::Active {
                continue;
            }
            *state = next_state.clone();
            self.store_receive_key_record(store, &record)?;
        }
        Ok(())
    }

    fn active_offline_receive_record_for_chain(
        &self,
        store: &WalletStore,
        chain_id: [u8; 32],
        minimum_remaining_ms: u64,
    ) -> Result<Option<ReceiveKeyRecord>> {
        let now_unix_ms = Self::now_unix_ms();
        Ok(self
            .iterate_receive_key_records(store)?
            .into_iter()
            .filter(|record| {
                if record.chain_id != chain_id {
                    return false;
                }
                match record.mode {
                    ReceiveKeyModeRecord::OfflineDescriptor {
                        state: OfflineReceiveDescriptorState::Active,
                        ..
                    } => {
                        now_unix_ms < record.expires_unix_ms
                            && record.expires_unix_ms.saturating_sub(now_unix_ms)
                                >= minimum_remaining_ms
                    }
                    ReceiveKeyModeRecord::OfflineDescriptor { .. } => false,
                    ReceiveKeyModeRecord::FixedOwner { .. } => false,
                }
            })
            .max_by(|left, right| {
                left.issued_unix_ms
                    .cmp(&right.issued_unix_ms)
                    .then(left.key_id.cmp(&right.key_id))
            }))
    }

    fn offline_receive_descriptor_from_record(
        &self,
        record: &ReceiveKeyRecord,
    ) -> Result<discovery::OfflineReceiveDescriptor> {
        let (descriptor_binding, asset_policy, policy_flags) = match &record.mode {
            ReceiveKeyModeRecord::OfflineDescriptor {
                descriptor_binding,
                asset_policy,
                policy_flags,
                ..
            } => (*descriptor_binding, asset_policy.clone(), *policy_flags),
            ReceiveKeyModeRecord::FixedOwner { .. } => {
                bail!("fixed-owner receive key cannot be reconstructed as an offline descriptor");
            }
        };
        let descriptor = discovery::sign_offline_receive_descriptor(
            &self.signing_key_pkcs8,
            &self.signing_pk,
            record.chain_id,
            TaggedKemPublicKey::from_ml_kem_768_array(record.kem_pk),
            asset_policy,
            policy_flags,
            record.issued_unix_ms,
            record.expires_unix_ms,
        )?;
        if descriptor.descriptor_binding != descriptor_binding {
            bail!("offline receive descriptor binding mismatch for stored receive key");
        }
        Ok(descriptor)
    }

    fn discovery_record_for_chain_with_mode(
        &self,
        chain_id: [u8; 32],
        record_ttl: Duration,
        publish_mode: LocatorPublishMode,
    ) -> Result<(DiscoveryMailboxMaterial, DiscoveryRecord)> {
        let wallet_store = self.wallet_store()?;
        let material = self.discovery_mailbox_material_for_chain(chain_id)?;
        let rotation_window_ms = (record_ttl.as_millis() as u64)
            .saturating_div(OFFLINE_DESCRIPTOR_ROTATION_WINDOW_DIVISOR)
            .max(1);
        let offline_receive = match publish_mode {
            LocatorPublishMode::Automatic => match self.active_offline_receive_record_for_chain(
                wallet_store.as_ref(),
                chain_id,
                rotation_window_ms,
            )? {
                Some(record) => self.offline_receive_descriptor_from_record(&record)?,
                None => {
                    self.transition_active_offline_receive_records_for_chain(
                        wallet_store.as_ref(),
                        chain_id,
                        OfflineReceiveDescriptorState::Retired,
                    )?;
                    self.mint_offline_receive_material_for_chain(
                        wallet_store.as_ref(),
                        chain_id,
                        record_ttl,
                    )?
                }
            },
            LocatorPublishMode::ForceRotate => {
                self.transition_active_offline_receive_records_for_chain(
                    wallet_store.as_ref(),
                    chain_id,
                    OfflineReceiveDescriptorState::Retired,
                )?;
                self.mint_offline_receive_material_for_chain(
                    wallet_store.as_ref(),
                    chain_id,
                    record_ttl,
                )?
            }
            LocatorPublishMode::CompromiseRotate => {
                self.transition_active_offline_receive_records_for_chain(
                    wallet_store.as_ref(),
                    chain_id,
                    OfflineReceiveDescriptorState::Compromised,
                )?;
                self.mint_offline_receive_material_for_chain(
                    wallet_store.as_ref(),
                    chain_id,
                    record_ttl,
                )?
            }
        };
        let (_locator, locator_id, mailbox_id, record) = discovery::build_signed_discovery_record(
            &self.signing_key_pkcs8,
            &self.signing_pk,
            chain_id,
            material.mailbox_kem_pk.clone(),
            offline_receive,
            record_ttl,
        )?;
        if locator_id != material.locator_id || mailbox_id != material.mailbox_id {
            bail!("discovery record derivation mismatch");
        }
        Ok((material, record))
    }

    pub fn locator(&self) -> String {
        discovery::locator_from_signing_pk(&self.signing_pk)
    }

    async fn publish_locator_with_mode(
        &self,
        record_ttl: Duration,
        publish_mode: LocatorPublishMode,
    ) -> Result<String> {
        let chain_id = self.effective_chain_id()?;
        let (material, record) =
            self.discovery_record_for_chain_with_mode(chain_id, record_ttl, publish_mode)?;
        self.require_discovery_client()?
            .publish_record(&record, &material.mailbox_auth_token)
            .await?;
        Ok(material.locator)
    }

    pub async fn publish_locator(&self, record_ttl: Duration) -> Result<String> {
        self.publish_locator_with_mode(record_ttl, LocatorPublishMode::Automatic)
            .await
    }

    pub async fn rotate_locator(&self, record_ttl: Duration) -> Result<String> {
        self.publish_locator_with_mode(record_ttl, LocatorPublishMode::ForceRotate)
            .await
    }

    pub async fn compromise_rotate_locator(&self, record_ttl: Duration) -> Result<String> {
        self.publish_locator_with_mode(record_ttl, LocatorPublishMode::CompromiseRotate)
            .await
    }

    pub fn mint_invoice(&self) -> Result<String> {
        self.mint_invoice_with_amount(None)
    }

    pub fn mint_invoice_with_amount(&self, requested_amount: Option<u64>) -> Result<String> {
        self.mint_invoice_for_chain(self.effective_chain_id()?, requested_amount)
    }

    fn mint_invoice_for_chain(
        &self,
        chain_id: [u8; 32],
        requested_amount: Option<u64>,
    ) -> Result<String> {
        self.mint_recipient_handle_for_chain(chain_id, requested_amount)
    }

    pub fn parse_invoice(
        invoice_str: &str,
    ) -> Result<(Address, TaggedSigningPublicKey, TaggedKemPublicKey)> {
        let handle = Self::parse_recipient_handle_document(invoice_str)?;
        Ok((
            crate::crypto::address_from_pk(&handle.signing_pk),
            handle.signing_pk,
            handle.kem_pk,
        ))
    }

    fn parse_recipient_handle(
        &self,
        handle: &str,
    ) -> Result<(
        Address,
        TaggedSigningPublicKey,
        TaggedKemPublicKey,
        [u8; 32],
        Option<u64>,
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
        Option<u64>,
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
            handle.requested_amount,
        ))
    }

    pub fn validate_invoice(&self, handle: &str) -> Result<()> {
        self.parse_recipient_handle(handle).map(|_| ())
    }

    fn parse_recipient_handle_document(handle_str: &str) -> Result<RecipientHandle> {
        let trimmed = handle_str.trim();
        if !Self::looks_like_recipient_handle_document(trimmed) {
            bail!("recipient handle must be a signed JSON document");
        }
        let handle: RecipientHandle =
            serde_json::from_str(trimmed).context("invalid recipient handle JSON")?;
        Self::validate_recipient_handle_document_for_chain(&handle, handle.chain_id)?;
        Ok(handle)
    }

    fn materialize_owned_genesis_notes_from_coins(
        &self,
        chain_id: [u8; 32],
        committed_coins: &[(u64, crate::coin::Coin)],
    ) -> Result<()> {
        let wallet_store = self.wallet_store()?;
        for (birth_epoch, coin) in committed_coins {
            if coin.creator_address != self.address {
                continue;
            }
            let (note, note_key, checkpoint) =
                shielded::deterministic_genesis_note(coin, *birth_epoch, &chain_id);
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

    fn materialize_owned_genesis_notes(&self, snapshot: &ShieldedRuntimeSnapshot) -> Result<()> {
        self.materialize_owned_genesis_notes_from_coins(
            snapshot.chain_id,
            &snapshot.committed_coins,
        )
    }

    fn materialize_owned_genesis_notes_from_compact_coins(
        &self,
        chain_id: [u8; 32],
        committed_coins: &[CompactCommittedCoin],
    ) -> Result<()> {
        let owned = committed_coins
            .iter()
            .map(|record| (record.birth_epoch, record.coin.clone()))
            .collect::<Vec<_>>();
        self.materialize_owned_genesis_notes_from_coins(chain_id, &owned)
    }

    fn decrypt_shielded_payload(
        &self,
        note_commitment: &[u8; 32],
        kem_ct: &[u8; ML_KEM_768_CT_BYTES],
        nonce: &[u8; NONCE_LEN],
        detection_tag: u8,
        ciphertext: &[u8],
    ) -> Result<Option<(ShieldedOutputPlaintext, [u8; 32])>> {
        let wallet_store = self.wallet_store()?;
        for material in self.receive_key_materials(wallet_store.as_ref())? {
            let shared = crypto::ml_kem_768_decapsulate(
                &crypto::ml_kem_768_secret_key_from_bytes(&material.kem_sk),
                kem_ct,
            )?;
            if crypto::view_tag(&shared) != detection_tag {
                continue;
            }

            let cipher = XChaCha20Poly1305::new(Key::from_slice(&shared));
            let plaintext = match cipher.decrypt(XNonce::from_slice(nonce), ciphertext) {
                Ok(plaintext) => plaintext,
                Err(_) => continue,
            };
            let decoded = proof::output_plaintext_from_proof(
                &bincode::deserialize::<proof_core::ProofShieldedOutputPlaintext>(&plaintext)
                    .map_err(|err| anyhow!("failed to decode shielded output payload: {err}"))?,
            )?;
            if decoded.note.commitment != *note_commitment {
                bail!("shielded output plaintext commitment mismatch");
            }
            if decoded.note.owner_kem_pk != material.kem_pk {
                continue;
            }
            match &material.mode {
                WalletReceiveKeyMode::FixedOwner(owner_signing_pk) => {
                    if decoded.note.owner_signing_pk != *owner_signing_pk {
                        continue;
                    }
                }
                WalletReceiveKeyMode::OfflineDescriptor { descriptor_binding } => {
                    if !decoded.note.kind.is_payment() {
                        continue;
                    }
                    let expected_owner_signing_pk = Self::offline_receive_owner_signing_pk(
                        &shared,
                        descriptor_binding,
                        kem_ct,
                        decoded.note.value,
                        &material.chain_id,
                    );
                    if decoded.note.owner_signing_pk != expected_owner_signing_pk {
                        continue;
                    }
                }
            }
            if shielded::note_key_commitment(&decoded.note_key) != decoded.note.note_key_commitment
            {
                bail!("shielded output note key does not match the commitment");
            }
            return Ok(Some((decoded, material.key_id)));
        }
        Ok(None)
    }

    fn decrypt_shielded_output(
        &self,
        output: &ShieldedOutput,
    ) -> Result<Option<(ShieldedOutputPlaintext, [u8; 32])>> {
        self.decrypt_shielded_payload(
            &output.note_commitment,
            &output.kem_ct,
            &output.nonce,
            output.view_tag,
            &output.ciphertext,
        )
    }

    fn decrypt_compact_shielded_output(
        &self,
        output: &CompactShieldedOutput,
    ) -> Result<Option<(ShieldedOutputPlaintext, [u8; 32])>> {
        self.decrypt_shielded_payload(
            &output.note_commitment,
            &output.kem_ct,
            &output.nonce,
            output.detection_tag,
            &output.ciphertext,
        )
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

    fn rescan_compact_shielded_outputs(&self, outputs: &[CompactShieldedOutput]) -> Result<()> {
        let wallet_store = self.wallet_store()?;
        for output in outputs {
            let Some((plaintext, _receive_key_id)) =
                self.decrypt_compact_shielded_output(output)?
            else {
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
                    tx_id: output.tx_id,
                    output_index: output.output_index,
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
        let head = self.compact_wallet_sync_head()?;
        self.sync_owned_shielded_notes_to_head(&head)
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

    fn load_owned_shielded_notes_for_send_material(
        &self,
        material: &WalletSendRuntimeMaterial,
        unspent_only: bool,
    ) -> Result<Vec<OwnedShieldedNote>> {
        let wallet_store = self.wallet_store()?;
        self.sync_owned_shielded_notes_to_head(&material.compact_wallet_sync)?;
        self.load_owned_shielded_notes_local(wallet_store.as_ref(), unspent_only)
    }

    fn load_compact_wallet_scan_cursor(
        &self,
        store: &WalletStore,
    ) -> Result<Option<CompactWalletScanCursor>> {
        store.get("meta", COMPACT_WALLET_SYNC_CURSOR_KEY)
    }

    fn store_compact_wallet_scan_cursor(
        &self,
        store: &WalletStore,
        cursor: &CompactWalletScanCursor,
    ) -> Result<()> {
        store.put("meta", COMPACT_WALLET_SYNC_CURSOR_KEY, cursor)
    }

    fn apply_compact_wallet_sync_delta(&self, delta: &CompactWalletSyncDelta) -> Result<()> {
        self.materialize_owned_genesis_notes_from_compact_coins(
            delta.head.chain_id,
            &delta.committed_coins,
        )?;
        self.rescan_compact_shielded_outputs(&delta.shielded_outputs)
    }

    fn compact_wallet_sync_cursor_for_head(
        &self,
        head: &CompactWalletSyncHead,
        stored: Option<CompactWalletScanCursor>,
    ) -> CompactWalletScanCursor {
        match stored {
            Some(cursor)
                if cursor.chain_id == head.chain_id
                    && cursor.next_coin_index <= head.committed_coin_count
                    && cursor.next_output_index <= head.shielded_output_count =>
            {
                cursor
            }
            _ => CompactWalletScanCursor {
                chain_id: head.chain_id,
                next_coin_index: 0,
                next_output_index: 0,
                synced_through_anchor_num: 0,
            },
        }
    }

    fn sync_owned_shielded_notes_to_head(&self, head: &CompactWalletSyncHead) -> Result<()> {
        let wallet_store = self.wallet_store()?;
        let mut target_head = head.clone();
        let mut cursor = self.compact_wallet_sync_cursor_for_head(
            &target_head,
            self.load_compact_wallet_scan_cursor(wallet_store.as_ref())?,
        );

        while cursor.next_coin_index < target_head.committed_coin_count
            || cursor.next_output_index < target_head.shielded_output_count
        {
            let delta = self.request_compact_wallet_sync_delta(
                cursor.next_coin_index,
                cursor.next_output_index,
                COMPACT_WALLET_SYNC_MAX_COINS_PER_REQUEST,
                COMPACT_WALLET_SYNC_MAX_OUTPUTS_PER_REQUEST,
            )?;
            if delta.head.chain_id != target_head.chain_id {
                bail!("compact wallet sync chain_id changed during delta scan");
            }
            self.apply_compact_wallet_sync_delta(&delta)?;

            let next_coin_index = delta
                .committed_coins
                .last()
                .map(|coin| coin.scan_index.saturating_add(1))
                .unwrap_or(cursor.next_coin_index);
            let next_output_index = delta
                .shielded_outputs
                .last()
                .map(|output| output.scan_index.saturating_add(1))
                .unwrap_or(cursor.next_output_index);

            if next_coin_index == cursor.next_coin_index
                && next_output_index == cursor.next_output_index
                && (cursor.next_coin_index < delta.head.committed_coin_count
                    || cursor.next_output_index < delta.head.shielded_output_count)
            {
                bail!("compact wallet sync delta made no progress");
            }

            cursor.next_coin_index = next_coin_index.min(delta.head.committed_coin_count);
            cursor.next_output_index = next_output_index.min(delta.head.shielded_output_count);
            cursor.synced_through_anchor_num = delta.head.latest_finalized_anchor_num;
            self.store_compact_wallet_scan_cursor(wallet_store.as_ref(), &cursor)?;
            target_head = delta.head;
        }

        cursor.synced_through_anchor_num = target_head.latest_finalized_anchor_num;
        self.store_compact_wallet_scan_cursor(wallet_store.as_ref(), &cursor)?;
        Ok(())
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

    fn validator_pool_from_send_material(
        material: &WalletSendRuntimeMaterial,
        validator_id: ValidatorId,
    ) -> Result<crate::staking::ValidatorPool> {
        material
            .registered_validator_pools
            .iter()
            .find(|pool| pool.validator.id == validator_id)
            .cloned()
            .ok_or_else(|| anyhow!("validator pool not found"))
    }

    fn build_local_historical_extensions_from_runtime(
        &self,
        chain_id: [u8; 32],
        root_ledger: &shielded::NullifierRootLedger,
        archived_nullifier_epochs: &[shielded::ArchivedNullifierEpoch],
        requests: &[shielded::CheckpointExtensionRequest],
        rotation_round: u64,
    ) -> Result<Vec<shielded::HistoricalUnspentExtension>> {
        if requests.is_empty() {
            return Ok(Vec::new());
        }

        let provider_id = Self::local_archive_provider_id(&chain_id);
        let available_epochs = archived_nullifier_epochs
            .iter()
            .map(|archived| archived.epoch)
            .collect::<BTreeSet<_>>();
        let manifest = shielded::local_archive_provider_manifest(
            provider_id,
            root_ledger,
            crate::protocol::CURRENT.archive_shard_epoch_span,
            &available_epochs,
        )?;
        let directory = shielded::ArchiveDirectory::from_root_ledger_and_providers(
            root_ledger,
            crate::protocol::CURRENT.archive_shard_epoch_span,
            vec![manifest.clone()],
        )?;
        let mut server = shielded::ShieldedSyncServer::new();
        for archived in archived_nullifier_epochs {
            server.insert_archived_epoch(archived.clone())?;
        }

        let mut results = requests
            .iter()
            .map(|request| {
                if request.queries.is_empty() {
                    Ok(Some(request.local_checkpoint()?.empty_extension()))
                } else {
                    Ok(None)
                }
            })
            .collect::<Result<Vec<_>>>()?;
        let nonempty = requests
            .iter()
            .enumerate()
            .filter(|(_, request)| !request.queries.is_empty())
            .collect::<Vec<_>>();
        if nonempty.is_empty() {
            return results
                .into_iter()
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| anyhow!("missing local historical extension result"));
        }

        let batch_requests = nonempty
            .iter()
            .map(|(_, request)| (*request).clone())
            .collect::<Vec<_>>();
        let responses = server.serve_checkpoints_batch(&manifest, &batch_requests)?;
        if responses.len() != batch_requests.len() {
            bail!("local checkpoint batch response length mismatch");
        }

        for ((request_index, request), response) in nonempty.into_iter().zip(responses) {
            response.verify_against_request(request, &manifest, &directory)?;
            results[request_index] = Some(shielded::HistoricalUnspentExtension::aggregate(
                request.local_checkpoint()?,
                vec![response.rerandomize(request.presentation.blinding)],
                Self::local_extension_aggregate_blinding(
                    &chain_id,
                    rotation_round,
                    &request.request_binding(),
                ),
            )?);
        }

        results
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| anyhow!("missing aggregated local historical extension"))
    }

    async fn refresh_owned_shielded_checkpoints_with_runtime(
        &self,
        notes: &mut [OwnedShieldedNote],
        chain_id: [u8; 32],
        current_epoch: u64,
        root_ledger: &shielded::NullifierRootLedger,
        archived_nullifier_epochs: &[shielded::ArchivedNullifierEpoch],
        rotation_round: u64,
    ) -> Result<()> {
        let wallet_store = self.wallet_store()?;
        let Some(through_epoch) = current_epoch.checked_sub(1) else {
            return Ok(());
        };

        let prepared_requests =
            self.prepare_owned_checkpoint_requests(notes, through_epoch, chain_id)?;
        let requests = prepared_requests
            .iter()
            .map(|(_, _, request)| request.clone())
            .collect::<Vec<_>>();

        if requests.is_empty() {
            return Ok(());
        }

        let extensions = self.build_local_historical_extensions_from_runtime(
            chain_id,
            root_ledger,
            archived_nullifier_epochs,
            &requests,
            rotation_round,
        )?;

        for (request_index, (note_index, request_checkpoint, _)) in
            prepared_requests.into_iter().enumerate()
        {
            if !extensions[request_index].strata.is_empty() {
                let accumulator = self
                    .prove_checkpoint_accumulator_with_backend(
                        &request_checkpoint,
                        &extensions[request_index],
                        notes[note_index].checkpoint_accumulator.as_ref(),
                    )
                    .await?;
                notes[note_index].checkpoint =
                    request_checkpoint.apply_accumulator(&accumulator.journal, root_ledger)?;
                notes[note_index].checkpoint_accumulator = Some(accumulator);
            }
            self.store_owned_note_record(wallet_store.as_ref(), &notes[note_index])?;
            self.store_checkpoint_record(wallet_store.as_ref(), &notes[note_index].checkpoint)?;
        }
        Ok(())
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
            let change_receive_kem_pk = self.mint_internal_receive_kem_public_key_for_chain(
                snapshot.chain_id,
                &send_seed,
                0,
                b"fee-payment-change",
            )?;
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

    pub async fn submit_cover_traffic_once(&self) -> Result<[u8; 32]> {
        self.require_ingress_client()?.submit_cover().await
    }

    pub async fn run_cover_traffic_loop(
        self: Arc<Self>,
        interval_secs: u64,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) -> Result<()> {
        if interval_secs == 0 {
            return Ok(());
        }
        let offset_secs = self.fixed_cadence_refresh_offset_secs(interval_secs);
        if offset_secs > 0 {
            tokio::select! {
                _ = shutdown_rx.recv() => return Ok(()),
                _ = time::sleep(Duration::from_secs(offset_secs)) => {}
            }
        }
        let mut interval = time::interval(Duration::from_secs(interval_secs.max(1)));
        interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => break,
                _ = interval.tick() => {
                    if let Err(err) = self.submit_cover_traffic_once().await {
                        eprintln!("wallet ingress cover submission failed: {err}");
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn run_oblivious_refresh_cycle(&self) -> Result<()> {
        let wallet_store = self.wallet_store()?;
        let material = self.wallet_send_runtime_material_async().await?;
        let mut notes = self.load_owned_shielded_notes_for_send_material(&material, true)?;
        let rotation_round = self.next_shielded_sync_round(wallet_store.as_ref())?;
        if !notes.is_empty() {
            self.refresh_owned_shielded_checkpoints_with_runtime(
                &mut notes,
                material.compact_wallet_sync.chain_id,
                material.compact_wallet_sync.current_nullifier_epoch,
                &material.root_ledger,
                &material.archived_nullifier_epochs,
                rotation_round,
            )
            .await?;
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

    fn offline_receive_value_tag(value: u64) -> [u8; 15] {
        let mut tag = [0u8; 15];
        tag[..7].copy_from_slice(b"payment");
        tag[7..15].copy_from_slice(&value.to_le_bytes());
        tag
    }

    fn offline_receive_owner_signing_pk(
        shared: &[u8; 32],
        descriptor_binding: &[u8; 32],
        kem_ct: &[u8; ML_KEM_768_CT_BYTES],
        value: u64,
        chain_id: &[u8; 32],
    ) -> TaggedSigningPublicKey {
        let seed = crypto::stealth_seed_v3(
            shared,
            descriptor_binding,
            kem_ct,
            &Self::offline_receive_value_tag(value),
            chain_id,
        );
        TaggedSigningPublicKey::from_ml_dsa_65_array(crypto::derive_one_time_pk_bytes(seed))
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

    fn build_offline_shielded_output(
        &self,
        descriptor: &discovery::OfflineReceiveDescriptor,
        value: u64,
        birth_epoch: u64,
        entropy: &ShieldedOutputEntropy,
    ) -> Result<(
        ShieldedOutput,
        ShieldedOutputPlaintext,
        [u8; proof_core::SHIELDED_OUTPUT_ENCAPSULATION_SEED_LEN],
    )> {
        let (kem_ct, shared) = descriptor
            .scan_kem_pk
            .encapsulate_deterministic(&entropy.encapsulation_seed)?;
        let owner_signing_pk = Self::offline_receive_owner_signing_pk(
            &shared,
            &descriptor.descriptor_binding,
            &kem_ct,
            value,
            &descriptor.chain_id,
        );
        let note = shielded::ShieldedNote::new_with_kind(
            shielded::ShieldedNoteKind::Payment,
            value,
            birth_epoch,
            owner_signing_pk,
            descriptor.scan_kem_pk.clone(),
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
            .map_err(|err| anyhow!("failed to encode offline shielded output payload: {err}"))?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&shared));
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&entropy.nonce), payload_bytes.as_ref())
            .map_err(|e| anyhow!("failed to encrypt offline shielded output: {}", e))?;
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
        let mut notes = self.load_owned_shielded_notes(true, true)?;
        Self::retain_payment_notes(&mut notes);
        Ok(notes
            .into_iter()
            .fold(0u64, |sum, note| sum.saturating_add(note.note.value)))
    }

    /// Prepares a canonical shielded transaction and witness without proving it.
    pub async fn prepare_fee_payment(&self, fee_amount: u64) -> Result<PreparedShieldedTx> {
        let material = self.wallet_send_runtime_material_async().await?;
        let mut available_notes =
            self.load_owned_shielded_notes_for_send_material(&material, true)?;
        Self::retain_payment_notes(&mut available_notes);
        let rotation_round = self.next_shielded_sync_round(self.wallet_store()?.as_ref())?;
        self.refresh_owned_shielded_checkpoints_with_runtime(
            &mut available_notes,
            material.compact_wallet_sync.chain_id,
            material.compact_wallet_sync.current_nullifier_epoch,
            &material.root_ledger,
            &material.archived_nullifier_epochs,
            rotation_round,
        )
        .await?;
        self.build_fee_payment_from_snapshot_with_notes(
            &ShieldedRuntimeSnapshot {
                chain_id: material.compact_wallet_sync.chain_id,
                current_nullifier_epoch: material.compact_wallet_sync.current_nullifier_epoch,
                committed_coins: Vec::new(),
                shielded_outputs: Vec::new(),
                note_tree: material.note_tree,
                root_ledger: material.root_ledger,
                archived_nullifier_epochs: material.archived_nullifier_epochs,
            },
            available_notes,
            fee_amount,
        )
    }

    /// Prepares a canonical shielded transaction and witness without proving it.
    pub async fn prepare_shielded_send(
        &self,
        recipient_handle: &str,
        amount: u64,
    ) -> Result<PreparedShieldedTx> {
        let material = self.wallet_send_runtime_material_async().await?;
        let (
            _recipient_addr,
            recipient_signing_pk,
            receiver_kem_pk,
            _receive_key_id,
            requested_amount,
        ) = self
            .parse_recipient_handle_for_chain(
                recipient_handle,
                material.compact_wallet_sync.chain_id,
            )
            .context("Invalid receiver handle")?;
        if let Some(requested_amount) = requested_amount {
            if requested_amount != amount {
                bail!(
                    "recipient handle is constrained to amount {}, but send requested {}",
                    requested_amount,
                    amount
                );
            }
        }
        let recipient_address = recipient_signing_pk.address();
        let mut available_notes =
            self.load_owned_shielded_notes_for_send_material(&material, true)?;
        Self::retain_payment_notes(&mut available_notes);
        let rotation_round = self.next_shielded_sync_round(self.wallet_store()?.as_ref())?;
        self.refresh_owned_shielded_checkpoints_with_runtime(
            &mut available_notes,
            material.compact_wallet_sync.chain_id,
            material.compact_wallet_sync.current_nullifier_epoch,
            &material.root_ledger,
            &material.archived_nullifier_epochs,
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

        let state_binding = Self::state_binding_from_send_material(&material)?;
        let current_epoch = material.compact_wallet_sync.current_nullifier_epoch;
        let note_tree = &material.note_tree;
        let tree_root = note_tree.root();
        let chain_id = material.compact_wallet_sync.chain_id;
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
            let change_receive_kem_pk = self.mint_internal_receive_kem_public_key_for_chain(
                material.compact_wallet_sync.chain_id,
                &send_seed,
                1,
                b"payment-change",
            )?;
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

    async fn prepare_locator_send(
        &self,
        record: &DiscoveryRecord,
        amount: u64,
    ) -> Result<PreparedShieldedTx> {
        let material = self.wallet_send_runtime_material_async().await?;
        if record.chain_id != material.compact_wallet_sync.chain_id {
            bail!("locator discovery record chain_id mismatch");
        }
        let recipient_address = record.owner_signing_pk.address();
        let mut available_notes =
            self.load_owned_shielded_notes_for_send_material(&material, true)?;
        Self::retain_payment_notes(&mut available_notes);
        let rotation_round = self.next_shielded_sync_round(self.wallet_store()?.as_ref())?;
        self.refresh_owned_shielded_checkpoints_with_runtime(
            &mut available_notes,
            material.compact_wallet_sync.chain_id,
            material.compact_wallet_sync.current_nullifier_epoch,
            &material.root_ledger,
            &material.archived_nullifier_epochs,
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

        let state_binding = Self::state_binding_from_send_material(&material)?;
        let current_epoch = material.compact_wallet_sync.current_nullifier_epoch;
        let note_tree = &material.note_tree;
        let tree_root = note_tree.root();
        let chain_id = material.compact_wallet_sync.chain_id;
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
            .build_offline_shielded_output(
                &record.offline_receive,
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
            let change_receive_kem_pk = self.mint_internal_receive_kem_public_key_for_chain(
                material.compact_wallet_sync.chain_id,
                &send_seed,
                1,
                b"payment-change",
            )?;
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
        let material = self.wallet_send_runtime_material_async().await?;
        let pool = Self::validator_pool_from_send_material(&material, validator_id)?;
        let delegation_preview = pool.preview_delegation(amount)?;
        let mut available_notes =
            self.load_owned_shielded_notes_for_send_material(&material, true)?;
        Self::retain_payment_notes(&mut available_notes);
        let rotation_round = self.next_shielded_sync_round(self.wallet_store()?.as_ref())?;
        self.refresh_owned_shielded_checkpoints_with_runtime(
            &mut available_notes,
            material.compact_wallet_sync.chain_id,
            material.compact_wallet_sync.current_nullifier_epoch,
            &material.root_ledger,
            &material.archived_nullifier_epochs,
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

        let state_binding = Self::state_binding_from_send_material(&material)?;
        let current_epoch = material.compact_wallet_sync.current_nullifier_epoch;
        let note_tree = &material.note_tree;
        let tree_root = note_tree.root();
        let chain_id = material.compact_wallet_sync.chain_id;
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
        let delegated_receive_kem_pk = self.mint_internal_receive_kem_public_key_for_chain(
            material.compact_wallet_sync.chain_id,
            &send_seed,
            0,
            b"delegation-share",
        )?;
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
            let change_receive_kem_pk = self.mint_internal_receive_kem_public_key_for_chain(
                material.compact_wallet_sync.chain_id,
                &send_seed,
                1,
                b"delegation-change",
            )?;
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
        let material = self.wallet_send_runtime_material_async().await?;
        let pool = Self::validator_pool_from_send_material(&material, validator_id)?;
        let undelegation_preview = pool.preview_undelegation(
            share_amount,
            material.compact_wallet_sync.current_nullifier_epoch,
            PROTOCOL.stake_unbonding_epochs,
        )?;
        let mut available_notes =
            self.load_owned_shielded_notes_for_send_material(&material, true)?;
        Self::retain_delegation_share_notes(&mut available_notes, validator_id);
        let rotation_round = self.next_shielded_sync_round(self.wallet_store()?.as_ref())?;
        self.refresh_owned_shielded_checkpoints_with_runtime(
            &mut available_notes,
            material.compact_wallet_sync.chain_id,
            material.compact_wallet_sync.current_nullifier_epoch,
            &material.root_ledger,
            &material.archived_nullifier_epochs,
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

        let state_binding = Self::state_binding_from_send_material(&material)?;
        let current_epoch = material.compact_wallet_sync.current_nullifier_epoch;
        let note_tree = &material.note_tree;
        let tree_root = note_tree.root();
        let chain_id = material.compact_wallet_sync.chain_id;
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
        let claim_receive_kem_pk = self.mint_internal_receive_kem_public_key_for_chain(
            material.compact_wallet_sync.chain_id,
            &send_seed,
            0,
            b"undelegation-claim",
        )?;
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
            let change_receive_kem_pk = self.mint_internal_receive_kem_public_key_for_chain(
                material.compact_wallet_sync.chain_id,
                &send_seed,
                1,
                b"undelegation-change",
            )?;
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
        let material = self.wallet_send_runtime_material_async().await?;
        let mut available_notes =
            self.load_owned_shielded_notes_for_send_material(&material, true)?;
        Self::retain_mature_unbonding_claim_notes(
            &mut available_notes,
            material.compact_wallet_sync.current_nullifier_epoch,
        );
        let rotation_round = self.next_shielded_sync_round(self.wallet_store()?.as_ref())?;
        self.refresh_owned_shielded_checkpoints_with_runtime(
            &mut available_notes,
            material.compact_wallet_sync.chain_id,
            material.compact_wallet_sync.current_nullifier_epoch,
            &material.root_ledger,
            &material.archived_nullifier_epochs,
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
        let state_binding = Self::state_binding_from_send_material(&material)?;
        let current_epoch = material.compact_wallet_sync.current_nullifier_epoch;
        let note_tree = &material.note_tree;
        let tree_root = note_tree.root();
        let chain_id = material.compact_wallet_sync.chain_id;
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
        let payout_receive_kem_pk = self.mint_internal_receive_kem_public_key_for_chain(
            material.compact_wallet_sync.chain_id,
            &send_seed,
            0,
            b"unbonding-payout",
        )?;
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
        proof: proof::TransparentProof,
    ) -> Result<SendOutcome> {
        let wallet_store = self.wallet_store()?;
        let current_binding = Self::state_binding_from_send_material(
            &self.wallet_send_runtime_material_async().await?,
        )?;
        if current_binding != prepared.state_binding {
            bail!(
                "prepared shielded transaction is stale; canonical shielded state changed, re-prepare the send"
            );
        }
        let tx = Tx::new(
            prepared.nullifiers.clone(),
            prepared.outputs,
            prepared.witness.fee_amount,
            proof,
        );
        let tx_id = self.require_ingress_client()?.submit_tx(&tx).await?;
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
        proof: proof::TransparentProof,
    ) -> Result<[u8; 32]> {
        let wallet_store = self.wallet_store()?;
        let current_binding = Self::state_binding_from_send_material(
            &self.wallet_send_runtime_material_async().await?,
        )?;
        if current_binding != prepared.state_binding {
            bail!(
                "prepared private delegation is stale; canonical shielded state changed, re-prepare the delegation"
            );
        }
        let tx = prepared.tx_with_proof(proof);
        let tx_id = self.require_ingress_client()?.submit_tx(&tx).await?;
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
        proof: proof::TransparentProof,
    ) -> Result<[u8; 32]> {
        let wallet_store = self.wallet_store()?;
        let current_binding = Self::state_binding_from_send_material(
            &self.wallet_send_runtime_material_async().await?,
        )?;
        if current_binding != prepared.state_binding {
            bail!(
                "prepared private undelegation is stale; canonical shielded state changed, re-prepare the undelegation"
            );
        }
        let tx = prepared.tx_with_proof(proof);
        let tx_id = self.require_ingress_client()?.submit_tx(&tx).await?;
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
        proof: proof::TransparentProof,
    ) -> Result<[u8; 32]> {
        let wallet_store = self.wallet_store()?;
        let current_binding = Self::state_binding_from_send_material(
            &self.wallet_send_runtime_material_async().await?,
        )?;
        if current_binding != prepared.state_binding {
            bail!(
                "prepared unbonding claim is stale; canonical shielded state changed, re-prepare the claim"
            );
        }
        let tx = prepared.tx_with_proof(proof);
        let tx_id = self.require_ingress_client()?.submit_tx(&tx).await?;
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

    pub async fn submit_shared_state_control_document(
        &self,
        document: SharedStateControlDocument,
    ) -> Result<SendOutcome> {
        let current_chain_id = self.effective_chain_id()?;
        if document.chain_id != current_chain_id {
            bail!(
                "shared-state control document targets chain {}, but the connected node is on chain {}",
                hex::encode(document.chain_id),
                hex::encode(current_chain_id),
            );
        }
        if !document.requires_fee_payment() {
            bail!(
                "shared-state control documents only support control actions without embedded shielded transfers"
            );
        }
        let prepared_fee = self
            .prepare_fee_payment(document.required_fee_amount())
            .await?;
        let proof = self.prove_shielded_tx_proof(prepared_fee.witness()).await?;
        self.submit_prepared_shared_state_control_document(document, prepared_fee, proof)
            .await
    }

    async fn submit_prepared_shared_state_control_document(
        &self,
        document: SharedStateControlDocument,
        prepared_fee: PreparedShieldedTx,
        proof: proof::TransparentProof,
    ) -> Result<SendOutcome> {
        let wallet_store = self.wallet_store()?;
        let current_material = self.wallet_send_runtime_material_async().await?;
        let current_binding = Self::state_binding_from_send_material(&current_material)?;
        if current_binding != prepared_fee.state_binding {
            bail!(
                "prepared shared-state control fee payment is stale; canonical shielded state changed, re-prepare the submission"
            );
        }
        let fee_payment = OrdinaryPrivateTransfer {
            nullifiers: prepared_fee.nullifiers.clone(),
            outputs: prepared_fee.outputs.clone(),
            fee_amount: prepared_fee.witness.fee_amount,
            proof,
        };
        let tx = document.into_tx_with_fee_payment(fee_payment)?;
        let tx_id = self.require_ingress_client()?.submit_tx(&tx).await?;
        for (owned, nullifier) in prepared_fee
            .selected_notes
            .iter()
            .zip(prepared_fee.nullifiers.iter())
        {
            self.mark_owned_note_spent(wallet_store.as_ref(), &owned.note.commitment, nullifier)?;
        }
        self.store_sent_tx_record(
            wallet_store.as_ref(),
            &tx_id,
            current_material.latest_finalized_anchor_epoch,
            0,
            prepared_fee.witness.fee_amount,
            [0u8; 32],
        )?;
        self.scan_tx_for_me(&tx)?;

        Ok(SendOutcome {
            tx_id,
            fee_amount: prepared_fee.witness.fee_amount,
            input_count: tx.input_count(),
            output_count: tx.output_count(),
        })
    }

    /// Sends a canonical shielded transaction against an explicit one-time invoice capability.
    pub async fn send_to_invoice(&self, invoice: &str, amount: u64) -> Result<SendOutcome> {
        let prepared = self.prepare_shielded_send(invoice, amount).await?;
        let proof = self.prove_shielded_tx_proof(prepared.witness()).await?;
        self.submit_prepared_shielded_send(prepared, proof).await
    }

    pub async fn send_to_locator(&self, locator: &str, amount: u64) -> Result<SendOutcome> {
        let discovery_client = self.require_discovery_client()?;
        let record = discovery_client.resolve_locator(locator).await?;
        let prepared = self.prepare_locator_send(&record, amount).await?;
        let proof = self.prove_shielded_tx_proof(prepared.witness()).await?;
        self.submit_prepared_shielded_send(prepared, proof).await
    }

    pub async fn resolve_locator_record(&self, locator: &str) -> Result<DiscoveryRecord> {
        self.require_discovery_client()?
            .resolve_locator(locator)
            .await
    }

    pub async fn request_amount_bound_handle(
        &self,
        locator: &str,
        amount: u64,
        timeout: Duration,
    ) -> Result<String> {
        self.require_discovery_client()?
            .request_handle(locator, amount, timeout)
            .await
    }

    pub fn discovery_replica_count(&self) -> usize {
        self.discovery_client
            .as_ref()
            .map(|client| client.mirror_count() + 1)
            .unwrap_or(0)
    }

    pub async fn service_discovery_mailbox_once(&self) -> Result<usize> {
        let chain_id = self.effective_chain_id()?;
        let material = self.discovery_mailbox_material_for_chain(chain_id)?;
        let discovery_client = self.require_discovery_client()?;
        let messages = discovery_client
            .poll_mailbox(material.mailbox_id, material.mailbox_auth_token, 32)
            .await?;
        for message in &messages {
            let request =
                discovery::open_handle_request(&message.envelope, &material.mailbox_kem_sk)
                    .context("open discovery mailbox request")?;
            if request.chain_id != chain_id || request.locator_id != material.locator_id {
                continue;
            }
            if Self::now_unix_ms() >= request.expires_unix_ms {
                continue;
            }
            let handle_json =
                self.mint_invoice_for_chain(chain_id, Some(request.requested_amount))?;
            let handle: RecipientHandle =
                serde_json::from_str(&handle_json).context("decode minted handle")?;
            let response = HandleResponsePlaintext {
                version: 1,
                chain_id,
                locator_id: material.locator_id,
                request_id: request.request_id,
                handle,
                issued_unix_ms: Self::now_unix_ms(),
            };
            let response_envelope =
                discovery::seal_handle_response(&response, &request.response_kem_pk)?;
            discovery_client
                .post_handle_response(
                    request.response_slot_id,
                    request.response_auth_token,
                    response_envelope,
                )
                .await?;
        }
        Ok(messages.len())
    }

    pub async fn run_discovery_loop(
        &self,
        publish_interval: Duration,
        poll_interval: Duration,
        record_ttl: Duration,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) -> Result<()> {
        let mut publish_tick = time::interval(publish_interval);
        let mut poll_tick = time::interval(poll_interval);
        publish_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        poll_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        self.publish_locator(record_ttl).await?;
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => break,
                _ = publish_tick.tick() => {
                    if let Err(err) = self.publish_locator(record_ttl).await {
                        eprintln!("discovery publish failed: {err}");
                    }
                }
                _ = poll_tick.tick() => {
                    if let Err(err) = self.service_discovery_mailbox_once().await {
                        eprintln!("discovery mailbox service failed: {err}");
                    }
                }
            }
        }
        Ok(())
    }

    /// Sends using a PIR-resolved wallet locator.
    pub async fn send(&self, locator: &str, amount: u64) -> Result<SendOutcome> {
        self.send_to_locator(locator, amount).await
    }

    pub async fn delegate_to_validator(
        &self,
        validator_id: ValidatorId,
        amount: u64,
    ) -> Result<[u8; 32]> {
        let prepared = self
            .prepare_private_delegation(validator_id, amount)
            .await?;
        let proof = self
            .prove_private_delegation_proof(prepared.witness())
            .await?;
        self.submit_prepared_private_delegation(prepared, proof)
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
        let proof = self
            .prove_private_undelegation_proof(prepared.witness())
            .await?;
        self.submit_prepared_private_undelegation(prepared, proof)
            .await
    }

    pub async fn claim_mature_unbondings(&self) -> Result<[u8; 32]> {
        let prepared = self.prepare_unbonding_claims().await?;
        let proof = self.prove_unbonding_claim_proof(prepared.witness()).await?;
        self.submit_prepared_unbonding_claim(prepared, proof).await
    }

    /// Gets the transaction history for this wallet
    pub fn get_transaction_history(&self) -> Result<Vec<TransactionRecord>> {
        let store = self.wallet_store()?;
        self.sync_owned_shielded_notes()?;
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

    pub(crate) fn observed_state_for_compact_head(
        &self,
        head: &CompactWalletSyncHead,
    ) -> Result<WalletObservedState> {
        let wallet_store = self.wallet_store()?;
        self.sync_owned_shielded_notes_to_head(head)?;
        let notes = self.load_owned_shielded_notes_local(wallet_store.as_ref(), true)?;
        let history = self.transaction_history_from_local(wallet_store.as_ref())?;
        Ok(WalletObservedState {
            address: self.address,
            chain_id: head.chain_id,
            current_nullifier_epoch: head.current_nullifier_epoch,
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
    fn minted_invoices_are_single_use_and_signed() -> Result<()> {
        let _passphrase = EnvGuard::set("WALLET_PASSPHRASE", "unit-test-wallet-passphrase");
        let tempdir = TempDir::new()?;
        let wallet_store = Arc::new(WalletStore::open(&tempdir.path().to_string_lossy())?);
        let wallet = Wallet::load_or_create_private(wallet_store.clone())?;
        let chain_id = [7u8; 32];

        let handle_a = wallet.mint_invoice_for_chain(chain_id, None)?;
        let handle_b = wallet.mint_invoice_for_chain(chain_id, None)?;
        let doc_a = Wallet::parse_recipient_handle_document(&handle_a)?;
        let doc_b = Wallet::parse_recipient_handle_document(&handle_b)?;

        assert_eq!(doc_a.chain_id, chain_id);
        assert_eq!(doc_a.chain_id, doc_b.chain_id);
        assert_eq!(doc_a.requested_amount, None);
        assert_eq!(doc_b.requested_amount, None);
        assert_ne!(doc_a.signing_pk, doc_b.signing_pk);
        assert_ne!(doc_a.receive_key_id, doc_b.receive_key_id);
        assert_ne!(doc_a.kem_pk, doc_b.kem_pk);
        assert_ne!(doc_a.signing_pk, wallet.public_key().clone());
        assert_ne!(doc_b.signing_pk, wallet.public_key().clone());
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
    fn expired_receive_keys_are_pruned_before_new_invoices_are_minted() -> Result<()> {
        let _passphrase = EnvGuard::set("WALLET_PASSPHRASE", "unit-test-wallet-passphrase");
        let tempdir = TempDir::new()?;
        let wallet_store = Arc::new(WalletStore::open(&tempdir.path().to_string_lossy())?);
        let wallet = Wallet::load_or_create_private(wallet_store.clone())?;
        let chain_id = [9u8; 32];

        let original_handle = wallet.mint_invoice_for_chain(chain_id, None)?;
        let original_doc = Wallet::parse_recipient_handle_document(&original_handle)?;
        let mut expired = wallet
            .load_receive_key_record(wallet_store.as_ref(), &original_doc.receive_key_id)?
            .ok_or_else(|| anyhow!("missing receive key record"))?;
        expired.expires_unix_ms = 0;
        expired.retention_expires_unix_ms = 0;
        wallet.store_receive_key_record(wallet_store.as_ref(), &expired)?;

        let rotated_handle = wallet.mint_invoice_for_chain(chain_id, None)?;
        let rotated_doc = Wallet::parse_recipient_handle_document(&rotated_handle)?;
        assert_ne!(original_doc.receive_key_id, rotated_doc.receive_key_id);
        assert_ne!(original_doc.signing_pk, rotated_doc.signing_pk);
        assert!(wallet
            .load_receive_key_record(wallet_store.as_ref(), &original_doc.receive_key_id)?
            .is_none());
        assert!(wallet
            .load_receive_key_record(wallet_store.as_ref(), &rotated_doc.receive_key_id)?
            .is_some());
        Ok(())
    }

    #[test]
    fn minted_invoice_can_bind_an_exact_amount() -> Result<()> {
        let _passphrase = EnvGuard::set("WALLET_PASSPHRASE", "unit-test-wallet-passphrase");
        let tempdir = TempDir::new()?;
        let wallet_store = Arc::new(WalletStore::open(&tempdir.path().to_string_lossy())?);
        let wallet = Wallet::load_or_create_private(wallet_store)?;
        let chain_id = [10u8; 32];

        let handle = wallet.mint_invoice_for_chain(chain_id, Some(77))?;
        let doc = Wallet::parse_recipient_handle_document(&handle)?;
        assert_eq!(doc.chain_id, chain_id);
        assert_eq!(doc.requested_amount, Some(77));
        Ok(())
    }

    #[test]
    fn offline_receive_outputs_decrypt_via_descriptor_binding() -> Result<()> {
        let _passphrase = EnvGuard::set("WALLET_PASSPHRASE", "unit-test-wallet-passphrase");
        let sender_dir = TempDir::new()?;
        let receiver_dir = TempDir::new()?;
        let sender_store = Arc::new(WalletStore::open(&sender_dir.path().to_string_lossy())?);
        let receiver_store = Arc::new(WalletStore::open(&receiver_dir.path().to_string_lossy())?);
        let sender = Wallet::load_or_create_private(sender_store)?;
        let receiver = Wallet::load_or_create_private(receiver_store.clone())?;
        let chain_id = [11u8; 32];

        let descriptor = receiver.mint_offline_receive_material_for_chain(
            receiver_store.as_ref(),
            chain_id,
            Duration::from_secs(60),
        )?;
        let recipient_address = receiver.public_key().address();
        let send_seed = sender.derive_send_seed(&recipient_address, 42, 0, 7, &[]);
        let entropy = sender.derive_output_entropy(&send_seed, 0);
        let (output, plaintext, _) =
            sender.build_offline_shielded_output(&descriptor, 42, 7, &entropy)?;

        let (decrypted, _receive_key_id) = receiver
            .decrypt_shielded_output(&output)?
            .ok_or_else(|| anyhow!("receiver failed to decrypt offline receive output"))?;
        assert_eq!(decrypted, plaintext);
        assert_eq!(decrypted.note.owner_kem_pk, descriptor.scan_kem_pk);
        assert_ne!(
            decrypted.note.owner_signing_pk,
            receiver.public_key().clone()
        );
        Ok(())
    }

    #[test]
    fn discovery_records_reuse_fresh_offline_descriptors_and_rotate_near_expiry() -> Result<()> {
        let _passphrase = EnvGuard::set("WALLET_PASSPHRASE", "unit-test-wallet-passphrase");
        let tempdir = TempDir::new()?;
        let wallet_store = Arc::new(WalletStore::open(&tempdir.path().to_string_lossy())?);
        let wallet = Wallet::load_or_create_private(wallet_store.clone())?;
        let chain_id = [13u8; 32];
        let record_ttl = Duration::from_secs(60);

        let (_mailbox_material, first_record) = wallet.discovery_record_for_chain_with_mode(
            chain_id,
            record_ttl,
            LocatorPublishMode::Automatic,
        )?;
        let initial_receive_keys = wallet.iterate_receive_key_records(wallet_store.as_ref())?;
        assert_eq!(initial_receive_keys.len(), 1);

        let (_mailbox_material, second_record) = wallet.discovery_record_for_chain_with_mode(
            chain_id,
            record_ttl,
            LocatorPublishMode::Automatic,
        )?;
        let reused_receive_keys = wallet.iterate_receive_key_records(wallet_store.as_ref())?;
        assert_eq!(reused_receive_keys.len(), 1);
        assert_eq!(
            first_record.offline_receive.scan_kem_pk,
            second_record.offline_receive.scan_kem_pk
        );
        assert_eq!(
            first_record.offline_receive.descriptor_binding,
            second_record.offline_receive.descriptor_binding
        );

        let mut expiring_record = reused_receive_keys
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("missing offline receive key record"))?;
        expiring_record.expires_unix_ms = Wallet::now_unix_ms().saturating_add(10);
        expiring_record.retention_expires_unix_ms =
            Wallet::offline_descriptor_retention_expires(expiring_record.expires_unix_ms);
        wallet.store_receive_key_record(wallet_store.as_ref(), &expiring_record)?;

        let (_mailbox_material, rotated_record) = wallet.discovery_record_for_chain_with_mode(
            chain_id,
            record_ttl,
            LocatorPublishMode::Automatic,
        )?;
        let rotated_receive_keys = wallet.iterate_receive_key_records(wallet_store.as_ref())?;
        assert_eq!(rotated_receive_keys.len(), 2);
        let retired_record = rotated_receive_keys
            .iter()
            .find(|record| record.key_id == expiring_record.key_id)
            .ok_or_else(|| anyhow!("missing retired offline descriptor record"))?;
        match &retired_record.mode {
            ReceiveKeyModeRecord::OfflineDescriptor { state, .. } => {
                assert_eq!(*state, OfflineReceiveDescriptorState::Retired);
            }
            ReceiveKeyModeRecord::FixedOwner { .. } => {
                bail!("expected offline descriptor record");
            }
        }
        assert_ne!(
            second_record.offline_receive.scan_kem_pk,
            rotated_record.offline_receive.scan_kem_pk
        );
        assert_ne!(
            second_record.offline_receive.descriptor_binding,
            rotated_record.offline_receive.descriptor_binding
        );
        Ok(())
    }

    #[test]
    fn compromise_rotation_marks_previous_descriptor_compromised_and_keeps_it_scannable(
    ) -> Result<()> {
        let _passphrase = EnvGuard::set("WALLET_PASSPHRASE", "unit-test-wallet-passphrase");
        let sender_dir = TempDir::new()?;
        let receiver_dir = TempDir::new()?;
        let sender_store = Arc::new(WalletStore::open(&sender_dir.path().to_string_lossy())?);
        let receiver_store = Arc::new(WalletStore::open(&receiver_dir.path().to_string_lossy())?);
        let sender = Wallet::load_or_create_private(sender_store)?;
        let receiver = Wallet::load_or_create_private(receiver_store.clone())?;
        let chain_id = [14u8; 32];
        let record_ttl = Duration::from_secs(60);

        let (_mailbox_material, first_record) = receiver.discovery_record_for_chain_with_mode(
            chain_id,
            record_ttl,
            LocatorPublishMode::Automatic,
        )?;
        let (_mailbox_material, rotated_record) = receiver.discovery_record_for_chain_with_mode(
            chain_id,
            record_ttl,
            LocatorPublishMode::CompromiseRotate,
        )?;
        assert_ne!(
            first_record.offline_receive.scan_kem_pk,
            rotated_record.offline_receive.scan_kem_pk
        );

        let records = receiver.iterate_receive_key_records(receiver_store.as_ref())?;
        assert_eq!(records.len(), 2);
        let compromised = records
            .iter()
            .find(|record| record.kem_pk == first_record.offline_receive.scan_kem_pk.bytes)
            .ok_or_else(|| anyhow!("missing compromised offline descriptor record"))?;
        match &compromised.mode {
            ReceiveKeyModeRecord::OfflineDescriptor { state, .. } => {
                assert_eq!(*state, OfflineReceiveDescriptorState::Compromised);
            }
            ReceiveKeyModeRecord::FixedOwner { .. } => bail!("expected offline descriptor record"),
        }

        let recipient_address = receiver.public_key().address();
        let send_seed = sender.derive_send_seed(&recipient_address, 19, 0, 9, &[]);
        let entropy = sender.derive_output_entropy(&send_seed, 0);
        let (output, plaintext, _) =
            sender.build_offline_shielded_output(&first_record.offline_receive, 19, 9, &entropy)?;
        let (decrypted, _receive_key_id) = receiver
            .decrypt_shielded_output(&output)?
            .ok_or_else(|| anyhow!("receiver failed to decrypt compromised-descriptor output"))?;
        assert_eq!(decrypted, plaintext);
        Ok(())
    }

    #[test]
    fn expired_offline_descriptor_records_are_pruned_after_retention_window() -> Result<()> {
        let _passphrase = EnvGuard::set("WALLET_PASSPHRASE", "unit-test-wallet-passphrase");
        let tempdir = TempDir::new()?;
        let wallet_store = Arc::new(WalletStore::open(&tempdir.path().to_string_lossy())?);
        let wallet = Wallet::load_or_create_private(wallet_store.clone())?;
        let chain_id = [15u8; 32];
        let record_ttl = Duration::from_secs(60);

        let _ = wallet.discovery_record_for_chain_with_mode(
            chain_id,
            record_ttl,
            LocatorPublishMode::Automatic,
        )?;
        let mut record = wallet
            .iterate_receive_key_records(wallet_store.as_ref())?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("missing offline descriptor record"))?;
        record.expires_unix_ms = 0;
        record.retention_expires_unix_ms = 0;
        wallet.store_receive_key_record(wallet_store.as_ref(), &record)?;

        let _ = wallet.receive_key_materials(wallet_store.as_ref())?;
        assert!(wallet
            .load_receive_key_record(wallet_store.as_ref(), &record.key_id)?
            .is_none());
        Ok(())
    }

    #[test]
    fn cover_cadence_offset_is_deterministic_per_wallet() -> Result<()> {
        let _passphrase = EnvGuard::set("WALLET_PASSPHRASE", "unit-test-wallet-passphrase");
        let tempdir = TempDir::new()?;
        let wallet_store = Arc::new(WalletStore::open(&tempdir.path().to_string_lossy())?);
        let wallet = Wallet::load_or_create_private(wallet_store)?;

        let first = wallet.fixed_cadence_refresh_offset_secs(30);
        let second = wallet.fixed_cadence_refresh_offset_secs(30);

        assert_eq!(first, second);
        assert!(first < 30);
        assert_eq!(wallet.fixed_cadence_refresh_offset_secs(1), 0);
        Ok(())
    }
}
