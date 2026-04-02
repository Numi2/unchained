use anyhow::{anyhow, bail, Context, Result};
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::signature::{KeyPair as _, UnparsedPublicKey};
use aws_lc_rs::unstable::signature::{PqdsaKeyPair, ML_DSA_65, ML_DSA_65_SIGNING};
use base64::Engine;
use rand::rngs::OsRng;
use rand::RngCore;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    sign::CertifiedKey, DigitallySignedStruct, DistinguishedName, Error as RustlsError,
    SignatureAlgorithm, SignatureScheme,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::{self, Debug, Formatter};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::RwLock;

const NODE_ROOT_KEY_PATH: &str = "node_root.p8";
const NODE_AUTH_KEY_PATH: &str = "node_auth.p8";
const NODE_RECORD_PATH: &str = "node_record.bin";
const NODE_RECORD_VERSION: u8 = 2;
const NODE_RECORD_LIFETIME_MS: u64 = 7 * 24 * 60 * 60 * 1000;
const NODE_RECORD_RENEW_BEFORE_MS: u64 = 12 * 60 * 60 * 1000;
const NODE_RECORD_DOMAIN: &[u8] = b"unchained-node-record-v2";
const ENVELOPE_DOMAIN: &[u8] = b"unchained-wire-envelope-v2";
const ENVELOPE_LIFETIME_MS: u64 = 30_000;
const ENVELOPE_MAX_CLOCK_SKEW_MS: u64 = 5_000;
const ENVELOPE_NONCE_BYTES: usize = 16;
const TRUST_UPDATE_VERSION: u8 = 1;
const TRUST_UPDATE_DOMAIN: &[u8] = b"unchained-trust-update-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeRecordV2 {
    pub version: u8,
    pub protocol_version: u32,
    pub node_id: [u8; 32],
    pub chain_id: Option<[u8; 32]>,
    pub root_spki: Vec<u8>,
    pub auth_spki: Vec<u8>,
    pub addresses: Vec<String>,
    pub issued_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub sig: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NodeRecordSignableV2 {
    version: u8,
    protocol_version: u32,
    node_id: [u8; 32],
    chain_id: Option<[u8; 32]>,
    root_spki: Vec<u8>,
    auth_spki: Vec<u8>,
    addresses: Vec<String>,
    issued_unix_ms: u64,
    expires_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedEnvelope {
    pub version: u8,
    pub protocol_version: u32,
    pub node_id: [u8; 32],
    pub chain_id: Option<[u8; 32]>,
    pub issued_unix_ms: u64,
    pub expires_unix_ms: u64,
    pub response_to_message_id: Option<[u8; 32]>,
    pub nonce: [u8; ENVELOPE_NONCE_BYTES],
    pub message_id: [u8; 32],
    pub payload: Vec<u8>,
    pub sig: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EnvelopeSignable {
    version: u8,
    protocol_version: u32,
    node_id: [u8; 32],
    chain_id: Option<[u8; 32]>,
    issued_unix_ms: u64,
    expires_unix_ms: u64,
    response_to_message_id: Option<[u8; 32]>,
    nonce: [u8; ENVELOPE_NONCE_BYTES],
    message_id: [u8; 32],
    payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TrustUpdateAction {
    Revoke,
    Replace,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustApprovalV1 {
    pub signer_node_id: [u8; 32],
    pub signer_root_spki: Vec<u8>,
    pub sig: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustUpdateV1 {
    pub version: u8,
    pub action: TrustUpdateAction,
    pub subject_node_id: [u8; 32],
    pub replacement_node_id: Option<[u8; 32]>,
    pub replacement_root_spki: Option<Vec<u8>>,
    pub issued_unix_ms: u64,
    pub approvals: Vec<TrustApprovalV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct TrustUpdateSignableV1 {
    version: u8,
    action: TrustUpdateAction,
    subject_node_id: [u8; 32],
    replacement_node_id: Option<[u8; 32]>,
    replacement_root_spki: Option<Vec<u8>>,
    issued_unix_ms: u64,
}

#[derive(Debug, Clone, Default)]
pub struct TrustPolicy {
    trustees: HashSet<Vec<u8>>,
    required_approvals: usize,
    revoked_node_ids: HashSet<[u8; 32]>,
    replacement_node_ids: HashMap<[u8; 32], [u8; 32]>,
}

#[derive(Clone)]
pub struct NodeIdentity {
    dir: PathBuf,
    node_id: [u8; 32],
    auth_key: Arc<PqdsaKeyPair>,
    certified_key: Arc<CertifiedKey>,
    record: NodeRecordV2,
}

impl Debug for NodeIdentity {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("node_id", &hex::encode(self.node_id))
            .field("record", &self.record)
            .finish()
    }
}

#[derive(Debug)]
pub struct ExpectedPeerStore {
    by_server_name: RwLock<HashMap<String, Vec<u8>>>,
}

impl ExpectedPeerStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            by_server_name: RwLock::new(HashMap::new()),
        })
    }

    pub fn remember(&self, record: &NodeRecordV2) {
        let mut guard = self
            .by_server_name
            .write()
            .expect("expected peer lock poisoned");
        guard.insert(record.server_name(), record.auth_spki.clone());
    }

    pub fn forget(&self, record: &NodeRecordV2) {
        let mut guard = self
            .by_server_name
            .write()
            .expect("expected peer lock poisoned");
        guard.remove(&record.server_name());
    }

    fn expected_spki(&self, server_name: &ServerName<'_>) -> Option<Vec<u8>> {
        let name = match server_name {
            ServerName::DnsName(name) => name.as_ref(),
            _ => return None,
        };
        self.by_server_name
            .read()
            .expect("expected peer lock poisoned")
            .get(name)
            .cloned()
    }
}

impl NodeRecordV2 {
    pub fn validate(&self, now_unix_ms: u64) -> Result<()> {
        if self.version != NODE_RECORD_VERSION {
            bail!("unsupported node record version {}", self.version);
        }
        if self.addresses.is_empty() {
            bail!("node record has no addresses");
        }
        if self.expires_unix_ms <= self.issued_unix_ms {
            bail!("node record expiry is not after issuance");
        }
        if self.expires_unix_ms <= now_unix_ms {
            bail!("node record expired");
        }
        if self.node_id != derive_node_id(&self.root_spki) {
            bail!("node record node_id does not match root key");
        }
        let signable = NodeRecordSignableV2::from(self.clone());
        let bytes = record_signable_bytes(&signable)?;
        UnparsedPublicKey::new(&ML_DSA_65, self.root_spki.as_slice())
            .verify(&bytes, self.sig.as_slice())
            .map_err(|_| anyhow!("node record signature verification failed"))?;
        Ok(())
    }

    pub fn server_name(&self) -> String {
        let node_hex = hex::encode(self.node_id);
        format!("nid-{}.{}.unchained", &node_hex[..32], &node_hex[32..])
    }

    pub fn primary_address(&self) -> Result<std::net::SocketAddr> {
        self.addresses
            .first()
            .ok_or_else(|| anyhow!("node record missing address"))?
            .parse()
            .context("invalid socket address in node record")
    }

    pub fn encode_compact(&self) -> Result<String> {
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bincode::serialize(self)?))
    }

    pub fn decode_compact(value: &str) -> Result<Self> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(value.trim())
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(value.trim()))
            .context("invalid base64 bootstrap record")?;
        Ok(bincode::deserialize(&bytes)?)
    }
}

impl TrustUpdateV1 {
    pub fn new_revocation(subject_node_id: [u8; 32]) -> Self {
        Self {
            version: TRUST_UPDATE_VERSION,
            action: TrustUpdateAction::Revoke,
            subject_node_id,
            replacement_node_id: None,
            replacement_root_spki: None,
            issued_unix_ms: now_unix_ms(),
            approvals: Vec::new(),
        }
    }

    pub fn new_replacement(subject_node_id: [u8; 32], replacement: &NodeRecordV2) -> Self {
        Self {
            version: TRUST_UPDATE_VERSION,
            action: TrustUpdateAction::Replace,
            subject_node_id,
            replacement_node_id: Some(replacement.node_id),
            replacement_root_spki: Some(replacement.root_spki.clone()),
            issued_unix_ms: now_unix_ms(),
            approvals: Vec::new(),
        }
    }

    pub fn encode_compact(&self) -> Result<String> {
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bincode::serialize(self)?))
    }

    pub fn decode_compact(value: &str) -> Result<Self> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(value.trim())
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(value.trim()))
            .context("invalid base64 trust update")?;
        Ok(bincode::deserialize(&bytes)?)
    }

    pub fn validate(
        &self,
        now_unix_ms: u64,
        trusted_roots: &HashSet<Vec<u8>>,
        required_approvals: usize,
    ) -> Result<()> {
        if self.version != TRUST_UPDATE_VERSION {
            bail!("unsupported trust update version {}", self.version);
        }
        if self.issued_unix_ms > now_unix_ms.saturating_add(ENVELOPE_MAX_CLOCK_SKEW_MS) {
            bail!("trust update issued in the future");
        }
        match self.action {
            TrustUpdateAction::Revoke => {
                if self.replacement_node_id.is_some() || self.replacement_root_spki.is_some() {
                    bail!("revocation update must not include replacement fields");
                }
            }
            TrustUpdateAction::Replace => {
                let replacement_node_id = self
                    .replacement_node_id
                    .ok_or_else(|| anyhow!("replacement update missing replacement node_id"))?;
                let replacement_root_spki = self
                    .replacement_root_spki
                    .as_ref()
                    .ok_or_else(|| anyhow!("replacement update missing replacement root key"))?;
                if derive_node_id(replacement_root_spki) != replacement_node_id {
                    bail!("replacement node_id does not match replacement root key");
                }
                if replacement_node_id == self.subject_node_id {
                    bail!("replacement node_id must differ from subject node_id");
                }
            }
        }
        if required_approvals == 0 {
            if !self.approvals.is_empty() {
                bail!("trust update approvals provided without configured trustees");
            }
            return Ok(());
        }
        let signable_bytes =
            trust_update_signable_bytes(&TrustUpdateSignableV1::from(self.clone()))?;
        let mut approved_by = HashSet::new();
        for approval in &self.approvals {
            if approval.signer_node_id != derive_node_id(&approval.signer_root_spki) {
                bail!("trust update signer node_id does not match signer root key");
            }
            if !trusted_roots.contains(&approval.signer_root_spki) {
                continue;
            }
            if !approved_by.insert(approval.signer_node_id) {
                continue;
            }
            UnparsedPublicKey::new(&ML_DSA_65, approval.signer_root_spki.as_slice())
                .verify(&signable_bytes, approval.sig.as_slice())
                .map_err(|_| anyhow!("trust update approval signature verification failed"))?;
        }
        if approved_by.len() < required_approvals {
            bail!(
                "trust update has {} valid approvals, requires {}",
                approved_by.len(),
                required_approvals
            );
        }
        Ok(())
    }
}

impl From<TrustUpdateV1> for TrustUpdateSignableV1 {
    fn from(value: TrustUpdateV1) -> Self {
        Self {
            version: value.version,
            action: value.action,
            subject_node_id: value.subject_node_id,
            replacement_node_id: value.replacement_node_id,
            replacement_root_spki: value.replacement_root_spki,
            issued_unix_ms: value.issued_unix_ms,
        }
    }
}

impl TrustPolicy {
    pub fn load(bootstrap_records: &[NodeRecordV2], items: &[String]) -> Result<Self> {
        let trustees = bootstrap_records
            .iter()
            .map(|record| record.root_spki.clone())
            .collect::<HashSet<_>>();
        if items.is_empty() {
            return Ok(Self {
                required_approvals: required_trust_approvals(trustees.len()),
                trustees,
                ..Self::default()
            });
        }
        if trustees.is_empty() {
            bail!("trust updates require at least one bootstrap root");
        }
        let required_approvals = required_trust_approvals(trustees.len());
        let mut policy = Self {
            trustees,
            required_approvals,
            ..Self::default()
        };
        for item in items {
            let update = load_trust_update(item)?;
            update.validate(now_unix_ms(), &policy.trustees, policy.required_approvals)?;
            policy.revoked_node_ids.insert(update.subject_node_id);
            if let Some(replacement_node_id) = update.replacement_node_id {
                policy
                    .replacement_node_ids
                    .insert(update.subject_node_id, replacement_node_id);
            }
        }
        Ok(policy)
    }

    pub fn ensure_record_allowed(&self, record: &NodeRecordV2) -> Result<()> {
        if self.revoked_node_ids.contains(&record.node_id) {
            bail!("node record revoked by trust policy");
        }
        Ok(())
    }

    pub fn replacement_for(&self, node_id: &[u8; 32]) -> Option<[u8; 32]> {
        self.replacement_node_ids.get(node_id).copied()
    }

    pub fn required_approvals(&self) -> usize {
        self.required_approvals
    }
}

impl From<NodeRecordV2> for NodeRecordSignableV2 {
    fn from(value: NodeRecordV2) -> Self {
        Self {
            version: value.version,
            protocol_version: value.protocol_version,
            node_id: value.node_id,
            chain_id: value.chain_id,
            root_spki: value.root_spki,
            auth_spki: value.auth_spki,
            addresses: value.addresses,
            issued_unix_ms: value.issued_unix_ms,
            expires_unix_ms: value.expires_unix_ms,
        }
    }
}

impl SignedEnvelope {
    pub fn new(
        identity: &NodeIdentity,
        protocol_version: u32,
        chain_id: Option<[u8; 32]>,
        payload: Vec<u8>,
    ) -> Result<Self> {
        Self::new_related(identity, protocol_version, chain_id, payload, None)
    }

    pub fn new_related(
        identity: &NodeIdentity,
        protocol_version: u32,
        chain_id: Option<[u8; 32]>,
        payload: Vec<u8>,
        response_to_message_id: Option<[u8; 32]>,
    ) -> Result<Self> {
        let issued_unix_ms = now_unix_ms();
        let expires_unix_ms = issued_unix_ms.saturating_add(ENVELOPE_LIFETIME_MS);
        let mut nonce = [0u8; ENVELOPE_NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce);
        let signable = EnvelopeSignable {
            version: NODE_RECORD_VERSION,
            protocol_version,
            node_id: identity.node_id,
            chain_id,
            issued_unix_ms,
            expires_unix_ms,
            response_to_message_id,
            nonce,
            message_id: envelope_message_id(
                protocol_version,
                chain_id,
                issued_unix_ms,
                expires_unix_ms,
                response_to_message_id,
                &nonce,
                &payload,
            ),
            payload,
        };
        let signable_bytes = envelope_signable_bytes(&signable)?;
        let mut sig = vec![0u8; ML_DSA_65_SIGNING.signature_len()];
        let sig_len = identity
            .auth_key
            .sign(&signable_bytes, &mut sig)
            .map_err(|_| anyhow!("failed to sign wire envelope"))?;
        sig.truncate(sig_len);
        Ok(Self {
            version: signable.version,
            protocol_version,
            node_id: identity.node_id,
            chain_id,
            issued_unix_ms,
            expires_unix_ms,
            response_to_message_id,
            nonce,
            message_id: signable.message_id,
            payload: signable.payload,
            sig,
        })
    }

    pub fn verify(&self, record: &NodeRecordV2, now_unix_ms: u64) -> Result<()> {
        if self.version != NODE_RECORD_VERSION {
            bail!("unsupported wire envelope version {}", self.version);
        }
        if self.node_id != record.node_id {
            bail!("wire envelope node_id does not match node record");
        }
        if self.expires_unix_ms <= self.issued_unix_ms {
            bail!("wire envelope expiry is not after issuance");
        }
        if self.expires_unix_ms.saturating_sub(self.issued_unix_ms)
            > ENVELOPE_LIFETIME_MS.saturating_add(ENVELOPE_MAX_CLOCK_SKEW_MS)
        {
            bail!("wire envelope lifetime exceeds protocol maximum");
        }
        if self.issued_unix_ms > now_unix_ms.saturating_add(ENVELOPE_MAX_CLOCK_SKEW_MS) {
            bail!("wire envelope issued in the future");
        }
        if now_unix_ms
            > self
                .expires_unix_ms
                .saturating_add(ENVELOPE_MAX_CLOCK_SKEW_MS)
        {
            bail!("wire envelope expired");
        }
        let signable = EnvelopeSignable {
            version: self.version,
            protocol_version: self.protocol_version,
            node_id: self.node_id,
            chain_id: self.chain_id,
            issued_unix_ms: self.issued_unix_ms,
            expires_unix_ms: self.expires_unix_ms,
            response_to_message_id: self.response_to_message_id,
            nonce: self.nonce,
            message_id: self.message_id,
            payload: self.payload.clone(),
        };
        let expected_id = envelope_message_id(
            self.protocol_version,
            self.chain_id,
            self.issued_unix_ms,
            self.expires_unix_ms,
            self.response_to_message_id,
            &self.nonce,
            &signable.payload,
        );
        if expected_id != self.message_id {
            bail!("wire envelope message_id mismatch");
        }
        let bytes = envelope_signable_bytes(&signable)?;
        UnparsedPublicKey::new(&ML_DSA_65, record.auth_spki.as_slice())
            .verify(&bytes, self.sig.as_slice())
            .map_err(|_| anyhow!("wire envelope signature verification failed"))?;
        Ok(())
    }
}

impl NodeIdentity {
    pub fn load_or_create(
        protocol_version: u32,
        chain_id: Option<[u8; 32]>,
        addresses: Vec<String>,
    ) -> Result<Self> {
        Self::load_or_create_in_dir(".", protocol_version, chain_id, addresses)
    }

    pub fn load_or_create_in_dir(
        dir: impl AsRef<Path>,
        protocol_version: u32,
        chain_id: Option<[u8; 32]>,
        addresses: Vec<String>,
    ) -> Result<Self> {
        let dir = identity_dir(dir.as_ref());
        fs::create_dir_all(&dir)?;

        let root = Arc::new(load_or_create_key(&dir.join(NODE_ROOT_KEY_PATH))?);
        let root_spki = root
            .public_key()
            .as_der()
            .map_err(|_| anyhow!("failed to DER-encode node root public key"))?
            .as_ref()
            .to_vec();
        let node_id = derive_node_id(&root_spki);

        let persisted = load_persisted_record(&dir).ok();
        let now = now_unix_ms();
        let should_refresh = persisted
            .as_ref()
            .map(|record| {
                record.protocol_version != protocol_version
                    || record.chain_id != chain_id
                    || record.addresses != addresses
                    || record.root_spki != root_spki
                    || record.node_id != node_id
                    || record.expires_unix_ms.saturating_sub(now) <= NODE_RECORD_RENEW_BEFORE_MS
            })
            .unwrap_or(true);
        let auth = load_or_create_auth_key(&dir, should_refresh)?;
        let auth_spki = auth
            .public_key()
            .as_der()
            .map_err(|_| anyhow!("failed to DER-encode node auth public key"))?
            .as_ref()
            .to_vec();
        let needs_refresh = should_refresh
            || persisted
                .as_ref()
                .map(|record| record.auth_spki != auth_spki)
                .unwrap_or(true);

        let record = if needs_refresh {
            let signable = NodeRecordSignableV2 {
                version: NODE_RECORD_VERSION,
                protocol_version,
                node_id,
                chain_id,
                root_spki: root_spki.clone(),
                auth_spki: auth_spki.clone(),
                addresses,
                issued_unix_ms: now,
                expires_unix_ms: now.saturating_add(NODE_RECORD_LIFETIME_MS),
            };
            let signable_bytes = record_signable_bytes(&signable)?;
            let mut sig = vec![0u8; ML_DSA_65_SIGNING.signature_len()];
            let sig_len = root
                .sign(&signable_bytes, &mut sig)
                .map_err(|_| anyhow!("failed to sign node record"))?;
            sig.truncate(sig_len);
            let record = NodeRecordV2 {
                version: signable.version,
                protocol_version,
                node_id,
                chain_id,
                root_spki: signable.root_spki,
                auth_spki: signable.auth_spki,
                addresses: signable.addresses,
                issued_unix_ms: signable.issued_unix_ms,
                expires_unix_ms: signable.expires_unix_ms,
                sig,
            };
            persist_record(&dir, &record)?;
            record
        } else {
            persisted.expect("persisted record missing")
        };

        let certified_key = Arc::new(build_certified_key(auth.clone())?);

        Ok(Self {
            dir,
            node_id,
            auth_key: auth,
            certified_key,
            record,
        })
    }

    pub fn refresh(
        &mut self,
        protocol_version: u32,
        chain_id: Option<[u8; 32]>,
        addresses: Vec<String>,
    ) -> Result<bool> {
        if self.record.protocol_version == protocol_version
            && self.record.chain_id == chain_id
            && self.record.addresses == addresses
            && self.record.expires_unix_ms.saturating_sub(now_unix_ms())
                > NODE_RECORD_RENEW_BEFORE_MS
        {
            return Ok(false);
        }
        let refreshed =
            Self::load_or_create_in_dir(&self.dir, protocol_version, chain_id, addresses)?;
        *self = refreshed;
        Ok(true)
    }

    pub fn certified_key(&self) -> Arc<CertifiedKey> {
        self.certified_key.clone()
    }

    pub fn record(&self) -> &NodeRecordV2 {
        &self.record
    }

    pub fn node_id(&self) -> [u8; 32] {
        self.node_id
    }

    pub fn approve_trust_update(&self, update: &mut TrustUpdateV1) -> Result<()> {
        let root = load_key(&self.dir.join(NODE_ROOT_KEY_PATH))?;
        let signer_root_spki = root
            .public_key()
            .as_der()
            .map_err(|_| anyhow!("failed to DER-encode node root public key"))?
            .as_ref()
            .to_vec();
        let signable = trust_update_signable_bytes(&TrustUpdateSignableV1::from(update.clone()))?;
        let mut sig = vec![0u8; ML_DSA_65_SIGNING.signature_len()];
        let sig_len = root
            .sign(&signable, &mut sig)
            .map_err(|_| anyhow!("failed to sign trust update"))?;
        sig.truncate(sig_len);
        let signer_node_id = derive_node_id(&signer_root_spki);
        if let Some(existing) = update
            .approvals
            .iter_mut()
            .find(|approval| approval.signer_node_id == signer_node_id)
        {
            existing.signer_root_spki = signer_root_spki;
            existing.sig = sig;
        } else {
            update.approvals.push(TrustApprovalV1 {
                signer_node_id,
                signer_root_spki,
                sig,
            });
        }
        Ok(())
    }
}

pub fn load_local_identity_output(
    protocol_version: u32,
    chain_id: Option<[u8; 32]>,
    addresses: Vec<String>,
) -> Result<(String, String)> {
    load_local_identity_output_in_dir(".", protocol_version, chain_id, addresses)
}

pub fn load_local_identity_output_in_dir(
    dir: impl AsRef<Path>,
    protocol_version: u32,
    chain_id: Option<[u8; 32]>,
    addresses: Vec<String>,
) -> Result<(String, String)> {
    let identity = NodeIdentity::load_or_create_in_dir(dir, protocol_version, chain_id, addresses)?;
    Ok((
        hex::encode(identity.node_id()),
        identity.record().encode_compact()?,
    ))
}

pub fn load_local_node_id() -> Result<String> {
    load_local_node_id_in_dir(".")
}

pub fn load_local_node_id_in_dir(dir: impl AsRef<Path>) -> Result<String> {
    let dir = identity_dir(dir.as_ref());
    fs::create_dir_all(&dir)?;
    let root = load_or_create_key(&dir.join(NODE_ROOT_KEY_PATH))?;
    let root_spki = root
        .public_key()
        .as_der()
        .map_err(|_| anyhow!("failed to DER-encode node root public key"))?;
    Ok(hex::encode(derive_node_id(root_spki.as_ref())))
}

pub fn build_server_config(identity: &NodeIdentity) -> Result<rustls::ServerConfig> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::MLKEM768];

    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(PqClientVerifier))
        .with_cert_resolver(Arc::new(
            rustls::server::AlwaysResolvesServerRawPublicKeys::new(identity.certified_key()),
        ));
    config.alpn_protocols = vec![b"unchained-pq/v2".to_vec()];
    Ok(config)
}

pub fn build_client_config(
    identity: &NodeIdentity,
    expected_peers: Arc<ExpectedPeerStore>,
) -> Result<rustls::ClientConfig> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::MLKEM768];

    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PqServerVerifier { expected_peers }))
        .with_client_cert_resolver(Arc::new(
            rustls::client::AlwaysResolvesClientRawPublicKeys::new(identity.certified_key()),
        ));
    config.alpn_protocols = vec![b"unchained-pq/v2".to_vec()];
    Ok(config)
}

pub fn tls_peer_spki(peer_identity: Option<Box<dyn std::any::Any>>) -> Result<Vec<u8>> {
    let certs = peer_identity
        .ok_or_else(|| anyhow!("peer did not present a raw public key"))?
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| anyhow!("unexpected peer identity type"))?;
    certs
        .first()
        .map(|cert| cert.as_ref().to_vec())
        .ok_or_else(|| anyhow!("peer raw public key missing"))
}

pub fn verify_record_matches_tls(record: &NodeRecordV2, tls_spki: &[u8]) -> Result<()> {
    if record.auth_spki != tls_spki {
        bail!("peer TLS key does not match signed node record");
    }
    Ok(())
}

fn identity_dir(base: &Path) -> PathBuf {
    base.join("node_identity")
}

fn load_persisted_record(dir: &Path) -> Result<NodeRecordV2> {
    let bytes = fs::read(dir.join(NODE_RECORD_PATH))?;
    Ok(bincode::deserialize(&bytes)?)
}

fn persist_record(dir: &Path, record: &NodeRecordV2) -> Result<()> {
    let bytes = bincode::serialize(record)?;
    let path = dir.join(NODE_RECORD_PATH);
    fs::write(&path, bytes)?;
    set_private_permissions(&path)?;
    Ok(())
}

fn load_or_create_key(path: &Path) -> Result<PqdsaKeyPair> {
    if path.exists() {
        return load_key(path);
    }
    generate_key(path)
}

fn load_key(path: &Path) -> Result<PqdsaKeyPair> {
    let bytes = fs::read(path)?;
    PqdsaKeyPair::from_pkcs8(&ML_DSA_65_SIGNING, &bytes)
        .map_err(|_| anyhow!("failed to parse ML-DSA key at {}", path.display()))
}

fn generate_key(path: &Path) -> Result<PqdsaKeyPair> {
    let key = PqdsaKeyPair::generate(&ML_DSA_65_SIGNING)
        .map_err(|_| anyhow!("failed to generate ML-DSA key"))?;
    let pkcs8 = key
        .private_key()
        .as_der()
        .map_err(|_| anyhow!("failed to encode ML-DSA private key"))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, pkcs8.as_ref())?;
    set_private_permissions(path)?;
    Ok(key)
}

fn load_or_create_auth_key(dir: &Path, rotate: bool) -> Result<Arc<PqdsaKeyPair>> {
    let path = dir.join(NODE_AUTH_KEY_PATH);
    let key = if rotate {
        generate_key(&path)?
    } else {
        load_or_create_key(&path)?
    };
    Ok(Arc::new(key))
}

fn set_private_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}

fn build_certified_key(auth_key: Arc<PqdsaKeyPair>) -> Result<CertifiedKey> {
    let signing_key = Arc::new(MlDsaSigningKey::new(auth_key)?);
    let cert = vec![CertificateDer::from(signing_key.spki.as_ref().to_vec())];
    Ok(CertifiedKey::new(cert, signing_key))
}

fn derive_node_id(root_spki: &[u8]) -> [u8; 32] {
    *blake3::Hasher::new_derive_key("unchained-node-id-v2")
        .update(root_spki)
        .finalize()
        .as_bytes()
}

fn record_signable_bytes(signable: &NodeRecordSignableV2) -> Result<Vec<u8>> {
    let mut bytes = NODE_RECORD_DOMAIN.to_vec();
    bytes.extend(bincode::serialize(signable)?);
    Ok(bytes)
}

fn trust_update_signable_bytes(signable: &TrustUpdateSignableV1) -> Result<Vec<u8>> {
    let mut bytes = TRUST_UPDATE_DOMAIN.to_vec();
    bytes.extend(bincode::serialize(signable)?);
    Ok(bytes)
}

fn envelope_signable_bytes(signable: &EnvelopeSignable) -> Result<Vec<u8>> {
    let mut bytes = ENVELOPE_DOMAIN.to_vec();
    bytes.extend(bincode::serialize(signable)?);
    Ok(bytes)
}

fn envelope_message_id(
    protocol_version: u32,
    chain_id: Option<[u8; 32]>,
    issued_unix_ms: u64,
    expires_unix_ms: u64,
    response_to_message_id: Option<[u8; 32]>,
    nonce: &[u8; ENVELOPE_NONCE_BYTES],
    payload: &[u8],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("unchained-wire-message-id-v2");
    hasher.update(&protocol_version.to_le_bytes());
    match chain_id {
        Some(chain_id) => {
            hasher.update(&[1]);
            hasher.update(&chain_id);
        }
        None => {
            hasher.update(&[0]);
        }
    }
    hasher.update(&issued_unix_ms.to_le_bytes());
    hasher.update(&expires_unix_ms.to_le_bytes());
    match response_to_message_id {
        Some(message_id) => {
            hasher.update(&[1]);
            hasher.update(&message_id);
        }
        None => {
            hasher.update(&[0]);
        }
    }
    hasher.update(nonce);
    hasher.update(payload);
    *hasher.finalize().as_bytes()
}

pub fn load_trust_update(item: &str) -> Result<TrustUpdateV1> {
    let trimmed = item.trim();
    if Path::new(trimmed).exists() {
        let bytes = fs::read(trimmed)?;
        if let Ok(update) = bincode::deserialize::<TrustUpdateV1>(&bytes) {
            return Ok(update);
        }
        let text = String::from_utf8(bytes).context("trust update file is not valid UTF-8")?;
        return parse_trust_update_text(text.trim());
    }
    parse_trust_update_text(trimmed)
}

fn parse_trust_update_text(text: &str) -> Result<TrustUpdateV1> {
    if text.starts_with('{') {
        return Ok(serde_json::from_str(text).context("invalid trust update JSON")?);
    }
    TrustUpdateV1::decode_compact(text)
}

fn required_trust_approvals(trustee_count: usize) -> usize {
    if trustee_count == 0 {
        0
    } else {
        (trustee_count * 2 + 2) / 3
    }
}

fn verify_mldsa_signature(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, RustlsError> {
    if dss.scheme != SignatureScheme::ML_DSA_65 {
        return Err(RustlsError::General(format!(
            "unsupported signature scheme {:?}",
            dss.scheme
        )));
    }
    UnparsedPublicKey::new(&ML_DSA_65, cert.as_ref())
        .verify(message, dss.signature())
        .map_err(|_| {
            RustlsError::General("ML-DSA handshake signature verification failed".into())
        })?;
    Ok(HandshakeSignatureValid::assertion())
}

#[derive(Debug)]
struct MlDsaSigningKey {
    keypair: Arc<PqdsaKeyPair>,
    spki: SubjectPublicKeyInfoDer<'static>,
}

impl MlDsaSigningKey {
    fn new(keypair: Arc<PqdsaKeyPair>) -> Result<Self> {
        let spki = SubjectPublicKeyInfoDer::from(
            keypair
                .public_key()
                .as_der()
                .map_err(|_| anyhow!("failed to DER-encode ML-DSA public key"))?
                .as_ref()
                .to_vec(),
        );
        Ok(Self { keypair, spki })
    }
}

impl rustls::sign::SigningKey for MlDsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        if offered.contains(&SignatureScheme::ML_DSA_65) {
            Some(Box::new(MlDsaSigner {
                keypair: self.keypair.clone(),
            }))
        } else {
            None
        }
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(self.spki.clone())
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Unknown(0)
    }
}

#[derive(Debug)]
struct MlDsaSigner {
    keypair: Arc<PqdsaKeyPair>,
}

impl rustls::sign::Signer for MlDsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, RustlsError> {
        let mut signature = vec![0u8; ML_DSA_65_SIGNING.signature_len()];
        let sig_len = self
            .keypair
            .sign(message, &mut signature)
            .map_err(|_| RustlsError::General("ML-DSA signing failed".into()))?;
        signature.truncate(sig_len);
        Ok(signature)
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ML_DSA_65
    }
}

#[derive(Debug)]
struct PqServerVerifier {
    expected_peers: Arc<ExpectedPeerStore>,
}

impl ServerCertVerifier for PqServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        if !intermediates.is_empty() {
            return Err(RustlsError::General(
                "raw-public-key server auth does not allow intermediates".into(),
            ));
        }
        let expected = self
            .expected_peers
            .expected_spki(server_name)
            .ok_or_else(|| {
                RustlsError::General(format!(
                    "no pinned node record for server {:?}",
                    server_name
                ))
            })?;
        if end_entity.as_ref() != expected.as_slice() {
            return Err(RustlsError::General(
                "server raw public key does not match pinned node record".into(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_mldsa_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_mldsa_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ML_DSA_65]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct PqClientVerifier;

impl ClientCertVerifier for PqClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        if !intermediates.is_empty() {
            return Err(RustlsError::General(
                "raw-public-key client auth does not allow intermediates".into(),
            ));
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_mldsa_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_mldsa_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ML_DSA_65]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn expired_record_rotates_auth_key_but_keeps_root_identity() -> Result<()> {
        let dir = TempDir::new()?;
        let chain_id = Some([9u8; 32]);
        let addresses = vec!["127.0.0.1:4040".to_string()];
        let first =
            NodeIdentity::load_or_create_in_dir(dir.path(), 7, chain_id, addresses.clone())?;

        let first_node_id = first.node_id();
        let first_root = first.record.root_spki.clone();
        let first_auth = first.record.auth_spki.clone();

        let mut expired = first.record.clone();
        expired.expires_unix_ms = now_unix_ms().saturating_sub(1);
        persist_record(&identity_dir(dir.path()), &expired)?;

        let second = NodeIdentity::load_or_create_in_dir(dir.path(), 7, chain_id, addresses)?;
        assert_eq!(second.node_id(), first_node_id);
        assert_eq!(second.record.root_spki, first_root);
        assert_ne!(second.record.auth_spki, first_auth);
        assert!(second.record.expires_unix_ms > now_unix_ms());
        second.record.validate(now_unix_ms())?;
        Ok(())
    }

    #[test]
    fn fresh_envelope_verifies_and_expired_one_is_rejected() -> Result<()> {
        let dir = TempDir::new()?;
        let identity = NodeIdentity::load_or_create_in_dir(
            dir.path(),
            7,
            Some([3u8; 32]),
            vec!["127.0.0.1:4040".to_string()],
        )?;
        let envelope = SignedEnvelope::new(&identity, 7, Some([3u8; 32]), b"hello".to_vec())?;
        envelope.verify(identity.record(), now_unix_ms())?;

        let mut expired = envelope.clone();
        expired.expires_unix_ms = expired.issued_unix_ms;
        assert!(expired.verify(identity.record(), now_unix_ms()).is_err());
        Ok(())
    }

    #[test]
    fn trust_update_requires_bootstrap_quorum() -> Result<()> {
        let trustee_a = TempDir::new()?;
        let trustee_b = TempDir::new()?;
        let trustee_c = TempDir::new()?;
        let subject_dir = TempDir::new()?;

        let trustee_a_identity = NodeIdentity::load_or_create_in_dir(
            trustee_a.path(),
            7,
            Some([7u8; 32]),
            vec!["127.0.0.1:4101".to_string()],
        )?;
        let trustee_b_identity = NodeIdentity::load_or_create_in_dir(
            trustee_b.path(),
            7,
            Some([7u8; 32]),
            vec!["127.0.0.1:4102".to_string()],
        )?;
        let trustee_c_identity = NodeIdentity::load_or_create_in_dir(
            trustee_c.path(),
            7,
            Some([7u8; 32]),
            vec!["127.0.0.1:4103".to_string()],
        )?;
        let subject_identity = NodeIdentity::load_or_create_in_dir(
            subject_dir.path(),
            7,
            Some([7u8; 32]),
            vec!["127.0.0.1:4999".to_string()],
        )?;

        let bootstrap_records = vec![
            trustee_a_identity.record().clone(),
            trustee_b_identity.record().clone(),
            trustee_c_identity.record().clone(),
        ];

        let mut update = TrustUpdateV1::new_revocation(subject_identity.node_id());
        trustee_a_identity.approve_trust_update(&mut update)?;
        assert!(TrustPolicy::load(&bootstrap_records, &[update.encode_compact()?]).is_err());

        trustee_b_identity.approve_trust_update(&mut update)?;
        let policy = TrustPolicy::load(&bootstrap_records, &[update.encode_compact()?])?;
        assert_eq!(policy.required_approvals(), 2);
        assert!(policy
            .ensure_record_allowed(subject_identity.record())
            .is_err());
        assert!(policy
            .ensure_record_allowed(trustee_c_identity.record())
            .is_ok());
        Ok(())
    }
}
