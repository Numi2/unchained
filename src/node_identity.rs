use crate::canonical::{self, CanonicalReader, CanonicalWriter};
use crate::crypto;
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
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

const NODE_ROOT_KEY_PATH: &str = "node_root.p8";
const NODE_ROOT_INFO_PATH: &str = "node_root_public.bin";
const NODE_AUTH_KEY_PATH: &str = "node_auth.p8";
const NODE_INGRESS_KEM_KEY_PATH: &str = "node_ingress_mlkem.bin";
const NODE_INGRESS_X25519_KEY_PATH: &str = "node_ingress_x25519.bin";
const NODE_AUTH_REQUEST_PATH: &str = "node_auth_request.bin";
const NODE_RECORD_PATH: &str = "node_record.bin";
const NODE_RECORD_VERSION: u8 = 2;
const NODE_ROOT_INFO_VERSION: u8 = 1;
const NODE_AUTH_REQUEST_VERSION: u8 = 1;
const NODE_RECORD_LIFETIME_MS: u64 = 30 * 24 * 60 * 60 * 1000;
const NODE_RECORD_RENEW_BEFORE_MS: u64 = 3 * 24 * 60 * 60 * 1000;
const NODE_RECORD_DOMAIN: &[u8] = b"unchained-node-record-v2";
const NODE_AUTH_REQUEST_DOMAIN: &[u8] = b"unchained-node-auth-request-v1";
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
    pub ingress_kem_pk: crypto::TaggedKemPublicKey,
    pub ingress_x25519_pk: [u8; 32],
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
    ingress_kem_pk: crypto::TaggedKemPublicKey,
    ingress_x25519_pk: [u8; 32],
    addresses: Vec<String>,
    issued_unix_ms: u64,
    expires_unix_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeRootInfoV1 {
    pub version: u8,
    pub node_id: [u8; 32],
    pub root_spki: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeAuthRequestV1 {
    pub version: u8,
    pub protocol_version: u32,
    pub node_id: [u8; 32],
    pub chain_id: Option<[u8; 32]>,
    pub root_spki: Vec<u8>,
    pub auth_spki: Vec<u8>,
    pub ingress_kem_pk: crypto::TaggedKemPublicKey,
    pub ingress_x25519_pk: [u8; 32],
    pub addresses: Vec<String>,
    pub issued_unix_ms: u64,
    pub sig: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct NodeAuthRequestSignableV1 {
    version: u8,
    protocol_version: u32,
    node_id: [u8; 32],
    chain_id: Option<[u8; 32]>,
    root_spki: Vec<u8>,
    auth_spki: Vec<u8>,
    ingress_kem_pk: crypto::TaggedKemPublicKey,
    ingress_x25519_pk: [u8; 32],
    addresses: Vec<String>,
    issued_unix_ms: u64,
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
    allowed_roots: HashSet<Vec<u8>>,
    required_approvals: usize,
    require_known_roots: bool,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IngressKeyMaterial {
    pub kem_public: crypto::TaggedKemPublicKey,
    pub kem_secret: [u8; crypto::ML_KEM_768_SK_BYTES],
    pub x25519_public: [u8; 32],
    pub x25519_secret: [u8; 32],
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
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(canonical::encode_node_record(self)?))
    }

    pub fn decode_compact(value: &str) -> Result<Self> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(value.trim())
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(value.trim()))
            .context("invalid base64 bootstrap record")?;
        canonical::decode_node_record(&bytes)
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
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(canonical::encode_trust_update(self)?))
    }

    pub fn decode_compact(value: &str) -> Result<Self> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(value.trim())
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(value.trim()))
            .context("invalid base64 trust update")?;
        canonical::decode_trust_update(&bytes)
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

impl NodeRootInfoV1 {
    pub fn encode_compact(&self) -> Result<String> {
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(encode_root_info(self)?))
    }

    pub fn decode_compact(value: &str) -> Result<Self> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(value.trim())
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(value.trim()))
            .context("invalid base64 root info")?;
        decode_root_info(&bytes)
    }
}

impl NodeAuthRequestV1 {
    pub fn validate(&self, now_unix_ms: u64) -> Result<()> {
        if self.version != NODE_AUTH_REQUEST_VERSION {
            bail!("unsupported auth request version {}", self.version);
        }
        if self.issued_unix_ms > now_unix_ms.saturating_add(ENVELOPE_MAX_CLOCK_SKEW_MS) {
            bail!("auth request issued in the future");
        }
        if self.addresses.is_empty() {
            bail!("auth request has no addresses");
        }
        if self.node_id != derive_node_id(&self.root_spki) {
            bail!("auth request node_id does not match root key");
        }
        let bytes = auth_request_signable_bytes(&NodeAuthRequestSignableV1::from(self.clone()))?;
        UnparsedPublicKey::new(&ML_DSA_65, self.auth_spki.as_slice())
            .verify(&bytes, self.sig.as_slice())
            .map_err(|_| anyhow!("auth request signature verification failed"))?;
        Ok(())
    }

    pub fn encode_compact(&self) -> Result<String> {
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(encode_auth_request(self)?))
    }

    pub fn decode_compact(value: &str) -> Result<Self> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(value.trim())
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(value.trim()))
            .context("invalid base64 auth request")?;
        decode_auth_request(&bytes)
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

impl From<NodeAuthRequestV1> for NodeAuthRequestSignableV1 {
    fn from(value: NodeAuthRequestV1) -> Self {
        Self {
            version: value.version,
            protocol_version: value.protocol_version,
            node_id: value.node_id,
            chain_id: value.chain_id,
            root_spki: value.root_spki,
            auth_spki: value.auth_spki,
            ingress_kem_pk: value.ingress_kem_pk,
            ingress_x25519_pk: value.ingress_x25519_pk,
            addresses: value.addresses,
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
                allowed_roots: trustees.clone(),
                trustees,
                ..Self::default()
            });
        }
        if trustees.is_empty() {
            bail!("trust updates require at least one bootstrap root");
        }
        let required_approvals = required_trust_approvals(trustees.len());
        let mut policy = Self {
            allowed_roots: trustees.clone(),
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
            if let Some(replacement_root_spki) = update.replacement_root_spki {
                policy.allowed_roots.insert(replacement_root_spki);
            }
        }
        Ok(policy)
    }

    pub fn with_strict_root_pinning(mut self, enabled: bool) -> Self {
        self.require_known_roots = enabled;
        self
    }

    pub fn ensure_record_allowed(&self, record: &NodeRecordV2) -> Result<()> {
        if self.revoked_node_ids.contains(&record.node_id) {
            bail!("node record revoked by trust policy");
        }
        if self.require_known_roots && !self.allowed_roots.contains(&record.root_spki) {
            bail!("node record root is not explicitly trusted");
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
            ingress_kem_pk: value.ingress_kem_pk,
            ingress_x25519_pk: value.ingress_x25519_pk,
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
    pub fn dir(&self) -> &Path {
        &self.dir
    }

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
        let root_info = root_info_from_key(root.as_ref())?;
        persist_root_info(&dir, &root_info)?;

        let persisted = load_persisted_record(&dir).ok();
        let now = now_unix_ms();
        let should_refresh = persisted
            .as_ref()
            .map(|record| {
                record.protocol_version != protocol_version
                    || record.chain_id != chain_id
                    || record.addresses != addresses
                    || record.root_spki != root_info.root_spki
                    || record.node_id != root_info.node_id
                    || record.expires_unix_ms.saturating_sub(now) <= NODE_RECORD_RENEW_BEFORE_MS
            })
            .unwrap_or(true);
        let auth = load_or_create_auth_key(&dir, should_refresh)?;
        let ingress = load_or_create_ingress_keys(&dir, should_refresh)?;
        let auth_spki = auth
            .public_key()
            .as_der()
            .map_err(|_| anyhow!("failed to DER-encode node auth public key"))?
            .as_ref()
            .to_vec();
        let needs_refresh = should_refresh
            || persisted
                .as_ref()
                .map(|record| {
                    record.auth_spki != auth_spki
                        || record.ingress_kem_pk != ingress.kem_public
                        || record.ingress_x25519_pk != ingress.x25519_public
                })
                .unwrap_or(true);

        let record = if needs_refresh {
            let record = sign_node_record(
                root.as_ref(),
                protocol_version,
                chain_id,
                root_info.node_id,
                root_info.root_spki.clone(),
                auth_spki,
                ingress.kem_public,
                ingress.x25519_public,
                addresses,
                now,
                now.saturating_add(NODE_RECORD_LIFETIME_MS),
            )?;
            persist_record(&dir, &record)?;
            record
        } else {
            persisted.expect("persisted record missing")
        };

        let certified_key = Arc::new(build_certified_key(auth.clone())?);

        Ok(Self {
            dir,
            node_id: root_info.node_id,
            auth_key: auth,
            certified_key,
            record,
        })
    }

    pub fn load_runtime_in_dir(
        dir: impl AsRef<Path>,
        protocol_version: u32,
        chain_id: Option<[u8; 32]>,
        addresses: Vec<String>,
    ) -> Result<Self> {
        let dir = identity_dir(dir.as_ref());
        fs::create_dir_all(&dir)?;

        let auth_path = dir.join(NODE_AUTH_KEY_PATH);
        if !auth_path.exists() {
            bail!(
                "missing runtime auth key at {}. run `unchained_node auth-prepare` first",
                auth_path.display()
            );
        }
        let record_path = dir.join(NODE_RECORD_PATH);
        if !record_path.exists() {
            bail!(
                "missing signed node record at {}. run `unchained_node auth-install` after offline signing",
                record_path.display()
            );
        }

        let auth = Arc::new(load_key(&auth_path)?);
        let ingress = load_local_ingress_key_material_in_dir(&dir)?;
        let auth_spki = auth
            .public_key()
            .as_der()
            .map_err(|_| anyhow!("failed to DER-encode node auth public key"))?
            .as_ref()
            .to_vec();
        let now = now_unix_ms();
        let mut record = load_persisted_record(&dir)?;
        record.validate(now)?;
        if record.auth_spki != auth_spki {
            bail!("runtime auth key does not match the installed signed node record");
        }
        if record.ingress_kem_pk != ingress.kem_public
            || record.ingress_x25519_pk != ingress.x25519_public
        {
            bail!("local ingress keys do not match the installed signed node record");
        }
        let needs_refresh = record.protocol_version != protocol_version
            || record.chain_id != chain_id
            || record.addresses != addresses
            || record.expires_unix_ms.saturating_sub(now) <= NODE_RECORD_RENEW_BEFORE_MS;
        if needs_refresh {
            record = refresh_runtime_record(
                &dir,
                &auth_spki,
                &ingress.kem_public,
                &ingress.x25519_public,
                protocol_version,
                chain_id,
                &addresses,
            )?;
        }
        if record.protocol_version != protocol_version {
            bail!(
                "installed node record protocol version {} does not match runtime {}",
                record.protocol_version,
                protocol_version
            );
        }
        if record.chain_id != chain_id {
            bail!("installed node record chain_id does not match local chain");
        }
        if record.addresses != addresses {
            bail!("installed node record addresses differ from configured published addresses");
        }
        let node_id = derive_node_id(&record.root_spki);
        if node_id != record.node_id {
            bail!("installed node record node_id does not match root key");
        }
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
        let refreshed =
            Self::load_runtime_in_dir(&self.dir, protocol_version, chain_id, addresses)?;
        let changed = self.record != refreshed.record
            || self.node_id != refreshed.node_id
            || self.auth_key.public_key().as_ref() != refreshed.auth_key.public_key().as_ref();
        if changed {
            *self = refreshed;
        }
        Ok(changed)
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

    pub fn sign_consensus_message(&self, message: &[u8]) -> Result<Vec<u8>> {
        let mut sig = vec![0u8; ML_DSA_65_SIGNING.signature_len()];
        let sig_len = self
            .auth_key
            .sign(message, &mut sig)
            .map_err(|_| anyhow!("failed to sign consensus message"))?;
        sig.truncate(sig_len);
        Ok(sig)
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

pub fn validator_from_record(
    record: &NodeRecordV2,
    voting_power: u64,
) -> Result<crate::consensus::Validator> {
    crate::consensus::Validator::new(
        voting_power,
        crate::consensus::ValidatorKeys {
            hot_ml_dsa_65_spki: record.auth_spki.clone(),
            cold_governance_key: record.root_spki.clone(),
        },
    )
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
    let identity = NodeIdentity::load_runtime_in_dir(dir, protocol_version, chain_id, addresses)?;
    Ok((
        hex::encode(identity.node_id()),
        identity.record().encode_compact()?,
    ))
}

pub fn load_local_runtime_record_in_dir(
    dir: impl AsRef<Path>,
    protocol_version: u32,
    chain_id: Option<[u8; 32]>,
    addresses: Vec<String>,
) -> Result<NodeRecordV2> {
    Ok(
        NodeIdentity::load_runtime_in_dir(dir, protocol_version, chain_id, addresses)?
            .record()
            .clone(),
    )
}

pub fn load_local_ingress_key_material_in_dir(dir: impl AsRef<Path>) -> Result<IngressKeyMaterial> {
    let dir = identity_dir(dir.as_ref());
    fs::create_dir_all(&dir)?;
    let kem_secret = load_raw_secret_key(
        &dir.join(NODE_INGRESS_KEM_KEY_PATH),
        crypto::ML_KEM_768_SK_BYTES,
    )?;
    let kem_public = crypto::TaggedKemPublicKey::from_ml_kem_768_bytes(&load_raw_secret_key(
        &dir.join(NODE_INGRESS_KEM_KEY_PATH).with_extension("pub"),
        crypto::ML_KEM_768_PK_BYTES,
    )?)?;
    let x25519_secret = load_raw_secret_key(&dir.join(NODE_INGRESS_X25519_KEY_PATH), 32)?;
    let x25519_public = load_raw_secret_key(
        &dir.join(NODE_INGRESS_X25519_KEY_PATH).with_extension("pub"),
        32,
    )?;
    Ok(IngressKeyMaterial {
        kem_public,
        kem_secret: kem_secret
            .try_into()
            .map_err(|_| anyhow!("invalid stored ingress ML-KEM secret length"))?,
        x25519_public: x25519_public
            .try_into()
            .map_err(|_| anyhow!("invalid stored ingress X25519 public length"))?,
        x25519_secret: x25519_secret
            .try_into()
            .map_err(|_| anyhow!("invalid stored ingress X25519 secret length"))?,
    })
}

pub fn sign_with_local_root_in_dir(dir: impl AsRef<Path>, msg: &[u8]) -> Result<Vec<u8>> {
    let dir = identity_dir(dir.as_ref());
    fs::create_dir_all(&dir)?;
    let path = dir.join(NODE_ROOT_KEY_PATH);
    if !path.exists() {
        bail!(
            "local node root key is missing at {}; run `unchained_node init-root` first",
            path.display()
        );
    }
    let root = load_key(&path)?;
    crypto::ml_dsa_65_sign(&root, msg)
}

pub fn load_local_node_id() -> Result<String> {
    load_local_node_id_in_dir(".")
}

pub fn load_local_node_id_in_dir(dir: impl AsRef<Path>) -> Result<String> {
    let dir = identity_dir(dir.as_ref());
    fs::create_dir_all(&dir)?;
    if let Ok(record) = load_persisted_record(&dir) {
        return Ok(hex::encode(record.node_id));
    }
    if let Ok(info) = load_root_info(&dir) {
        return Ok(hex::encode(info.node_id));
    }
    if dir.join(NODE_ROOT_KEY_PATH).exists() {
        let root = load_key(&dir.join(NODE_ROOT_KEY_PATH))?;
        let root_spki = root
            .public_key()
            .as_der()
            .map_err(|_| anyhow!("failed to DER-encode node root public key"))?;
        return Ok(hex::encode(derive_node_id(root_spki.as_ref())));
    }
    bail!("no node identity present; run `unchained_node init-root` and the auth ceremony first")
}

pub fn init_root_in_dir(dir: impl AsRef<Path>) -> Result<(String, String)> {
    let dir = identity_dir(dir.as_ref());
    fs::create_dir_all(&dir)?;
    let root = if dir.join(NODE_ROOT_KEY_PATH).exists() {
        load_key(&dir.join(NODE_ROOT_KEY_PATH))?
    } else {
        generate_key(&dir.join(NODE_ROOT_KEY_PATH))?
    };
    let info = root_info_from_key(&root)?;
    persist_root_info(&dir, &info)?;
    Ok((hex::encode(info.node_id), info.encode_compact()?))
}

pub fn prepare_auth_request_in_dir(
    dir: impl AsRef<Path>,
    protocol_version: u32,
    chain_id: Option<[u8; 32]>,
    addresses: Vec<String>,
    root_info_source: Option<&str>,
) -> Result<(String, String)> {
    let dir = identity_dir(dir.as_ref());
    fs::create_dir_all(&dir)?;
    let root_info = if let Some(source) = root_info_source {
        let info = load_root_info_item(source)?;
        persist_root_info(&dir, &info)?;
        info
    } else {
        load_root_info(&dir)?
    };
    if addresses.is_empty() {
        bail!("auth request requires at least one published address");
    }
    let auth = Arc::new(load_or_create_key(&dir.join(NODE_AUTH_KEY_PATH))?);
    let ingress = load_or_create_ingress_keys(&dir, false)?;
    let auth_spki = auth_spki_from_key(auth.as_ref())?;
    let issued_unix_ms = now_unix_ms();
    let signable = NodeAuthRequestSignableV1 {
        version: NODE_AUTH_REQUEST_VERSION,
        protocol_version,
        node_id: root_info.node_id,
        chain_id,
        root_spki: root_info.root_spki.clone(),
        auth_spki: auth_spki.clone(),
        ingress_kem_pk: ingress.kem_public.clone(),
        ingress_x25519_pk: ingress.x25519_public,
        addresses: addresses.clone(),
        issued_unix_ms,
    };
    let signable_bytes = auth_request_signable_bytes(&signable)?;
    let mut sig = vec![0u8; ML_DSA_65_SIGNING.signature_len()];
    let sig_len = auth
        .sign(&signable_bytes, &mut sig)
        .map_err(|_| anyhow!("failed to sign auth request"))?;
    sig.truncate(sig_len);
    let request = NodeAuthRequestV1 {
        version: NODE_AUTH_REQUEST_VERSION,
        protocol_version,
        node_id: root_info.node_id,
        chain_id,
        root_spki: root_info.root_spki,
        auth_spki,
        ingress_kem_pk: ingress.kem_public,
        ingress_x25519_pk: ingress.x25519_public,
        addresses,
        issued_unix_ms,
        sig,
    };
    request.validate(now_unix_ms())?;
    persist_auth_request(&dir, &request)?;
    Ok((hex::encode(request.node_id), request.encode_compact()?))
}

pub fn sign_auth_request_in_dir(
    dir: impl AsRef<Path>,
    request_source: &str,
    lifetime_days: u64,
) -> Result<(String, String)> {
    let dir = identity_dir(dir.as_ref());
    fs::create_dir_all(&dir)?;
    let root = load_key(&dir.join(NODE_ROOT_KEY_PATH))?;
    let root_info = root_info_from_key(&root)?;
    persist_root_info(&dir, &root_info)?;
    let request = load_auth_request_item(request_source)?;
    request.validate(now_unix_ms())?;
    if request.root_spki != root_info.root_spki || request.node_id != root_info.node_id {
        bail!("auth request does not target this node root");
    }
    let days = lifetime_days.clamp(1, 3650);
    let issued_unix_ms = now_unix_ms();
    let expires_unix_ms = issued_unix_ms.saturating_add(days.saturating_mul(24 * 60 * 60 * 1000));
    let record = sign_node_record(
        &root,
        request.protocol_version,
        request.chain_id,
        root_info.node_id,
        root_info.root_spki,
        request.auth_spki,
        request.ingress_kem_pk,
        request.ingress_x25519_pk,
        request.addresses,
        issued_unix_ms,
        expires_unix_ms,
    )?;
    Ok((hex::encode(record.node_id), record.encode_compact()?))
}

pub fn install_node_record_in_dir(
    dir: impl AsRef<Path>,
    record_source: &str,
) -> Result<(String, String)> {
    let dir = identity_dir(dir.as_ref());
    fs::create_dir_all(&dir)?;
    let record = load_node_record_item(record_source)?;
    record.validate(now_unix_ms())?;
    let auth = load_key(&dir.join(NODE_AUTH_KEY_PATH)).map_err(|_| {
        anyhow!("missing runtime auth key; run `unchained_node auth-prepare` first")
    })?;
    let auth_spki = auth_spki_from_key(&auth)?;
    if auth_spki != record.auth_spki {
        bail!("record auth key does not match the local runtime auth key");
    }
    let ingress = load_local_ingress_key_material_in_dir(&dir).map_err(|_| {
        anyhow!("missing local ingress keys; run `unchained_node auth-prepare` first")
    })?;
    if ingress.kem_public != record.ingress_kem_pk
        || ingress.x25519_public != record.ingress_x25519_pk
    {
        bail!("record ingress keys do not match the local runtime ingress keys");
    }
    if let Ok(root_info) = load_root_info(&dir) {
        if root_info.node_id != record.node_id || root_info.root_spki != record.root_spki {
            bail!("record does not match the installed node root info");
        }
    }
    persist_record(&dir, &record)?;
    Ok((hex::encode(record.node_id), record.encode_compact()?))
}

pub fn create_trust_update_revoke(subject_node_id: [u8; 32]) -> Result<String> {
    TrustUpdateV1::new_revocation(subject_node_id).encode_compact()
}

pub fn create_trust_update_replace(
    subject_node_id: [u8; 32],
    replacement_source: &str,
) -> Result<String> {
    let replacement = load_node_record_item(replacement_source)?;
    TrustUpdateV1::new_replacement(subject_node_id, &replacement).encode_compact()
}

pub fn approve_trust_update_in_dir(dir: impl AsRef<Path>, update_source: &str) -> Result<String> {
    let dir = identity_dir(dir.as_ref());
    let root = load_key(&dir.join(NODE_ROOT_KEY_PATH))
        .map_err(|_| anyhow!("missing node root key; run `unchained_node init-root` first"))?;
    let root_info = root_info_from_key(&root)?;
    let mut update = load_trust_update(update_source)?;
    let signable = trust_update_signable_bytes(&TrustUpdateSignableV1::from(update.clone()))?;
    let mut sig = vec![0u8; ML_DSA_65_SIGNING.signature_len()];
    let sig_len = root
        .sign(&signable, &mut sig)
        .map_err(|_| anyhow!("failed to sign trust update"))?;
    sig.truncate(sig_len);
    let signer_node_id = root_info.node_id;
    if let Some(existing) = update
        .approvals
        .iter_mut()
        .find(|approval| approval.signer_node_id == signer_node_id)
    {
        existing.signer_root_spki = root_info.root_spki;
        existing.sig = sig;
    } else {
        update.approvals.push(TrustApprovalV1 {
            signer_node_id,
            signer_root_spki: root_info.root_spki,
            sig,
        });
    }
    update.encode_compact()
}

pub fn build_server_config(identity: &NodeIdentity) -> Result<rustls::ServerConfig> {
    build_server_config_with_alpn(identity, b"unchained-pq/v2", true)
}

pub fn build_server_config_with_alpn(
    identity: &NodeIdentity,
    alpn: &[u8],
    require_client_auth: bool,
) -> Result<rustls::ServerConfig> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::MLKEM768];

    let builder = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?;
    let mut config = if require_client_auth {
        builder
            .with_client_cert_verifier(Arc::new(PqClientVerifier))
            .with_cert_resolver(Arc::new(
                rustls::server::AlwaysResolvesServerRawPublicKeys::new(identity.certified_key()),
            ))
    } else {
        builder.with_no_client_auth().with_cert_resolver(Arc::new(
            rustls::server::AlwaysResolvesServerRawPublicKeys::new(identity.certified_key()),
        ))
    };
    config.alpn_protocols = vec![alpn.to_vec()];
    Ok(config)
}

pub fn build_client_config(
    identity: &NodeIdentity,
    expected_peers: Arc<ExpectedPeerStore>,
) -> Result<rustls::ClientConfig> {
    build_client_config_with_alpn(Some(identity), expected_peers, b"unchained-pq/v2")
}

pub fn build_client_config_with_alpn(
    identity: Option<&NodeIdentity>,
    expected_peers: Arc<ExpectedPeerStore>,
    alpn: &[u8],
) -> Result<rustls::ClientConfig> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    provider.kx_groups = vec![rustls::crypto::aws_lc_rs::kx_group::MLKEM768];

    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PqServerVerifier { expected_peers }));
    let mut config = if let Some(identity) = identity {
        builder.with_client_cert_resolver(Arc::new(
            rustls::client::AlwaysResolvesClientRawPublicKeys::new(identity.certified_key()),
        ))
    } else {
        builder.with_no_client_auth()
    };
    config.alpn_protocols = vec![alpn.to_vec()];
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
    if base
        .file_name()
        .map(|name| name == std::ffi::OsStr::new("node_identity"))
        .unwrap_or(false)
    {
        base.to_path_buf()
    } else {
        base.join("node_identity")
    }
}

fn load_persisted_record(dir: &Path) -> Result<NodeRecordV2> {
    let bytes = fs::read(dir.join(NODE_RECORD_PATH))?;
    canonical::decode_node_record(&bytes)
}

fn refresh_runtime_record(
    dir: &Path,
    auth_spki: &[u8],
    ingress_kem_pk: &crypto::TaggedKemPublicKey,
    ingress_x25519_pk: &[u8; 32],
    protocol_version: u32,
    chain_id: Option<[u8; 32]>,
    addresses: &[String],
) -> Result<NodeRecordV2> {
    let root_path = dir.join(NODE_ROOT_KEY_PATH);
    if !root_path.exists() {
        bail!(
            "installed node record is stale for the local chain/config and the node root key is unavailable for automatic refresh"
        );
    }
    let root = load_key(&root_path)?;
    let root_info = root_info_from_key(&root)?;
    persist_root_info(dir, &root_info)?;
    let now = now_unix_ms();
    let record = sign_node_record(
        &root,
        protocol_version,
        chain_id,
        root_info.node_id,
        root_info.root_spki,
        auth_spki.to_vec(),
        ingress_kem_pk.clone(),
        *ingress_x25519_pk,
        addresses.to_vec(),
        now,
        now.saturating_add(NODE_RECORD_LIFETIME_MS),
    )?;
    persist_record(dir, &record)?;
    Ok(record)
}

fn persist_record(dir: &Path, record: &NodeRecordV2) -> Result<()> {
    let bytes = canonical::encode_node_record(record)?;
    let path = dir.join(NODE_RECORD_PATH);
    fs::write(&path, bytes)?;
    set_private_permissions(&path)?;
    Ok(())
}

fn load_root_info(dir: &Path) -> Result<NodeRootInfoV1> {
    let bytes = fs::read(dir.join(NODE_ROOT_INFO_PATH))?;
    decode_root_info(&bytes)
}

fn persist_root_info(dir: &Path, info: &NodeRootInfoV1) -> Result<()> {
    let path = dir.join(NODE_ROOT_INFO_PATH);
    fs::write(&path, encode_root_info(info)?)?;
    Ok(())
}

fn persist_auth_request(dir: &Path, request: &NodeAuthRequestV1) -> Result<()> {
    let path = dir.join(NODE_AUTH_REQUEST_PATH);
    fs::write(&path, encode_auth_request(request)?)?;
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

fn load_or_create_ingress_keys(dir: &Path, rotate: bool) -> Result<IngressKeyMaterial> {
    let kem_secret_path = dir.join(NODE_INGRESS_KEM_KEY_PATH);
    let kem_public_path = dir.join(NODE_INGRESS_KEM_KEY_PATH).with_extension("pub");
    let x25519_secret_path = dir.join(NODE_INGRESS_X25519_KEY_PATH);
    let x25519_public_path = dir.join(NODE_INGRESS_X25519_KEY_PATH).with_extension("pub");

    let regenerate = rotate
        || !kem_secret_path.exists()
        || !kem_public_path.exists()
        || !x25519_secret_path.exists()
        || !x25519_public_path.exists();
    if regenerate {
        let (kem_secret_key, kem_public_key) = crypto::ml_kem_768_generate();
        let kem_secret = crypto::ml_kem_768_secret_key_to_bytes(&kem_secret_key);
        let kem_public = crypto::TaggedKemPublicKey::from_ml_kem_768_array(kem_public_key.bytes);
        let x25519_secret = X25519StaticSecret::random_from_rng(OsRng);
        let x25519_public = X25519PublicKey::from(&x25519_secret);
        fs::write(&kem_secret_path, kem_secret)?;
        set_private_permissions(&kem_secret_path)?;
        fs::write(&kem_public_path, kem_public.bytes)?;
        set_private_permissions(&kem_public_path)?;
        fs::write(&x25519_secret_path, x25519_secret.to_bytes())?;
        set_private_permissions(&x25519_secret_path)?;
        fs::write(&x25519_public_path, x25519_public.as_bytes())?;
        set_private_permissions(&x25519_public_path)?;
    }
    load_local_ingress_key_material_in_dir(dir)
}

fn load_raw_secret_key(path: &Path, expected_len: usize) -> Result<Vec<u8>> {
    let bytes = fs::read(path).with_context(|| format!("failed to read key {}", path.display()))?;
    if bytes.len() != expected_len {
        bail!(
            "key {} has length {}, expected {}",
            path.display(),
            bytes.len(),
            expected_len
        );
    }
    Ok(bytes)
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

fn root_info_from_key(root: &PqdsaKeyPair) -> Result<NodeRootInfoV1> {
    let root_spki = root
        .public_key()
        .as_der()
        .map_err(|_| anyhow!("failed to DER-encode node root public key"))?
        .as_ref()
        .to_vec();
    Ok(NodeRootInfoV1 {
        version: NODE_ROOT_INFO_VERSION,
        node_id: derive_node_id(&root_spki),
        root_spki,
    })
}

fn auth_spki_from_key(auth_key: &PqdsaKeyPair) -> Result<Vec<u8>> {
    Ok(auth_key
        .public_key()
        .as_der()
        .map_err(|_| anyhow!("failed to DER-encode node auth public key"))?
        .as_ref()
        .to_vec())
}

fn sign_node_record(
    root: &PqdsaKeyPair,
    protocol_version: u32,
    chain_id: Option<[u8; 32]>,
    node_id: [u8; 32],
    root_spki: Vec<u8>,
    auth_spki: Vec<u8>,
    ingress_kem_pk: crypto::TaggedKemPublicKey,
    ingress_x25519_pk: [u8; 32],
    addresses: Vec<String>,
    issued_unix_ms: u64,
    expires_unix_ms: u64,
) -> Result<NodeRecordV2> {
    let signable = NodeRecordSignableV2 {
        version: NODE_RECORD_VERSION,
        protocol_version,
        node_id,
        chain_id,
        root_spki: root_spki.clone(),
        auth_spki: auth_spki.clone(),
        ingress_kem_pk: ingress_kem_pk.clone(),
        ingress_x25519_pk,
        addresses: addresses.clone(),
        issued_unix_ms,
        expires_unix_ms,
    };
    let signable_bytes = record_signable_bytes(&signable)?;
    let mut sig = vec![0u8; ML_DSA_65_SIGNING.signature_len()];
    let sig_len = root
        .sign(&signable_bytes, &mut sig)
        .map_err(|_| anyhow!("failed to sign node record"))?;
    sig.truncate(sig_len);
    Ok(NodeRecordV2 {
        version: NODE_RECORD_VERSION,
        protocol_version,
        node_id,
        chain_id,
        root_spki,
        auth_spki,
        ingress_kem_pk,
        ingress_x25519_pk,
        addresses,
        issued_unix_ms,
        expires_unix_ms,
        sig,
    })
}

fn derive_node_id(root_spki: &[u8]) -> [u8; 32] {
    *blake3::Hasher::new_derive_key("unchained-node-id-v2")
        .update(root_spki)
        .finalize()
        .as_bytes()
}

fn record_signable_bytes(signable: &NodeRecordSignableV2) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_bytes(NODE_RECORD_DOMAIN)?;
    writer.write_u8(signable.version);
    writer.write_u32(signable.protocol_version);
    writer.write_fixed(&signable.node_id);
    write_option_fixed32(&mut writer, &signable.chain_id);
    writer.write_bytes(&signable.root_spki)?;
    writer.write_bytes(&signable.auth_spki)?;
    canonical::write_tagged_kem_public_key(&mut writer, &signable.ingress_kem_pk);
    writer.write_fixed(&signable.ingress_x25519_pk);
    writer.write_vec(&signable.addresses, |writer, address| {
        writer.write_string(address)
    })?;
    writer.write_u64(signable.issued_unix_ms);
    writer.write_u64(signable.expires_unix_ms);
    Ok(writer.into_vec())
}

fn trust_update_signable_bytes(signable: &TrustUpdateSignableV1) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_bytes(TRUST_UPDATE_DOMAIN)?;
    writer.write_u8(signable.version);
    write_trust_update_action(&mut writer, &signable.action);
    writer.write_fixed(&signable.subject_node_id);
    write_option_fixed32(&mut writer, &signable.replacement_node_id);
    write_option_bytes(&mut writer, &signable.replacement_root_spki)?;
    writer.write_u64(signable.issued_unix_ms);
    Ok(writer.into_vec())
}

fn envelope_signable_bytes(signable: &EnvelopeSignable) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_bytes(ENVELOPE_DOMAIN)?;
    writer.write_u8(signable.version);
    writer.write_u32(signable.protocol_version);
    writer.write_fixed(&signable.node_id);
    write_option_fixed32(&mut writer, &signable.chain_id);
    writer.write_u64(signable.issued_unix_ms);
    writer.write_u64(signable.expires_unix_ms);
    write_option_fixed32(&mut writer, &signable.response_to_message_id);
    writer.write_fixed(&signable.nonce);
    writer.write_fixed(&signable.message_id);
    writer.write_bytes(&signable.payload)?;
    Ok(writer.into_vec())
}

fn auth_request_signable_bytes(signable: &NodeAuthRequestSignableV1) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_bytes(NODE_AUTH_REQUEST_DOMAIN)?;
    writer.write_u8(signable.version);
    writer.write_u32(signable.protocol_version);
    writer.write_fixed(&signable.node_id);
    write_option_fixed32(&mut writer, &signable.chain_id);
    writer.write_bytes(&signable.root_spki)?;
    writer.write_bytes(&signable.auth_spki)?;
    canonical::write_tagged_kem_public_key(&mut writer, &signable.ingress_kem_pk);
    writer.write_fixed(&signable.ingress_x25519_pk);
    writer.write_vec(&signable.addresses, |writer, address| {
        writer.write_string(address)
    })?;
    writer.write_u64(signable.issued_unix_ms);
    Ok(writer.into_vec())
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

fn write_option_fixed32(writer: &mut CanonicalWriter, value: &Option<[u8; 32]>) {
    writer.write_bool(value.is_some());
    if let Some(value) = value {
        writer.write_fixed(value);
    }
}

fn read_option_fixed32(reader: &mut CanonicalReader<'_>) -> Result<Option<[u8; 32]>> {
    if reader.read_bool()? {
        Ok(Some(reader.read_fixed()?))
    } else {
        Ok(None)
    }
}

fn write_option_bytes(writer: &mut CanonicalWriter, value: &Option<Vec<u8>>) -> Result<()> {
    writer.write_bool(value.is_some());
    if let Some(value) = value {
        writer.write_bytes(value)?;
    }
    Ok(())
}

fn write_trust_update_action(writer: &mut CanonicalWriter, action: &TrustUpdateAction) {
    writer.write_u8(match action {
        TrustUpdateAction::Revoke => 1,
        TrustUpdateAction::Replace => 2,
    });
}

fn encode_root_info(info: &NodeRootInfoV1) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_u8(info.version);
    writer.write_fixed(&info.node_id);
    writer.write_bytes(&info.root_spki)?;
    Ok(writer.into_vec())
}

fn decode_root_info(bytes: &[u8]) -> Result<NodeRootInfoV1> {
    let mut reader = CanonicalReader::new(bytes);
    let info = NodeRootInfoV1 {
        version: reader.read_u8()?,
        node_id: reader.read_fixed()?,
        root_spki: reader.read_bytes()?,
    };
    reader.finish()?;
    if info.version != NODE_ROOT_INFO_VERSION {
        bail!("unsupported root info version {}", info.version);
    }
    if derive_node_id(&info.root_spki) != info.node_id {
        bail!("root info node_id does not match root key");
    }
    Ok(info)
}

fn encode_auth_request(request: &NodeAuthRequestV1) -> Result<Vec<u8>> {
    let mut writer = CanonicalWriter::new();
    writer.write_u8(request.version);
    writer.write_u32(request.protocol_version);
    writer.write_fixed(&request.node_id);
    write_option_fixed32(&mut writer, &request.chain_id);
    writer.write_bytes(&request.root_spki)?;
    writer.write_bytes(&request.auth_spki)?;
    canonical::write_tagged_kem_public_key(&mut writer, &request.ingress_kem_pk);
    writer.write_fixed(&request.ingress_x25519_pk);
    writer.write_vec(&request.addresses, |writer, address| {
        writer.write_string(address)
    })?;
    writer.write_u64(request.issued_unix_ms);
    writer.write_bytes(&request.sig)?;
    Ok(writer.into_vec())
}

fn decode_auth_request(bytes: &[u8]) -> Result<NodeAuthRequestV1> {
    let mut reader = CanonicalReader::new(bytes);
    let request = NodeAuthRequestV1 {
        version: reader.read_u8()?,
        protocol_version: reader.read_u32()?,
        node_id: reader.read_fixed()?,
        chain_id: read_option_fixed32(&mut reader)?,
        root_spki: reader.read_bytes()?,
        auth_spki: reader.read_bytes()?,
        ingress_kem_pk: canonical::read_tagged_kem_public_key(&mut reader)?,
        ingress_x25519_pk: reader.read_fixed()?,
        addresses: reader.read_vec(|reader| reader.read_string())?,
        issued_unix_ms: reader.read_u64()?,
        sig: reader.read_bytes()?,
    };
    reader.finish()?;
    Ok(request)
}

pub fn load_trust_update(item: &str) -> Result<TrustUpdateV1> {
    let trimmed = item.trim();
    if Path::new(trimmed).exists() {
        let bytes = fs::read(trimmed)?;
        if let Ok(update) = canonical::decode_trust_update(&bytes) {
            return Ok(update);
        }
        let text = String::from_utf8(bytes).context("trust update file is not valid UTF-8")?;
        return TrustUpdateV1::decode_compact(text.trim());
    }
    TrustUpdateV1::decode_compact(trimmed)
}

pub fn load_node_record(item: &str) -> Result<NodeRecordV2> {
    load_node_record_item(item)
}

fn load_root_info_item(item: &str) -> Result<NodeRootInfoV1> {
    let trimmed = item.trim();
    if Path::new(trimmed).exists() {
        let bytes = fs::read(trimmed)?;
        if let Ok(info) = decode_root_info(&bytes) {
            return Ok(info);
        }
        let text = String::from_utf8(bytes).context("root info file is not valid UTF-8")?;
        return NodeRootInfoV1::decode_compact(text.trim());
    }
    NodeRootInfoV1::decode_compact(trimmed)
}

fn load_auth_request_item(item: &str) -> Result<NodeAuthRequestV1> {
    let trimmed = item.trim();
    if Path::new(trimmed).exists() {
        let bytes = fs::read(trimmed)?;
        if let Ok(request) = decode_auth_request(&bytes) {
            return Ok(request);
        }
        let text = String::from_utf8(bytes).context("auth request file is not valid UTF-8")?;
        return NodeAuthRequestV1::decode_compact(text.trim());
    }
    NodeAuthRequestV1::decode_compact(trimmed)
}

fn load_node_record_item(item: &str) -> Result<NodeRecordV2> {
    let trimmed = item.trim();
    if Path::new(trimmed).exists() {
        let bytes = fs::read(trimmed)?;
        if let Ok(record) = canonical::decode_node_record(&bytes) {
            return Ok(record);
        }
        let text = String::from_utf8(bytes).context("node record file is not valid UTF-8")?;
        return NodeRecordV2::decode_compact(text.trim());
    }
    NodeRecordV2::decode_compact(trimmed)
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
    use crate::consensus::{
        ConsensusPosition, OrderingPath, QuorumCertificate, ValidatorVote, VoteTarget,
    };
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
    fn node_record_derives_validator_and_real_consensus_vote() -> Result<()> {
        let dir = TempDir::new()?;
        let identity = NodeIdentity::load_or_create_in_dir(
            dir.path(),
            7,
            Some([8u8; 32]),
            vec!["127.0.0.1:4040".to_string()],
        )?;
        let validator = validator_from_record(identity.record(), 1)?;
        let validator_set = crate::consensus::ValidatorSet::new(0, vec![validator.clone()])?;
        let target = VoteTarget {
            position: ConsensusPosition { epoch: 0, slot: 0 },
            ordering_path: OrderingPath::DagBftSharedState,
            block_digest: [5u8; 32],
        };
        let vote = ValidatorVote {
            voter: validator.id,
            target: target.clone(),
            signature: identity.sign_consensus_message(&target.signing_bytes())?,
        };
        let qc = QuorumCertificate::from_votes(&validator_set, target, vec![vote])?;
        qc.validate(&validator_set)?;
        Ok(())
    }

    #[test]
    fn auth_ceremony_installs_runtime_identity_without_online_root_key() -> Result<()> {
        let dir = TempDir::new()?;
        let chain_id = Some([4u8; 32]);
        let addresses = vec!["127.0.0.1:4040".to_string()];

        let (node_id, root_info) = init_root_in_dir(dir.path())?;
        let (_, request) = prepare_auth_request_in_dir(
            dir.path(),
            7,
            chain_id,
            addresses.clone(),
            Some(&root_info),
        )?;
        let (_, record) = sign_auth_request_in_dir(dir.path(), &request, 30)?;
        let (installed_node_id, _) = install_node_record_in_dir(dir.path(), &record)?;
        assert_eq!(installed_node_id, node_id);

        fs::remove_file(identity_dir(dir.path()).join(NODE_ROOT_KEY_PATH))?;

        let runtime = NodeIdentity::load_runtime_in_dir(dir.path(), 7, chain_id, addresses)?;
        assert_eq!(hex::encode(runtime.node_id()), installed_node_id);
        runtime.record().validate(now_unix_ms())?;
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
