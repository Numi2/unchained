use anyhow::{anyhow, bail, Result};
use atty;
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::signature::{KeyPair as _, UnparsedPublicKey};
use aws_lc_rs::unstable::signature::{PqdsaKeyPair, PqdsaPublicKey, ML_DSA_65, ML_DSA_65_SIGNING};
use blake3::Hasher;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::EncapsulateDeterministic;
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768, B32};
use once_cell::sync::OnceCell;
use rand::rngs::OsRng;
use rcgen::{CertificateParams, KeyPair, SanType};
use rpassword;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::sync::Arc;
use webpki_roots;
use zeroize::Zeroizing;

pub const ML_DSA_65_PK_BYTES: usize = 1952;
pub const ML_DSA_65_SIG_BYTES: usize = 3309;

pub const ML_KEM_768_CT_BYTES: usize = 1088;
pub const ML_KEM_768_PK_BYTES: usize = 1184;
pub const ML_KEM_768_SK_BYTES: usize = 2400;

pub const OTP_PK_BYTES: usize = ML_DSA_65_PK_BYTES;

pub type Address = [u8; 32];

pub type MlKem768SecretKey = <MlKem768 as KemCore>::DecapsulationKey;
pub type MlKem768PublicKey = <MlKem768 as KemCore>::EncapsulationKey;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAlgorithm {
    MlDsa65,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum KemAlgorithm {
    MlKem768,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct TaggedSigningPublicKey {
    pub algorithm: SignatureAlgorithm,
    #[serde(with = "BigArray")]
    pub bytes: [u8; ML_DSA_65_PK_BYTES],
}

impl TaggedSigningPublicKey {
    pub fn from_ml_dsa_65_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ML_DSA_65_PK_BYTES {
            bail!(
                "invalid ML-DSA-65 public key length: expected {}, got {}",
                ML_DSA_65_PK_BYTES,
                bytes.len()
            );
        }
        let mut out = [0u8; ML_DSA_65_PK_BYTES];
        out.copy_from_slice(bytes);
        Ok(Self::from_ml_dsa_65_array(out))
    }

    pub fn from_ml_dsa_65_array(bytes: [u8; ML_DSA_65_PK_BYTES]) -> Self {
        Self {
            algorithm: SignatureAlgorithm::MlDsa65,
            bytes,
        }
    }

    pub fn from_public_key(public_key: &PqdsaPublicKey) -> Self {
        let mut bytes = [0u8; ML_DSA_65_PK_BYTES];
        bytes.copy_from_slice(public_key.as_ref());
        Self::from_ml_dsa_65_array(bytes)
    }

    pub fn zero_ml_dsa_65() -> Self {
        Self::from_ml_dsa_65_array([0u8; ML_DSA_65_PK_BYTES])
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub fn address(&self) -> Address {
        address_from_bytes(&self.bytes)
    }

    pub fn verify(&self, msg: &[u8], signature: &[u8]) -> Result<()> {
        match self.algorithm {
            SignatureAlgorithm::MlDsa65 => UnparsedPublicKey::new(&ML_DSA_65, self.as_slice())
                .verify(msg, signature)
                .map_err(|_| anyhow!("ML-DSA-65 signature verification failed")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct TaggedKemPublicKey {
    pub algorithm: KemAlgorithm,
    #[serde(with = "BigArray")]
    pub bytes: [u8; ML_KEM_768_PK_BYTES],
}

impl TaggedKemPublicKey {
    pub fn from_ml_kem_768_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != ML_KEM_768_PK_BYTES {
            bail!(
                "invalid ML-KEM-768 public key length: expected {}, got {}",
                ML_KEM_768_PK_BYTES,
                bytes.len()
            );
        }
        let mut out = [0u8; ML_KEM_768_PK_BYTES];
        out.copy_from_slice(bytes);
        Ok(Self::from_ml_kem_768_array(out))
    }

    pub fn from_ml_kem_768_array(bytes: [u8; ML_KEM_768_PK_BYTES]) -> Self {
        Self {
            algorithm: KemAlgorithm::MlKem768,
            bytes,
        }
    }

    pub fn zero_ml_kem_768() -> Self {
        Self::from_ml_kem_768_array([0u8; ML_KEM_768_PK_BYTES])
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub fn encapsulate(&self) -> Result<([u8; ML_KEM_768_CT_BYTES], [u8; 32])> {
        kem_encapsulate_to_ml_kem(self)
    }

    pub fn encapsulate_deterministic(
        &self,
        seed: &[u8; 32],
    ) -> Result<([u8; ML_KEM_768_CT_BYTES], [u8; 32])> {
        kem_encapsulate_to_ml_kem_deterministic(self, seed)
    }
}

// -----------------------------------------------------------------------------
// Unified passphrase handling (cached once per process)
// -----------------------------------------------------------------------------
static UNIFIED_PASSPHRASE: OnceCell<Zeroizing<String>> = OnceCell::new();

pub fn unified_passphrase(prompt: Option<&str>) -> anyhow::Result<Zeroizing<String>> {
    if let Some(existing) = UNIFIED_PASSPHRASE.get() {
        return Ok(existing.clone());
    }
    if let Ok(val) = std::env::var("QUANTUM_PASSPHRASE") {
        let z = Zeroizing::new(val);
        let _ = UNIFIED_PASSPHRASE.set(z.clone());
        return Ok(z);
    }
    if atty::is(atty::Stream::Stdin) {
        let text = prompt.unwrap_or("Enter quantum pass-phrase: ");
        let pw = rpassword::prompt_password(text)?;
        let z = Zeroizing::new(pw);
        let _ = UNIFIED_PASSPHRASE.set(z.clone());
        return Ok(z);
    }
    bail!("QUANTUM_PASSPHRASE is required in non-interactive mode")
}

pub fn address_from_pk(pk: &TaggedSigningPublicKey) -> Address {
    pk.address()
}

/// Computes an Address directly from arbitrary public bytes.
pub fn address_from_bytes(bytes: &[u8]) -> Address {
    *Hasher::new_derive_key("unchained-address")
        .update(bytes)
        .finalize()
        .as_bytes()
}

pub fn ml_dsa_65_generate() -> Result<PqdsaKeyPair> {
    PqdsaKeyPair::generate(&ML_DSA_65_SIGNING)
        .map_err(|_| anyhow!("failed to generate ML-DSA-65 keypair"))
}

pub fn ml_dsa_65_keypair_from_pkcs8(bytes: &[u8]) -> Result<PqdsaKeyPair> {
    PqdsaKeyPair::from_pkcs8(&ML_DSA_65_SIGNING, bytes)
        .map_err(|_| anyhow!("failed to decode ML-DSA-65 PKCS#8 keypair"))
}

pub fn ml_dsa_65_keypair_to_pkcs8(keypair: &PqdsaKeyPair) -> Result<Vec<u8>> {
    keypair
        .to_pkcs8()
        .map(|doc| doc.as_ref().to_vec())
        .map_err(|_| anyhow!("failed to encode ML-DSA-65 PKCS#8 keypair"))
}

pub fn ml_dsa_65_public_key(keypair: &PqdsaKeyPair) -> TaggedSigningPublicKey {
    TaggedSigningPublicKey::from_public_key(keypair.public_key())
}

pub fn ml_dsa_65_public_key_spki(keypair: &PqdsaKeyPair) -> Result<Vec<u8>> {
    keypair
        .public_key()
        .as_der()
        .map(|der| der.as_ref().to_vec())
        .map_err(|_| anyhow!("failed to DER-encode ML-DSA-65 public key"))
}

pub fn ml_dsa_65_sign(keypair: &PqdsaKeyPair, msg: &[u8]) -> Result<Vec<u8>> {
    let mut signature = vec![0u8; ML_DSA_65_SIGNING.signature_len()];
    let len = keypair
        .sign(msg, &mut signature)
        .map_err(|_| anyhow!("failed to sign with ML-DSA-65"))?;
    signature.truncate(len);
    Ok(signature)
}

pub fn ml_kem_768_generate() -> (MlKem768SecretKey, TaggedKemPublicKey) {
    let (secret_key, public_key) = MlKem768::generate(&mut OsRng);
    let encoded = public_key.as_bytes();
    let mut public_key_bytes = [0u8; ML_KEM_768_PK_BYTES];
    public_key_bytes.copy_from_slice(encoded.as_slice());
    (
        secret_key,
        TaggedKemPublicKey::from_ml_kem_768_array(public_key_bytes),
    )
}

pub fn ml_kem_768_generate_deterministic(
    d: &[u8; 32],
    z: &[u8; 32],
) -> (MlKem768SecretKey, TaggedKemPublicKey) {
    let d_seed: B32 = (*d).into();
    let z_seed: B32 = (*z).into();
    let (secret_key, public_key) = MlKem768::generate_deterministic(&d_seed, &z_seed);
    let encoded = public_key.as_bytes();
    let mut public_key_bytes = [0u8; ML_KEM_768_PK_BYTES];
    public_key_bytes.copy_from_slice(encoded.as_slice());
    (
        secret_key,
        TaggedKemPublicKey::from_ml_kem_768_array(public_key_bytes),
    )
}

pub fn ml_kem_768_secret_key_to_bytes(sk: &MlKem768SecretKey) -> [u8; ML_KEM_768_SK_BYTES] {
    let encoded = sk.as_bytes();
    let mut out = [0u8; ML_KEM_768_SK_BYTES];
    out.copy_from_slice(encoded.as_slice());
    out
}

pub fn ml_kem_768_secret_key_from_bytes(bytes: &[u8; ML_KEM_768_SK_BYTES]) -> MlKem768SecretKey {
    let encoded = Encoded::<MlKem768SecretKey>::try_from(&bytes[..])
        .expect("ML-KEM-768 secret key bytes have fixed width");
    MlKem768SecretKey::from_bytes(&encoded)
}

fn ml_kem_768_public_key_from_tagged(pk: &TaggedKemPublicKey) -> MlKem768PublicKey {
    let encoded = Encoded::<MlKem768PublicKey>::try_from(&pk.bytes[..])
        .expect("ML-KEM-768 public key bytes have fixed width");
    MlKem768PublicKey::from_bytes(&encoded)
}

fn ml_kem_768_ciphertext_from_bytes(
    bytes: &[u8; ML_KEM_768_CT_BYTES],
) -> ml_kem::Ciphertext<MlKem768> {
    ml_kem::Ciphertext::<MlKem768>::try_from(&bytes[..])
        .expect("ML-KEM-768 ciphertext bytes have fixed width")
}

/// Hashes arbitrary data with a domain-specific key for internal consistency.
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *Hasher::new_derive_key("unchained-v1")
        .update(data)
        .finalize()
        .as_bytes()
}

/// Derive deterministic one-time "public key" bytes from a 32-byte seed.
pub fn derive_one_time_pk_bytes(seed32: [u8; 32]) -> [u8; OTP_PK_BYTES] {
    let mut hasher = blake3::Hasher::new_keyed(&seed32);
    hasher.update(b"unchained-otp-bytes.v1");
    let mut out = [0u8; OTP_PK_BYTES];
    hasher.finalize_xof().fill(&mut out);
    out
}

/// Commitment of a stealth output used in spend authorization.
pub fn commitment_of_stealth_ct(ml_kem_ct_bytes: &[u8]) -> [u8; 32] {
    blake3_hash(ml_kem_ct_bytes)
}

/// V3: Length-prefixed stealth seed derivation bound to chain id using ML-KEM only.
/// TAG = "unchained-stealth-v3|mlkem768"
pub fn stealth_seed_v3(
    ss: &[u8],
    receiver_binding: &[u8],
    ml_kem_ct_bytes: &[u8],
    value_tag: &[u8],
    chain_id32: &[u8; 32],
) -> [u8; 32] {
    fn lp(len: usize) -> [u8; 4] {
        (len as u32).to_le_bytes()
    }
    let mut h = Hasher::new();
    h.update(b"unchained-stealth-v3|mlkem768");
    h.update(&lp(ss.len()));
    h.update(ss);
    h.update(&lp(receiver_binding.len()));
    h.update(receiver_binding);
    h.update(&lp(ml_kem_ct_bytes.len()));
    h.update(ml_kem_ct_bytes);
    h.update(&lp(value_tag.len()));
    h.update(value_tag);
    h.update(chain_id32);
    let out = h.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&out.as_bytes()[..32]);
    seed
}

/// Generate a self-signed X.509 certificate.
pub fn generate_self_signed_cert() -> Result<(Vec<u8>, Vec<u8>)> {
    let mut params = CertificateParams::new(vec!["node.local".to_string()])?;
    params.subject_alt_names = vec![
        SanType::DnsName("node.local".try_into()?),
        SanType::DnsName("p2p.local".try_into()?),
    ];

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    Ok((cert.der().to_vec(), key_pair.serialize_der()))
}

/// Create a post-quantum aware Rustls client configuration.
pub fn create_pq_client_config() -> Result<Arc<ClientConfig>> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_root_certificates(root_store)
    .with_no_client_auth();

    Ok(Arc::new(config))
}

/// Create a post-quantum aware Rustls server configuration.
pub fn create_pq_server_config(
    cert_der: Vec<u8>,
    private_key_der: Vec<u8>,
) -> Result<Arc<ServerConfig>> {
    let cert_chain = vec![CertificateDer::from(cert_der)];
    let private_key = PrivateKeyDer::try_from(private_key_der)
        .map_err(|e| anyhow!("Failed to parse private key: {}", e))?;

    let mut config = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_no_client_auth()
    .with_single_cert(cert_chain, private_key)?;

    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}

/// Compute preimage p for a payment.
pub fn compute_preimage_v1(
    chain_id32: &[u8; 32],
    coin_id: &[u8; 32],
    amount_le: u64,
    shared_secret: &[u8],
    note_s: &[u8],
) -> [u8; 32] {
    fn lp(len: usize) -> [u8; 4] {
        (len as u32).to_le_bytes()
    }
    let mut h = Hasher::new();
    h.update(b"pre");
    h.update(chain_id32);
    h.update(coin_id);
    h.update(&amount_le.to_le_bytes());
    h.update(&lp(shared_secret.len()));
    h.update(shared_secret);
    h.update(&lp(note_s.len()));
    h.update(note_s);
    *h.finalize().as_bytes()
}

/// Compute lock hash from preimage.
pub fn lock_hash_from_preimage(
    chain_id32: &[u8; 32],
    coin_id: &[u8; 32],
    preimage: &[u8],
) -> [u8; 32] {
    fn lp(len: usize) -> [u8; 4] {
        (len as u32).to_le_bytes()
    }
    let mut h = Hasher::new();
    h.update(b"lh");
    h.update(chain_id32);
    h.update(coin_id);
    h.update(&lp(preimage.len()));
    h.update(preimage);
    *h.finalize().as_bytes()
}

/// Compute nullifier from preimage.
pub fn nullifier_from_preimage(
    chain_id32: &[u8; 32],
    coin_id: &[u8; 32],
    preimage: &[u8],
) -> [u8; 32] {
    fn lp(len: usize) -> [u8; 4] {
        (len as u32).to_le_bytes()
    }
    let mut h = Hasher::new();
    h.update(b"nf");
    h.update(chain_id32);
    h.update(coin_id);
    h.update(&lp(preimage.len()));
    h.update(preimage);
    *h.finalize().as_bytes()
}

/// Commitment hash for HTLC preimages.
pub fn commitment_hash_from_preimage(
    chain_id32: &[u8; 32],
    coin_id: &[u8; 32],
    preimage: &[u8],
) -> [u8; 32] {
    fn lp(len: usize) -> [u8; 4] {
        (len as u32).to_le_bytes()
    }
    let mut h = Hasher::new();
    h.update(b"ch");
    h.update(chain_id32);
    h.update(coin_id);
    h.update(&lp(preimage.len()));
    h.update(preimage);
    *h.finalize().as_bytes()
}

/// HTLC lock hash committing to both paths and timeout epoch.
pub fn htlc_lock_hash(
    chain_id32: &[u8; 32],
    coin_id: &[u8; 32],
    timeout_epoch: u64,
    ch_claim: &[u8; 32],
    ch_refund: &[u8; 32],
) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"htlc");
    h.update(chain_id32);
    h.update(coin_id);
    h.update(&timeout_epoch.to_le_bytes());
    h.update(ch_claim);
    h.update(ch_refund);
    *h.finalize().as_bytes()
}

/// View tag (1 byte) for receiver-side filtering.
pub fn view_tag(shared_secret: &[u8]) -> u8 {
    fn lp(len: usize) -> [u8; 4] {
        (len as u32).to_le_bytes()
    }
    let mut h = Hasher::new();
    h.update(b"vt");
    h.update(&lp(shared_secret.len()));
    h.update(shared_secret);
    h.finalize().as_bytes()[0]
}

/// Derive the next lock preimage from ML-KEM shared secret and context.
pub fn derive_next_lock_secret(
    shared: &[u8],
    ml_kem_ct_bytes: &[u8],
    amount_le: u64,
    coin_id: &[u8; 32],
    chain_id32: &[u8; 32],
) -> [u8; 32] {
    fn lp(len: usize) -> [u8; 4] {
        (len as u32).to_le_bytes()
    }
    let mut h = Hasher::new();
    h.update(b"unchained.locksecret.v1|mlkem768");
    h.update(&lp(shared.len()));
    h.update(shared);
    h.update(&lp(ml_kem_ct_bytes.len()));
    h.update(ml_kem_ct_bytes);
    h.update(&amount_le.to_le_bytes());
    h.update(coin_id);
    h.update(chain_id32);
    *h.finalize().as_bytes()
}

pub fn derive_next_lock_secret_with_note(
    shared: &[u8],
    ml_kem_ct_bytes: &[u8],
    amount_le: u64,
    coin_id: &[u8; 32],
    chain_id32: &[u8; 32],
    note_s: &[u8],
) -> [u8; 32] {
    fn lp(len: usize) -> [u8; 4] {
        (len as u32).to_le_bytes()
    }
    let mut h = Hasher::new();
    h.update(b"unchained.locksecret.v2|mlkem768");
    h.update(&lp(shared.len()));
    h.update(shared);
    h.update(&lp(ml_kem_ct_bytes.len()));
    h.update(ml_kem_ct_bytes);
    h.update(&amount_le.to_le_bytes());
    h.update(coin_id);
    h.update(chain_id32);
    h.update(&lp(note_s.len()));
    h.update(note_s);
    *h.finalize().as_bytes()
}

#[inline]
fn derive_kem_shared_key32(shared_secret: &[u8]) -> [u8; 32] {
    fn lp(len: usize) -> [u8; 4] {
        (len as u32).to_le_bytes()
    }
    let mut h = Hasher::new();
    h.update(b"ml-kem.shared-key.v1");
    h.update(&lp(shared_secret.len()));
    h.update(shared_secret);
    *h.finalize().as_bytes()
}

pub fn kem_encapsulate_to_ml_kem(
    pk: &TaggedKemPublicKey,
) -> Result<([u8; ML_KEM_768_CT_BYTES], [u8; 32])> {
    let public_key = ml_kem_768_public_key_from_tagged(pk);
    let (ciphertext, shared_secret) = public_key
        .encapsulate(&mut OsRng)
        .map_err(|_| anyhow!("ML-KEM-768 encapsulation failed"))?;
    let mut kem_ct = [0u8; ML_KEM_768_CT_BYTES];
    kem_ct.copy_from_slice(ciphertext.as_slice());
    Ok((kem_ct, derive_kem_shared_key32(shared_secret.as_slice())))
}

pub fn kem_encapsulate_to_ml_kem_deterministic(
    pk: &TaggedKemPublicKey,
    seed: &[u8; 32],
) -> Result<([u8; ML_KEM_768_CT_BYTES], [u8; 32])> {
    let public_key = ml_kem_768_public_key_from_tagged(pk);
    let seed: B32 = (*seed).into();
    let (ciphertext, shared_secret) = public_key
        .encapsulate_deterministic(&seed)
        .map_err(|_| anyhow!("ML-KEM-768 deterministic encapsulation failed"))?;
    let mut kem_ct = [0u8; ML_KEM_768_CT_BYTES];
    kem_ct.copy_from_slice(ciphertext.as_slice());
    Ok((kem_ct, derive_kem_shared_key32(shared_secret.as_slice())))
}

pub fn ml_kem_768_decapsulate(
    sk: &MlKem768SecretKey,
    kem_ct_bytes: &[u8; ML_KEM_768_CT_BYTES],
) -> Result<[u8; 32]> {
    let ciphertext = ml_kem_768_ciphertext_from_bytes(kem_ct_bytes);
    let shared_secret = sk
        .decapsulate(&ciphertext)
        .map_err(|_| anyhow!("ML-KEM-768 decapsulation failed"))?;
    Ok(derive_kem_shared_key32(shared_secret.as_slice()))
}

pub fn derive_genesis_lock_secret(
    lock_seed: &[u8; 32],
    coin_id: &[u8; 32],
    chain_id32: &[u8; 32],
) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"unchained.lockseed.genesis.v2");
    h.update(lock_seed);
    h.update(coin_id);
    h.update(chain_id32);
    *h.finalize().as_bytes()
}

pub fn commitment_id_v1(
    one_time_pk: &[u8; OTP_PK_BYTES],
    ml_kem_ct: &[u8; ML_KEM_768_CT_BYTES],
    next_lock_hash: &[u8; 32],
    coin_id: &[u8; 32],
    amount_le: u64,
    chain_id32: &[u8; 32],
) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"commitment_id_v1");
    h.update(one_time_pk);
    h.update(ml_kem_ct);
    h.update(next_lock_hash);
    h.update(coin_id);
    h.update(&amount_le.to_le_bytes());
    h.update(chain_id32);
    *h.finalize().as_bytes()
}
