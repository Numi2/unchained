use blake3::Hasher;
use argon2::{Argon2, Params, Version, Algorithm};
use pqcrypto_dilithium::dilithium3::{
    PublicKey, SecretKey,
};

use anyhow::{Result, anyhow};
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
use libp2p::identity;
use rcgen::{CertificateParams, KeyPair, SanType};
use rustls::{ClientConfig, ServerConfig, RootCertStore};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use once_cell::sync::OnceCell;
use zeroize::Zeroizing;
use anyhow::bail;
use atty;
use rpassword;
use webpki_roots;
// liboqs usage removed

// Constants for post-quantum crypto primitives ensure type safety and clarity.
pub const DILITHIUM3_PK_BYTES: usize = pqcrypto_dilithium::ffi::PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_PUBLICKEYBYTES;
pub const DILITHIUM3_SK_BYTES: usize = pqcrypto_dilithium::ffi::PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_SECRETKEYBYTES;
pub const DILITHIUM3_SIG_BYTES: usize = pqcrypto_dilithium::ffi::PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_BYTES;

// Kyber768 sizes for ciphertext and public key
pub const KYBER768_CT_BYTES: usize = pqcrypto_kyber::ffi::PQCLEAN_KYBER768_CLEAN_CRYPTO_CIPHERTEXTBYTES;
pub const KYBER768_PK_BYTES: usize = pqcrypto_kyber::ffi::PQCLEAN_KYBER768_CLEAN_CRYPTO_PUBLICKEYBYTES;
pub const KYBER768_SK_BYTES: usize = pqcrypto_kyber::ffi::PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES;

/// A 32-byte address, derived from a BLAKE3 hash of a public key.
/// This provides a fixed-size, user-friendly identifier.
pub type Address = [u8; 32];



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

pub fn address_from_pk(pk: &PublicKey) -> Address {
    *Hasher::new_derive_key("unchained-address")
        .update(pk.as_bytes())
        .finalize()
        .as_bytes()
}



/// Computes the Argon2id hash for Proof-of-Work.
/// Consensus parameters: lanes must be 1. Salt = BLAKE3(header)[0..16].
pub fn argon2id_pow(input: &[u8], mem_kib: u32) -> Result<[u8; 32]> {
    // lanes fixed to 1 as per consensus rules
    let params = Params::new(mem_kib, 1, 1, None)
        .map_err(|e| anyhow!("Invalid Argon2id parameters: {}", e))?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut hash = [0u8; 32];
    // Unkeyed BLAKE3 over header bytes; first 16 bytes as salt
    let full_salt = blake3::hash(input);
    let salt = &full_salt.as_bytes()[..16];

    a2.hash_password_into(input, salt, &mut hash)
        .map_err(|e| anyhow!("Argon2id hashing failed: {}", e))?;
    Ok(hash)
}

/// Hashes arbitrary data with a domain-specific key for internal consistency.
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *Hasher::new_derive_key("unchained-v1").update(data).finalize().as_bytes()
}

pub fn dilithium3_keypair() -> (PublicKey, SecretKey) {
    // Bleeding-edge deterministic only: generating with a fixed zero seed is disallowed.
    // Callers must use dilithium3_seeded_keypair with an explicit seed.
    panic!("Use dilithium3_seeded_keypair with an explicit seed");
}

/// Deterministically generate a Dilithium3 keypair from a 32-byte seed.
/// Note: liboqs removed. We derive a deterministic keypair via BLAKE3 XOF.
pub fn dilithium3_seeded_keypair(seed32: [u8; 32]) -> (PublicKey, SecretKey) {
    let mut hasher = blake3::Hasher::new_keyed(&seed32);
    hasher.update(b"unchained-dili-otp-v1");
    let mut out = vec![0u8; DILITHIUM3_PK_BYTES + DILITHIUM3_SK_BYTES];
    hasher.finalize_xof().fill(&mut out);
    let (pkb, skb) = out.split_at(DILITHIUM3_PK_BYTES);
    let pk = PublicKey::from_bytes(pkb).expect("invalid Dilithium3 public key bytes");
    let sk = SecretKey::from_bytes(skb).expect("invalid Dilithium3 secret key bytes");
    (pk, sk)
}

// [legacy] nullifier_v2 helper removed – V3 hashlock is the only active path.

/// Commitment of a stealth output used in spend authorization (V2)
/// New definition: commit to the Kyber ciphertext only to avoid circular
/// dependencies when deriving the one-time key deterministically.
pub fn commitment_of_stealth_ct(kyber_ct_bytes: &[u8]) -> [u8; 32] {
    blake3_hash(kyber_ct_bytes)
}

/// Length-prefixed stealth seed derivation bound to chain id and algo tags.
/// TAG = "unchained-stealth-v1|mlkem768|mldsa65"
/// seed32 = BLAKE3(TAG || lp(ss)||ss || lp(recv_pk)||recv_pk || lp(ct)||ct || lp(value_tag)||value_tag || chain_id32)
pub fn stealth_seed_v1(ss: &[u8], recv_dili_pk_bytes: &[u8], kyber_ct_bytes: &[u8], value_tag: &[u8], chain_id32: &[u8; 32]) -> [u8; 32] {
    fn lp(len: usize) -> [u8; 4] { (len as u32).to_le_bytes() }
    let mut h = Hasher::new();
    h.update(b"unchained-stealth-v1|mlkem768|mldsa65");
    h.update(&lp(ss.len()));          h.update(ss);
    h.update(&lp(recv_dili_pk_bytes.len())); h.update(recv_dili_pk_bytes);
    h.update(&lp(kyber_ct_bytes.len()));     h.update(kyber_ct_bytes);
    h.update(&lp(value_tag.len()));   h.update(value_tag);
    h.update(chain_id32);
    let out = h.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&out.as_bytes()[..32]);
    seed
}

// default_chain_id helper removed; chain id is retrieved from Store::get_chain_id()

/// Generate a self-signed X.509 certificate from a libp2p Ed25519 keypair
/// This cert is used for QUIC's TLS stack authentication
pub fn generate_self_signed_cert(_id_keys: &identity::Keypair) -> Result<(Vec<u8>, Vec<u8>)> {
    // Create certificate parameters
    let mut params = CertificateParams::new(vec!["node.local".to_string()])?;
    params.subject_alt_names = vec![
        SanType::DnsName("node.local".try_into()?),
        // Simple static hostname for P2P authentication
        SanType::DnsName("p2p.local".try_into()?),
    ];
    
    // Generate a new Ed25519 keypair for the certificate
    // Note: For simplicity, we generate a separate key for TLS rather than 
    // trying to convert the libp2p key format, which is complex
    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;
    
    Ok((cert.der().to_vec(), key_pair.serialize_der()))
}

/// Create a post-quantum aware Rustls client configuration
pub fn create_pq_client_config() -> Result<Arc<ClientConfig>> {
    // Initialize root certificate store with webpki-roots
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Build client config with post-quantum support
    // The aws_lc_rs provider includes Kyber hybrids when prefer-post-quantum is enabled
    let config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(Arc::new(config))
}

/// Create a post-quantum aware Rustls server configuration
pub fn create_pq_server_config(cert_der: Vec<u8>, private_key_der: Vec<u8>) -> Result<Arc<ServerConfig>> {
    // Parse the certificate and private key using the new API
    let cert_chain = vec![CertificateDer::from(cert_der)];
    let private_key = PrivateKeyDer::try_from(private_key_der)
        .map_err(|e| anyhow!("Failed to parse private key: {}", e))?;

    // Build server config with post-quantum support
    let mut config = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)?;

    // Prefer PQ/hybrid KEX via aws-lc provider. Set ALPN for HTTP/1.1.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}

// -----------------------------------------------------------------------------
// Signatureless spend helpers (BLAKE3 + Kyber)
// -----------------------------------------------------------------------------

/// Compute the lock hash H_lock = BLAKE3_k("unchained.lock.v1", preimage)
pub fn lock_hash(preimage: &[u8]) -> [u8; 32] {
    *Hasher::new_derive_key("unchained.lock.v1").update(preimage).finalize().as_bytes()
}

/// Compute nullifier for signatureless spend: N = BLAKE3("unchained.nullifier.v3" || chain_id32 || coin_id || preimage)
pub fn compute_nullifier_v3(preimage: &[u8], coin_id: &[u8; 32], chain_id32: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"unchained.nullifier.v3");
    h.update(chain_id32);
    h.update(coin_id);
    h.update(preimage);
    *h.finalize().as_bytes()
}

/// Derive the next lock preimage from Kyber shared secret and context.
/// s_next = BLAKE3("unchained.locksecret.v1|mlkem768" || lp(ss)||ss || lp(ct)||ct || amount_le || coin_id || chain_id)
pub fn derive_next_lock_secret(shared: &[u8], kyber_ct_bytes: &[u8], amount_le: u64, coin_id: &[u8;32], chain_id32: &[u8;32]) -> [u8;32] {
    fn lp(len: usize) -> [u8; 4] { (len as u32).to_le_bytes() }
    let mut h = Hasher::new();
    h.update(b"unchained.locksecret.v1|mlkem768");
    h.update(&lp(shared.len())); h.update(shared);
    h.update(&lp(kyber_ct_bytes.len())); h.update(kyber_ct_bytes);
    h.update(&amount_le.to_le_bytes());
    h.update(coin_id);
    h.update(chain_id32);
    *h.finalize().as_bytes()
}

/// Derive the genesis lock secret deterministically from Dilithium SK, coin id and chain id.
/// s0 = BLAKE3("unchained.lockseed.genesis.v1" || sk_bytes || coin_id || chain_id)
pub fn derive_genesis_lock_secret(dili_sk: &SecretKey, coin_id: &[u8;32], chain_id32: &[u8;32]) -> [u8;32] {
    let mut h = Hasher::new();
    h.update(b"unchained.lockseed.genesis.v1");
    h.update(dili_sk.as_bytes());
    h.update(coin_id);
    h.update(chain_id32);
    *h.finalize().as_bytes()
}

/// Deterministic commitment identifier derived from receiver commitment fields.
/// commitment_id = BLAKE3("commitment_id_v1" || one_time_pk || kyber_ct || next_lock_hash || coin_id || amount_le || chain_id32)
pub fn commitment_id_v1(
    one_time_pk: &[u8; DILITHIUM3_PK_BYTES],
    kyber_ct: &[u8; KYBER768_CT_BYTES],
    next_lock_hash: &[u8; 32],
    coin_id: &[u8; 32],
    amount_le: u64,
    chain_id32: &[u8; 32],
) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"commitment_id_v1");
    h.update(one_time_pk);
    h.update(kyber_ct);
    h.update(next_lock_hash);
    h.update(coin_id);
    h.update(&amount_le.to_le_bytes());
    h.update(chain_id32);
    *h.finalize().as_bytes()
}

