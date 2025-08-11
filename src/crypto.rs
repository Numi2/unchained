use blake3::Hasher;
use argon2::{Argon2, Params, Version, Algorithm};
use pqcrypto_dilithium::dilithium3::{
    PublicKey, SecretKey, keypair,
};
use anyhow::{Result, anyhow};
use pqcrypto_traits::sign::{PublicKey as _};
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

// Constants for post-quantum crypto primitives ensure type safety and clarity.
pub const DILITHIUM3_PK_BYTES: usize = pqcrypto_dilithium::ffi::PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_PUBLICKEYBYTES;
pub const DILITHIUM3_SK_BYTES: usize = pqcrypto_dilithium::ffi::PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_SECRETKEYBYTES;
pub const DILITHIUM3_SIG_BYTES: usize = pqcrypto_dilithium::ffi::PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_BYTES;

/// A 32-byte address, derived from a BLAKE3 hash of a public key.
/// This provides a fixed-size, user-friendly identifier.
pub type Address = [u8; 32];



// -----------------------------------------------------------------------------
// Unified passphrase handling (cached once per process)
// -----------------------------------------------------------------------------
static UNIFIED_PASSPHRASE: OnceCell<Zeroizing<String>> = OnceCell::new();

/// Obtain a single, unified pass-phrase for all sensitive at-rest keys.
/// Source order:
///   1) QUANTUM_PASSPHRASE env var
///   2) Interactive prompt (only once per process)
/// Non-interactive without env returns an error.
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
    keypair()
}

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
    let config = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)?;

    Ok(Arc::new(config))
}

