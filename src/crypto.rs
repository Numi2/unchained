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
use webpki_roots;

// Constants for post-quantum crypto primitives ensure type safety and clarity.
pub const DILITHIUM3_PK_BYTES: usize = pqcrypto_dilithium::ffi::PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_PUBLICKEYBYTES;
pub const DILITHIUM3_SK_BYTES: usize = pqcrypto_dilithium::ffi::PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_SECRETKEYBYTES;
pub const DILITHIUM3_SIG_BYTES: usize = pqcrypto_dilithium::ffi::PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_BYTES;

/// A 32-byte address, derived from a BLAKE3 hash of a public key.
/// This provides a fixed-size, user-friendly identifier.
pub type Address = [u8; 32];



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

/// Load or create the node's PQ peer identity keypair for networking (Dilithium3)
pub fn load_or_create_pq_peer_identity(path: &str) -> Result<(PublicKey, SecretKey)> {
    use std::fs;
    use std::path::Path;
    let pk_path = format!("{}", path);
    if Path::new(&pk_path).exists() {
        let bytes = fs::read(&pk_path)?;
        // Format: pk_len(2 bytes LE) || pk || sk
        if bytes.len() < 2 { return Err(anyhow!("invalid pq key file")); }
        let pk_len = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
        if bytes.len() < 2 + pk_len { return Err(anyhow!("invalid pq key file")); }
        let pk = PublicKey::from_bytes(&bytes[2..2+pk_len]).map_err(|_| anyhow!("bad pq pk"))?;
        let sk = SecretKey::from_bytes(&bytes[2+pk_len..]).map_err(|_| anyhow!("bad pq sk"))?;
        return Ok((pk, sk));
    }
    let (pk, sk) = dilithium3_keypair();
    // Store as simple concatenation with length prefix for future-proofing
    let mut out = Vec::with_capacity(2 + DILITHIUM3_PK_BYTES + DILITHIUM3_SK_BYTES);
    out.extend_from_slice(&(DILITHIUM3_PK_BYTES as u16).to_le_bytes());
    out.extend_from_slice(pk.as_bytes());
    out.extend_from_slice(sk.as_bytes());
    std::fs::write(&pk_path, out)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&pk_path) {
            let mut perms = meta.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(&pk_path, perms);
        }
    }
    Ok((pk, sk))
}

/// Sign arbitrary payload bytes with Dilithium3
pub fn pq_sign_payload(payload: &[u8], sk: &SecretKey) -> [u8; DILITHIUM3_SIG_BYTES] {
    let sig = pqcrypto_dilithium::dilithium3::detached_sign(payload, sk);
    let mut out = [0u8; DILITHIUM3_SIG_BYTES];
    out.copy_from_slice(sig.as_bytes());
    out
}

/// Verify Dilithium3 signature over raw payload bytes
pub fn pq_verify_payload(payload: &[u8], sig: &[u8; DILITHIUM3_SIG_BYTES], pk: &PublicKey) -> bool {
    match pqcrypto_dilithium::dilithium3::verify_detached_signature(
        &pqcrypto_dilithium::dilithium3::DetachedSignature::from_bytes(sig),
        payload,
        pk,
    ) {
        Ok(()) => true,
        Err(_) => false,
    }
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

