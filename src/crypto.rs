use blake3::Hasher;
use argon2::{Argon2, Params, Version, Algorithm};
use pqcrypto_dilithium::dilithium3::{
    PublicKey, SecretKey, keypair,
};
use anyhow::{Result, anyhow, bail};
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _, DetachedSignature as _};
use chacha20poly1305::{XChaCha20Poly1305, aead::{Aead, NewAead}, XNonce, Key as XKey};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroize;
// use rcgen removed; self-signed cert generation was unused
use rustls::{ClientConfig, RootCertStore};
// removed server-side rustls imports as TLS for proof server is restricted to loopback HTTP
use std::sync::Arc;
use webpki_roots;
use serde::{Serialize, Deserialize};
use pqcrypto_kyber::kyber768::{encapsulate, decapsulate, PublicKey as KyberPk, SecretKey as KyberSk, keypair as kyber_keypair, Ciphertext as KyberCt};
use pqcrypto_traits::kem::{Ciphertext as _, SharedSecret as _, PublicKey as _, SecretKey as _};
use once_cell::sync::OnceCell;

// Constants for post-quantum crypto primitives ensure type safety and clarity.
pub const DILITHIUM3_PK_BYTES: usize = pqcrypto_dilithium::ffi::PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_PUBLICKEYBYTES;
pub const DILITHIUM3_SK_BYTES: usize = pqcrypto_dilithium::ffi::PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_SECRETKEYBYTES;
pub const DILITHIUM3_SIG_BYTES: usize = pqcrypto_dilithium::ffi::PQCLEAN_DILITHIUM3_CLEAN_CRYPTO_BYTES;

/// A 32-byte address, derived from a BLAKE3 hash of a public key.
/// This provides a fixed-size, user-friendly identifier.
pub type Address = [u8; 32];



// -----------------------------------------------------------------------------
// Unified passphrase handling
// -----------------------------------------------------------------------------
static UNIFIED_PASSPHRASE: OnceCell<String> = OnceCell::new();

/// Obtain a single, unified pass-phrase for all sensitive at-rest keys.
/// Source:
///   - QUANTUM_PASSPHRASE
/// If not set and interactive, prompt using the provided text (or a default).
/// If non-interactive and not set, returns an error.
pub fn unified_passphrase(prompt: Option<&str>) -> Result<String> {
    if let Some(existing) = UNIFIED_PASSPHRASE.get() {
        return Ok(existing.clone());
    }

    // Only QUANTUM_PASSPHRASE is supported
    if let Ok(val) = std::env::var("QUANTUM_PASSPHRASE") {
        let _ = UNIFIED_PASSPHRASE.set(val.clone());
        return Ok(val);
    }

    // Prompt if interactive
    if atty::is(atty::Stream::Stdin) {
        let text = prompt.unwrap_or("Enter quantum pass-phrase: ");
        let pw = rpassword::prompt_password(text)?;
        let _ = UNIFIED_PASSPHRASE.set(pw.clone());
        return Ok(pw);
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
/// Consensus parameters:
/// - lanes must be 1 (determinism and side-channel avoidance)
/// - salt must be the previous anchor hash (challenge binding); first 16 bytes are used
pub fn argon2id_pow(header: &[u8], salt32: &[u8; 32], mem_kib: u32, t_cost: u32) -> Result<[u8; 32]> {
    // lanes fixed to 1 as per consensus rules
    let params = Params::new(mem_kib, t_cost, 1, None)
        .map_err(|e| anyhow!("Invalid Argon2id parameters: {}", e))?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut hash = [0u8; 32];
    let salt = &salt32[..16];

    a2.hash_password_into(header, salt, &mut hash)
        .map_err(|e| anyhow!("Argon2id hashing failed: {}", e))?;
    Ok(hash)
}

/// Big-endian compare helper: interpret 32-byte array as big-endian integer compare
pub fn leq_hash_to_target(pow_hash: &[u8; 32], target: &primitive_types::U256) -> bool {
    use primitive_types::U256;
    let h = U256::from_big_endian(pow_hash);
    h <= *target
}

pub fn decode_compact_target(nbits: u32) -> anyhow::Result<primitive_types::U256> {
    use primitive_types::U256;
    let exponent = (nbits >> 24) as u8;
    let mantissa = nbits & 0x00FF_FFFF;
    if mantissa == 0 { return Err(anyhow!("compact target mantissa cannot be zero")); }
    if exponent == 0 || exponent > 32 { return Err(anyhow!("compact target exponent out of bounds")); }
    // Build target = mantissa * 256^(exponent-3)
    let mut target = U256::from(mantissa);
    if exponent > 3 {
        let shift = ((exponent as i32) - 3) as usize * 8;
        target = target << shift;
    } else if exponent < 3 {
        let shift = ((3 - exponent as i32) as usize) * 8;
        target = target >> shift;
    }
    Ok(target)
}

/// Canonical compact encoding for a 256-bit target.
/// Ensures mantissa high bit is clear; if set, shifts and increments exponent.
pub fn encode_compact_target(target: &primitive_types::U256) -> u32 {
    if target.is_zero() { return 0; }
    // Determine exponent: number of bytes required
    let mut bytes = [0u8; 32];
    target.to_big_endian(&mut bytes);
    let mut i = 0;
    while i < 32 && bytes[i] == 0 { i += 1; }
    let exponent = (32 - i) as u8;
    let mut mantissa: u32;
    if exponent >= 3 {
        mantissa = ((bytes[i] as u32) << 16)
            | ((bytes.get(i+1).copied().unwrap_or(0) as u32) << 8)
            | (bytes.get(i+2).copied().unwrap_or(0) as u32);
    } else {
        let shift = (3 - exponent) as usize;
        let mut tmp = 0u32;
        for j in 0..3 {
            let idx = i + j - shift;
            let b = if idx < 32 { bytes.get(idx).copied().unwrap_or(0) } else { 0 };
            tmp = (tmp << 8) | b as u32;
        }
        mantissa = tmp;
    }
    // If mantissa's high bit is set, shift right and bump exponent to keep it canonical
    if (mantissa & 0x0080_0000) != 0 {
        mantissa >>= 8;
        // exponent is at least 1 less than or equal to 32, so increment won't overflow valid range for U256
        let exponent = exponent.saturating_add(1);
        return (exponent as u32) << 24 | (mantissa & 0x00FF_FFFF);
    }
    (exponent as u32) << 24 | (mantissa & 0x00FF_FFFF)
}

/// Returns the canonical compact representation for a given compact `nbits`.
/// Fails if `nbits` has an invalid exponent/mantissa.
pub fn normalize_compact_target(nbits: u32) -> anyhow::Result<u32> {
    let t = decode_compact_target(nbits)?;
    Ok(encode_compact_target(&t))
}

/// Compute per-coin work contribution: floor((2^256 - 1) / (h + 1))
pub fn work_from_pow_hash(pow_hash: &[u8; 32]) -> primitive_types::U256 {
    use primitive_types::{U256, U512};
    // Exact work definition: floor((2^256 - 1) / (h + 1))
    let h256 = U256::from_big_endian(pow_hash);
    if h256 == U256::MAX { return U256::zero(); }
    let denom256 = h256.saturating_add(U256::one());
    let denom512 = U512::from(denom256);
    let numerator = (U512::one() << 256) - U512::one(); // 2^256 - 1 as U512
    let q512 = numerator / denom512;
    let mut out = [0u8; 32];
    q512.to_big_endian(&mut out);
    U256::from_big_endian(&out)
}

/// Hashes arbitrary data with a domain-specific key for internal consistency.
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *Hasher::new_derive_key("unchained-v1").update(data).finalize().as_bytes()
}

pub fn dilithium3_keypair() -> (PublicKey, SecretKey) {
    keypair()
}

// Removed unused load_or_create_node_dilithium; node uses PQ identity and Kyber KEM keys

pub fn load_or_create_node_kyber() -> Result<(KyberPk, KyberSk)> {
    // Passphrase-protected node Kyber KEM keys
    const SALT_LEN: usize = 16; const NONCE_LEN: usize = 24; const VERSION: u8 = 1;
    let path = "node_kyber.enc";
    fn obtain_passphrase() -> Result<String> { unified_passphrase(Some("Enter quantum pass-phrase: ")) }
    if std::path::Path::new(path).exists() {
        let enc = std::fs::read(path)?;
        if enc.len() < 1 + SALT_LEN + NONCE_LEN { bail!("corrupt node kyber file"); }
        let version = enc[0]; if version != VERSION { bail!("unsupported kyber version: {}", version); }
        let salt = &enc[1..1+SALT_LEN]; let nonce = &enc[1+SALT_LEN..1+SALT_LEN+NONCE_LEN]; let ct = &enc[1+SALT_LEN+NONCE_LEN..];
        let pass = obtain_passphrase()?; let mut key = [0u8;32];
        let params = Params::new(256*1024, 3, 1, None).map_err(|e| anyhow!("Invalid Argon2id params: {}", e))?;
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(pass.as_bytes(), salt, &mut key)
            .map_err(|e| anyhow!("Argon2id failed: {}", e))?;
        let cipher = XChaCha20Poly1305::new(XKey::from_slice(&key));
        let mut plain = cipher.decrypt(XNonce::from_slice(nonce), ct).map_err(|_| anyhow!("node pass-phrase invalid"))?;
        key.zeroize();
        #[derive(Serialize, Deserialize)] struct KyStore { pk: Vec<u8>, sk: Vec<u8> }
        let s: KyStore = bincode::deserialize(&plain)?; plain.zeroize();
        let pk = KyberPk::from_bytes(&s.pk).map_err(|_| anyhow!("bad kyber pk"))?;
        let sk = KyberSk::from_bytes(&s.sk).map_err(|_| anyhow!("bad kyber sk"))?;
        return Ok((pk, sk));
    }
    let (pk, sk) = kyber_keypair_generate();
    let pass = obtain_passphrase()?; let mut salt = [0u8;SALT_LEN]; OsRng.fill_bytes(&mut salt);
    let mut key = [0u8;32];
    let params = Params::new(256*1024, 3, 1, None).map_err(|e| anyhow!("Invalid Argon2id params: {}", e))?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params).hash_password_into(pass.as_bytes(), &salt, &mut key).map_err(|e| anyhow!("Argon2id failed: {}", e))?;
    let cipher = XChaCha20Poly1305::new(XKey::from_slice(&key)); let mut nonce = [0u8;NONCE_LEN]; OsRng.fill_bytes(&mut nonce);
    #[derive(Serialize, Deserialize)] struct KyStore { pk: Vec<u8>, sk: Vec<u8> }
    let s = KyStore { pk: pk.as_bytes().to_vec(), sk: sk.as_bytes().to_vec() };
    let plain = bincode::serialize(&s)?; let ct = cipher.encrypt(XNonce::from_slice(&nonce), plain.as_ref()).expect("encrypt"); key.zeroize();
    let mut out = Vec::with_capacity(1 + SALT_LEN + NONCE_LEN + ct.len()); out.push(VERSION); out.extend_from_slice(&salt); out.extend_from_slice(&nonce); out.extend_from_slice(&ct);
    std::fs::write(path, &out)?; #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; let mut perms = std::fs::metadata(path)?.permissions(); perms.set_mode(0o600); std::fs::set_permissions(path, perms)?; }
    Ok((pk, sk))
}

pub fn load_or_create_pq_identity() -> Result<(PublicKey, SecretKey)> {
    // Encrypted at rest using Argon2id + XChaCha20-Poly1305; migrate legacy plaintext if present
    const SALT_LEN: usize = 16; const NONCE_LEN: usize = 24; const VERSION: u8 = 1;
    let legacy = "pq_identity.bin"; let path = "pq_identity.enc";

    fn obtain_passphrase(prompt: &str) -> Result<String> { unified_passphrase(Some(prompt)) }

    if std::path::Path::new(path).exists() {
        let enc = std::fs::read(path)?;
        if enc.len() < DILITHIUM3_PK_BYTES + 1 + SALT_LEN + NONCE_LEN { bail!("corrupt pq identity file"); }
        let pk_bytes = &enc[0..DILITHIUM3_PK_BYTES];
        let version = enc[DILITHIUM3_PK_BYTES]; if version != VERSION { bail!("unsupported pq identity version: {}", version); }
        let salt = &enc[DILITHIUM3_PK_BYTES+1 .. DILITHIUM3_PK_BYTES+1+SALT_LEN];
        let nonce = &enc[DILITHIUM3_PK_BYTES+1+SALT_LEN .. DILITHIUM3_PK_BYTES+1+SALT_LEN+NONCE_LEN];
        let ct = &enc[DILITHIUM3_PK_BYTES+1+SALT_LEN+NONCE_LEN .. ];
        let pass = obtain_passphrase("Enter quantum pass-phrase: ")?;
        let mut key = [0u8;32];
        let params = Params::new(256*1024, 3, 1, None).map_err(|e| anyhow!("Invalid Argon2id params: {}", e))?;
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(pass.as_bytes(), salt, &mut key)
            .map_err(|e| anyhow!("Argon2id failed: {}", e))?;
        let cipher = XChaCha20Poly1305::new(XKey::from_slice(&key));
        let mut sk_bytes = cipher.decrypt(XNonce::from_slice(nonce), ct).map_err(|_| anyhow!("Invalid PQ identity pass-phrase"))?;
        key.zeroize();
        let pk = PublicKey::from_bytes(pk_bytes)?; let sk = SecretKey::from_bytes(&sk_bytes)?; sk_bytes.zeroize();
        return Ok((pk, sk));
    }

    // Legacy migration path
    if std::path::Path::new(legacy).exists() {
        let bytes = std::fs::read(legacy)?;
        #[derive(Serialize, Deserialize)] struct PqIdentity { #[serde(with = "serde_big_array::BigArray")] pk: [u8; DILITHIUM3_PK_BYTES], #[serde(with = "serde_big_array::BigArray")] sk: [u8; DILITHIUM3_SK_BYTES] }
        let id: PqIdentity = bincode::deserialize(&bytes)?;
        let pk = PublicKey::from_bytes(&id.pk)?; let sk = SecretKey::from_bytes(&id.sk)?;
        // Re-encrypt under passphrase
        let pass = obtain_passphrase("Set a quantum pass-phrase to encrypt your identity: ")?;
        let mut salt = [0u8;SALT_LEN]; OsRng.fill_bytes(&mut salt);
        let mut key = [0u8;32]; let params = Params::new(256*1024, 3, 1, None).map_err(|e| anyhow!("Invalid Argon2id params: {}", e))?;
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params).hash_password_into(pass.as_bytes(), &salt, &mut key).map_err(|e| anyhow!("Argon2id failed: {}", e))?;
        let cipher = XChaCha20Poly1305::new(XKey::from_slice(&key)); let mut nonce = [0u8;NONCE_LEN]; OsRng.fill_bytes(&mut nonce);
        let ct = cipher.encrypt(XNonce::from_slice(&nonce), sk.as_bytes()).expect("encrypt"); key.zeroize();
        let mut out = Vec::with_capacity(DILITHIUM3_PK_BYTES + 1 + SALT_LEN + NONCE_LEN + ct.len());
        out.extend_from_slice(pk.as_bytes()); out.push(VERSION); out.extend_from_slice(&salt); out.extend_from_slice(&nonce); out.extend_from_slice(&ct);
        std::fs::write(path, &out)?; #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; let mut perms = std::fs::metadata(path)?.permissions(); perms.set_mode(0o600); std::fs::set_permissions(path, perms)?; }
        // Best-effort remove legacy file
        let _ = std::fs::remove_file(legacy);
        return Ok((pk, sk));
    }

    // Brand new PQ identity
    let (pk, sk) = dilithium3_keypair();
    let pass = obtain_passphrase("Set a quantum pass-phrase for your identity: ")?;
    let mut salt = [0u8;SALT_LEN]; OsRng.fill_bytes(&mut salt);
    let mut key = [0u8;32]; let params = Params::new(256*1024, 3, 1, None).map_err(|e| anyhow!("Invalid Argon2id params: {}", e))?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params).hash_password_into(pass.as_bytes(), &salt, &mut key).map_err(|e| anyhow!("Argon2id failed: {}", e))?;
    let cipher = XChaCha20Poly1305::new(XKey::from_slice(&key)); let mut nonce = [0u8;NONCE_LEN]; OsRng.fill_bytes(&mut nonce);
    let ct = cipher.encrypt(XNonce::from_slice(&nonce), sk.as_bytes()).expect("encrypt"); key.zeroize();
    let mut out = Vec::with_capacity(DILITHIUM3_PK_BYTES + 1 + SALT_LEN + NONCE_LEN + ct.len());
    out.extend_from_slice(pk.as_bytes()); out.push(VERSION); out.extend_from_slice(&salt); out.extend_from_slice(&nonce); out.extend_from_slice(&ct);
    std::fs::write(path, &out)?; #[cfg(unix)] { use std::os::unix::fs::PermissionsExt; let mut perms = std::fs::metadata(path)?.permissions(); perms.set_mode(0o600); std::fs::set_permissions(path, perms)?; }
    Ok((pk, sk))
}

pub fn pq_sign_detached(message: &[u8], sk: &SecretKey) -> [u8; DILITHIUM3_SIG_BYTES] {
    let sig = pqcrypto_dilithium::dilithium3::detached_sign(message, sk);
    let mut out = [0u8; DILITHIUM3_SIG_BYTES];
    out.copy_from_slice(sig.as_bytes());
    out
}

pub fn pq_verify_detached(message: &[u8], sig: &[u8; DILITHIUM3_SIG_BYTES], pk: &PublicKey) -> bool {
    let Ok(detached) = pqcrypto_dilithium::dilithium3::DetachedSignature::from_bytes(sig) else { return false; };
    pqcrypto_dilithium::dilithium3::verify_detached_signature(&detached, message, pk).is_ok()
}

// Minimal structs for future handshake messages can be added when the protocol is wired

pub fn kyber_keypair_generate() -> (KyberPk, KyberSk) {
    kyber_keypair()
}

pub fn kyber_encapsulate(pk: &KyberPk) -> (Vec<u8>, Vec<u8>) {
    let (ciphertext, shared_secret) = encapsulate(pk);
    (ciphertext.as_bytes().to_vec(), shared_secret.as_bytes().to_vec())
}

pub fn kyber_decapsulate(ct: &[u8], sk: &KyberSk) -> Option<Vec<u8>> {
    let ct = KyberCt::from_bytes(ct).ok()?;
    Some(decapsulate(&ct, sk).as_bytes().to_vec())
}

/// Install the aws-lc-rs crypto provider as the default for rustls (if not already installed).
/// This ensures downstream users that rely on rustls's default provider (e.g., libp2p-quic/quinn)
/// will negotiate PQ-capable cipher suites/KEMs when available.
pub fn ensure_aws_lc_rs_provider_installed() {
    // If the provider is already installed elsewhere, this returns an error we can ignore safely.
    #[allow(unused_must_use)]
    {
        rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
}

// Removed unused self-signed certificate generator (rcgen)

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

// Server-side TLS builder removed (proof server limited to loopback HTTP)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pq_provider_install_is_idempotent() {
        // Should not panic even if called multiple times
        ensure_aws_lc_rs_provider_installed();
        ensure_aws_lc_rs_provider_installed();
    }

    #[test]
    fn pq_client_config_builds_with_aws_lc_rs_provider() {
        ensure_aws_lc_rs_provider_installed();
        let cfg = create_pq_client_config().expect("pq client config must build");
        // Basic sanity: TLS13 should be enabled as per builder setup
        // No public API to introspect provider; success implies provider usable.
        assert!(Arc::strong_count(&cfg) >= 1);
    }
}

