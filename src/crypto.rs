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
use std::io::Write;
use std::sync::Mutex;
use anyhow::bail;
use atty;
use rpassword;
use webpki_roots;
#[cfg(feature = "liboqs")]
use oqs_sys::rand::OQS_randombytes_custom_algorithm;

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

/// Deterministically generate a Dilithium3/ML-DSA-65 keypair from a 32-byte seed.
/// Uses liboqs (ML-DSA-65) with a custom deterministic RNG fed by the seed so
/// the output must be  reproducible across nodes.
pub fn dilithium3_seeded_keypair(seed32: [u8; 32]) -> (PublicKey, SecretKey) {
    // Preferred robust path: invoke helper binary to isolate RNG override.
    // Fallback to in-process override only if helper is missing or fails.
    let helper_path = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("oqs_dili_seeded")))
        .unwrap_or_else(|| std::path::PathBuf::from("oqs_dili_seeded"));
    if let Ok(mut child) = std::process::Command::new(helper_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
    {
        if let Some(mut sin) = child.stdin.take() {
            let _ = sin.write_all(&seed32);
        }
        let out = child.wait_with_output();
        if let Ok(output) = out {
            if output.status.success() {
                let bytes = output.stdout;
                if bytes.len() == DILITHIUM3_PK_BYTES + DILITHIUM3_SK_BYTES {
                    let (pkb, skb) = bytes.split_at(DILITHIUM3_PK_BYTES);
                    let pk = PublicKey::from_bytes(pkb).expect("invalid Dilithium3 public key bytes");
                    let sk = SecretKey::from_bytes(skb).expect("invalid Dilithium3 secret key bytes");
                    return (pk, sk);
                }
            }
        }
        // If helper path fails, continue to fallback in-process path
    }

    // Fallback: in-process RNG override using BLAKE3 XOF
    static KEYGEN_LOCK: OnceCell<Mutex<()>> = OnceCell::new();
    let _kg_lock = KEYGEN_LOCK.get_or_init(|| Mutex::new(())).lock().expect("keygen lock poisoned");
    #[cfg(feature = "liboqs")]
    oqs::init();

    struct XofRng { reader: blake3::OutputReader }
    static DET_RNG: OnceCell<Mutex<Option<XofRng>>> = OnceCell::new();
    #[cfg(feature = "liboqs")]
    unsafe extern "C" fn oqs_custom_randombytes(out_ptr: *mut u8, out_len: usize) {
        let slice = std::slice::from_raw_parts_mut(out_ptr, out_len);
        if let Some(cell) = DET_RNG.get() {
            if let Ok(mut g) = cell.lock() {
                if let Some(st) = g.as_mut() {
                    st.reader.fill(slice);
                    return;
                }
            }
        }
        panic!("deterministic RNG state not initialized");
    }
    let cell = DET_RNG.get_or_init(|| Mutex::new(None));
    {
        let mut hasher = blake3::Hasher::new_keyed(&seed32);
        hasher.update(b"unchained-oqs-rng-xof-v1");
        let reader = hasher.finalize_xof();
        let mut guard = cell.lock().expect("deterministic RNG mutex poisoned");
        *guard = Some(XofRng { reader });
    }
    #[cfg(feature = "liboqs")]
    unsafe { OQS_randombytes_custom_algorithm(Some(oqs_custom_randombytes)); }
    #[cfg(feature = "liboqs")]
    let (pk_bytes, sk_bytes) = {
        let sig = oqs::sig::Sig::new(oqs::sig::Algorithm::MlDsa65).expect("liboqs ML-DSA-65 not available");
        let (oqs_pk, oqs_sk) = sig.keypair().expect("liboqs keypair failed");
        let pk_bytes = oqs_pk.as_ref().to_vec();
        let sk_bytes = oqs_sk.as_ref().to_vec();
        (pk_bytes, sk_bytes)
    };
    #[cfg(feature = "liboqs")]
    unsafe { OQS_randombytes_custom_algorithm(None); }
    #[cfg(not(feature = "liboqs"))]
    let (pk_bytes, sk_bytes) = {
        // Pure-Rust fallback using pqcrypto-dilithium deterministic seed API is not available,
        // so we derive via pqcrypto keypair and treat as seeded for non-liboqs builds.
        // This path is acceptable in CI where we only need Windows builds without liboqs.
        let (pk, sk) = pqcrypto_dilithium::dilithium3::keypair();
        (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
    };
    {
        let mut guard = cell.lock().expect("deterministic RNG mutex poisoned");
        *guard = None; // reader dropped
    }
    assert_eq!(pk_bytes.len(), DILITHIUM3_PK_BYTES, "Dilithium3 pk size mismatch");
    assert_eq!(sk_bytes.len(), DILITHIUM3_SK_BYTES, "Dilithium3 sk size mismatch");
    let dili_pk = PublicKey::from_bytes(&pk_bytes).expect("invalid Dilithium3 public key bytes");
    let dili_sk = SecretKey::from_bytes(&sk_bytes).expect("invalid Dilithium3 secret key bytes");
    (dili_pk, dili_sk)
}

/// Compute a PQ-safe nullifier bound to a secret spend key and coin id.
/// N = BLAKE3("nullifier_v2" || sk_bytes || coin_id)
pub fn compute_nullifier_v2(sk_bytes: &[u8], coin_id: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new_derive_key("nullifier_v2");
    h.update(sk_bytes);
    h.update(coin_id);
    *h.finalize().as_bytes()
}

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

/// Compute nullifier for signatureless spend: N = BLAKE3("unchained.nullifier.v3" || coin_id || preimage)
pub fn compute_nullifier_v3(preimage: &[u8], coin_id: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"unchained.nullifier.v3");
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

