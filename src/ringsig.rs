use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use serde_bytes;
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _, DetachedSignature as _};
#[cfg(feature = "llrs_ffi")]
use crate::crypto::DILITHIUM3_PK_BYTES;
use blake3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkTag(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RingPublicKey(#[serde(with = "serde_bytes")] pub Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RingSignatureBlob(pub Vec<u8>);

pub trait RingSignatureScheme {
    fn sign(
        &self,
        message: &[u8],
        ring: &[RingPublicKey],
        secret_key_bytes: &[u8],
    ) -> Result<(RingSignatureBlob, LinkTag)>;

    fn verify(
        &self,
        message: &[u8],
        ring: &[RingPublicKey],
        signature: &RingSignatureBlob,
        link_tag: &LinkTag,
    ) -> Result<bool>;
}

// FFI backend for a real lattice-based linkable ring signature implementation.
// This is opt-in behind the `llrs_ffi` feature. Link an audited LLRS library
// that exposes the symbols below.
#[cfg(feature = "llrs_ffi")]
pub struct FfiLlrs;

#[cfg(feature = "llrs_ffi")]
extern "C" {
    // Returns 0 on success, non-zero on failure
    fn llrs_sign(
        msg_ptr: *const u8,
        msg_len: usize,
        ring_ptr: *const u8,   // concatenated ring public keys
        ring_len: usize,       // number of public keys
        pk_len: usize,         // length in bytes of each public key
        sk_ptr: *const u8,
        sk_len: usize,
        sig_out_ptr: *mut *mut u8,
        sig_out_len: *mut usize,
        link_tag_out: *mut u8, // 32 bytes
    ) -> i32;

    fn llrs_free_sig(ptr: *mut u8, len: usize);

    // Returns 0 on success (valid), non-zero on failure
    fn llrs_verify(
        msg_ptr: *const u8,
        msg_len: usize,
        ring_ptr: *const u8,
        ring_len: usize,
        pk_len: usize,
        sig_ptr: *const u8,
        sig_len: usize,
        link_tag_ptr: *const u8, // 32 bytes
    ) -> i32;
}

#[cfg(feature = "llrs_ffi")]
impl RingSignatureScheme for FfiLlrs {
    fn sign(
        &self,
        message: &[u8],
        ring: &[RingPublicKey],
        secret_key_bytes: &[u8],
    ) -> Result<(RingSignatureBlob, LinkTag)> {
        // Validate and flatten ring public keys
        if ring.is_empty() { return Err(anyhow!("ring must not be empty")); }
        let pk_len = ring[0].0.len();
        if pk_len == 0 { return Err(anyhow!("ring public key length must be > 0")); }
        for pk in ring {
            if pk.0.len() != pk_len { return Err(anyhow!("inconsistent ring public key lengths")); }
        }
        let mut ring_bytes = Vec::with_capacity(ring.len() * pk_len);
        for pk in ring { ring_bytes.extend_from_slice(&pk.0); }

        let mut sig_ptr: *mut u8 = std::ptr::null_mut();
        let mut sig_len: usize = 0;
        let mut tag = [0u8; 32];
        let rc = unsafe {
            llrs_sign(
                message.as_ptr(), message.len(),
                ring_bytes.as_ptr(), ring.len(), pk_len,
                secret_key_bytes.as_ptr(), secret_key_bytes.len(),
                &mut sig_ptr, &mut sig_len,
                tag.as_mut_ptr(),
            )
        };
        if rc != 0 || sig_ptr.is_null() || sig_len == 0 { return Err(anyhow!("llrs_sign failed")); }
        let sig = unsafe { std::slice::from_raw_parts(sig_ptr, sig_len) }.to_vec();
        unsafe { llrs_free_sig(sig_ptr, sig_len); }
        Ok((RingSignatureBlob(sig), LinkTag(tag)))
    }

    fn verify(
        &self,
        message: &[u8],
        ring: &[RingPublicKey],
        signature: &RingSignatureBlob,
        link_tag: &LinkTag,
    ) -> Result<bool> {
        if ring.is_empty() { return Ok(false); }
        let pk_len = ring[0].0.len();
        if pk_len == 0 { return Ok(false); }
        for pk in ring {
            if pk.0.len() != pk_len { return Ok(false); }
        }
        let mut ring_bytes = Vec::with_capacity(ring.len() * pk_len);
        for pk in ring { ring_bytes.extend_from_slice(&pk.0); }
        let rc = unsafe {
            llrs_verify(
                message.as_ptr(), message.len(),
                ring_bytes.as_ptr(), ring.len(), pk_len,
                signature.0.as_ptr(), signature.0.len(),
                link_tag.0.as_ptr(),
            )
        };
        Ok(rc == 0)
    }
}

// Mock backend using Dilithium3 for compile-time scaffolding only.
// Not a true linkable ring signature. Guarded by feature flag.
#[cfg(feature = "ring_mock")]
pub struct MockLlrs;

#[cfg(feature = "ring_mock")]
impl RingSignatureScheme for MockLlrs {
    fn sign(
        &self,
        message: &[u8],
        _ring: &[RingPublicKey],
        secret_key_bytes: &[u8],
    ) -> Result<(RingSignatureBlob, LinkTag)> {
        let sk = pqcrypto_dilithium::dilithium3::SecretKey::from_bytes(secret_key_bytes)
            .map_err(|_| anyhow!("invalid secret key"))?;
        let sig = pqcrypto_dilithium::dilithium3::detached_sign(message, &sk);
        let sig_bytes = sig.as_bytes();
        // Pseudo link tag for mock: bind to public key and domain separation so
        // repeated spends by same signer are linkable within this mock regime.
        // Derive public key by re-signing a fixed label and search the ring? Not available.
        // Instead, require caller to include the true public key in the ring; we link against
        // any ring member that verifies the signature.
        // Compute tag as hash of first verifying public key and domain separation.
        let sig_obj = pqcrypto_dilithium::dilithium3::DetachedSignature::from_bytes(sig_bytes)
            .map_err(|_| anyhow!("invalid signature format"))?;
        let mut tag = [0u8; 32];
        for pk in _ring {
            if let Ok(pk_obj) = pqcrypto_dilithium::dilithium3::PublicKey::from_bytes(&pk.0) {
                if pqcrypto_dilithium::dilithium3::verify_detached_signature(&sig_obj, message, &pk_obj).is_ok() {
                    let mut h = blake3::Hasher::new_derive_key("unchained-ring-link-mock");
                    // Link tag derived solely from signer's public key so multiple signatures by the
                    // same key are linkable across messages (mock behavior only).
                    h.update(pk_obj.as_bytes());
                    tag = *h.finalize().as_bytes();
                    break;
                }
            }
        }
        Ok((RingSignatureBlob(sig_bytes.to_vec()), LinkTag(tag)))
    }

    fn verify(
        &self,
        message: &[u8],
        ring: &[RingPublicKey],
        signature: &RingSignatureBlob,
        link_tag: &LinkTag,
    ) -> Result<bool> {
        use pqcrypto_traits::sign::DetachedSignature as _;
        let sig = pqcrypto_dilithium::dilithium3::DetachedSignature::from_bytes(&signature.0)
            .map_err(|_| anyhow!("invalid signature format"))?;
        for pk in ring {
            if let Ok(pk_obj) = pqcrypto_dilithium::dilithium3::PublicKey::from_bytes(&pk.0) {
                if pqcrypto_dilithium::dilithium3::verify_detached_signature(&sig, message, &pk_obj).is_ok() {
                    // Check link_tag matches the mock derivation rule
                    let mut h = blake3::Hasher::new_derive_key("unchained-ring-link-mock");
                    h.update(pk_obj.as_bytes());
                    let expected = *h.finalize().as_bytes();
                    return Ok(expected == link_tag.0);
                }
            }
        }
        Ok(false)
    }
}

// Placeholder backend when feature is off to prevent accidental use.
#[cfg(not(feature = "ring_mock"))]
pub struct NoLlrs;

#[cfg(not(feature = "ring_mock"))]
impl RingSignatureScheme for NoLlrs {
    fn sign(
        &self,
        _message: &[u8],
        _ring: &[RingPublicKey],
        _secret_key_bytes: &[u8],
    ) -> Result<(RingSignatureBlob, LinkTag)> {
        Err(anyhow!("LLRS backend not enabled"))
    }

    fn verify(
        &self,
        _message: &[u8],
        _ring: &[RingPublicKey],
        _signature: &RingSignatureBlob,
        _link_tag: &LinkTag,
    ) -> Result<bool> {
        Err(anyhow!("LLRS backend not enabled"))
    }
}


