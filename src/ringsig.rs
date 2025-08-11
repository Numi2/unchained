use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use serde_bytes;
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _, DetachedSignature as _};

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
        // Flatten ring public keys
        let mut ring_bytes = Vec::with_capacity(ring.len() * DILITHIUM3_PK_BYTES);
        for pk in ring { ring_bytes.extend_from_slice(&pk.0); }

        let mut sig_ptr: *mut u8 = std::ptr::null_mut();
        let mut sig_len: usize = 0;
        let mut tag = [0u8; 32];
        let rc = unsafe {
            llrs_sign(
                message.as_ptr(), message.len(),
                ring_bytes.as_ptr(), ring.len(),
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
        let mut ring_bytes = Vec::with_capacity(ring.len() * DILITHIUM3_PK_BYTES);
        for pk in ring { ring_bytes.extend_from_slice(&pk.0); }
        let rc = unsafe {
            llrs_verify(
                message.as_ptr(), message.len(),
                ring_bytes.as_ptr(), ring.len(),
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
        let tag = crate::crypto::blake3_hash(sig_bytes);
        Ok((RingSignatureBlob(sig_bytes.to_vec()), LinkTag(tag)))
    }

    fn verify(
        &self,
        message: &[u8],
        ring: &[RingPublicKey],
        signature: &RingSignatureBlob,
        _link_tag: &LinkTag,
    ) -> Result<bool> {
        use pqcrypto_traits::sign::DetachedSignature as _;
        let sig = pqcrypto_dilithium::dilithium3::DetachedSignature::from_bytes(&signature.0)
            .map_err(|_| anyhow!("invalid signature format"))?;
        for pk in ring {
            if let Ok(pk_obj) = pqcrypto_dilithium::dilithium3::PublicKey::from_bytes(&pk.0) {
                if pqcrypto_dilithium::dilithium3::verify_detached_signature(&sig, message, &pk_obj).is_ok() {
                    return Ok(true);
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


