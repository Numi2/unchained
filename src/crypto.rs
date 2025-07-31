use blake3::Hasher;
use argon2::{Argon2, Params, Version, Algorithm};
use pqcrypto_dilithium::dilithium3::{
    DetachedSignature, PublicKey, SecretKey, detached_sign, verify_detached_signature, keypair,
};

pub fn argon2id_pow(input: &[u8], mem_kib: u32, lanes: u32) -> [u8;32] {
    let params = Params::new(mem_kib, 1, lanes, None).unwrap();
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut hash = [0u8; 32];
    a2.hash_password_into(input, b"", &mut hash).unwrap();
    hash
}

pub fn blake3_hash(data: &[u8]) -> [u8;32] {
    *Hasher::new_derive_key("unchained").update(data).finalize().as_bytes()
}

pub fn dilithium3_keypair() -> (PublicKey, SecretKey) { 
    keypair() 
}

pub fn sign(msg: &[u8], sk: &SecretKey) -> DetachedSignature { 
    detached_sign(msg, sk) 
}

pub fn verify(msg: &[u8], sig: &DetachedSignature, pk: &PublicKey) -> bool { 
    verify_detached_signature(sig, msg, pk).is_ok() 
}