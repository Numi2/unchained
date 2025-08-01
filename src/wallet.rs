use crate::{
    storage::Store,
    crypto::{self, Address, DILITHIUM3_PK_BYTES, DILITHIUM3_SK_BYTES},
};
use pqcrypto_dilithium::dilithium3::{PublicKey, SecretKey};
use anyhow::{Result, Context};
use std::sync::Arc;
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};

const WALLET_KEY: &[u8] = b"default_keypair";

pub struct Wallet {
    _db: std::sync::Weak<Store>,
    pk: PublicKey,
    sk: SecretKey,
    address: Address,
}

impl Wallet {
    /// Loads the default keypair from the store, or creates a new one if none exists.
    /// This ensures the miner's identity is persistent across restarts.
    pub fn load_or_create(db: Arc<Store>) -> Result<Self> {
        if let Some(encoded) = db.get::<Vec<u8>>("wallet", WALLET_KEY)? {
            let (pk_bytes, sk_bytes) = encoded.split_at(DILITHIUM3_PK_BYTES);
            let pk = PublicKey::from_bytes(pk_bytes)
                .with_context(|| "Failed to decode public key from wallet")?;
            let sk = SecretKey::from_bytes(sk_bytes)
                .with_context(|| "Failed to decode secret key from wallet")?;
            
            let address = crypto::address_from_pk(&pk);
            println!("🔑 Loaded existing wallet. Address: {}", hex::encode(address));
            Ok(Wallet { _db: Arc::downgrade(&db), pk, sk, address })
        } else {
            println!("✨ No wallet found, creating a new one...");
            let (pk, sk) = crypto::dilithium3_keypair();
            let address = crypto::address_from_pk(&pk);

            let mut encoded: Vec<u8> = Vec::with_capacity(DILITHIUM3_PK_BYTES + DILITHIUM3_SK_BYTES);
            encoded.extend_from_slice(pk.as_bytes());
            encoded.extend_from_slice(sk.as_bytes());

            db.put("wallet", WALLET_KEY, &encoded)?;
            println!("✅ New wallet created and saved. Address: {}", hex::encode(address));
            Ok(Wallet { _db: Arc::downgrade(&db), pk, sk, address })
        }
    }

    

    pub fn address(&self) -> Address {
        self.address
    }

    /// Signs a message using the wallet's secret key, returning the detached signature.
    pub fn sign(&self, message: &[u8]) -> pqcrypto_dilithium::dilithium3::DetachedSignature {
        pqcrypto_dilithium::dilithium3::detached_sign(message, &self.sk)
    }

    /// Verifies a message/signature pair using the wallet's public key.
    pub fn verify(&self, message: &[u8], signature: &pqcrypto_dilithium::dilithium3::DetachedSignature) -> bool {
        pqcrypto_dilithium::dilithium3::verify_detached_signature(signature, message, &self.pk).is_ok()
    }
}