use serde::{Serialize, Deserialize};
use crate::crypto::Address;


/// A self-contained coin object created via PoW.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Coin {
    pub id: [u8; 32],
    pub value: u64,
    pub epoch_hash: [u8; 32],
    pub nonce: u64,
    // The creator's address, derived from their public key.
    pub creator_address: Address,
    pub pow_hash: [u8; 32],  // result of argon2id(content)
}

impl Coin {
    /// Creates the raw input to hash with Argon2id.
    pub fn header_bytes(epoch_hash: &[u8; 32], nonce: u64, creator_address: &Address) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + 8 + 32);
        bytes.extend_from_slice(epoch_hash);
        bytes.extend_from_slice(&nonce.to_le_bytes());
        bytes.extend_from_slice(creator_address);
        bytes
    }

    /// Creates a new coin from raw fields + PoW hash.
    pub fn new(epoch_hash: [u8; 32], nonce: u64, creator_address: Address, pow_hash: [u8; 32]) -> Self {
        let mut id_hasher = blake3::Hasher::new();
        id_hasher.update(&epoch_hash);
        id_hasher.update(&nonce.to_le_bytes());
        id_hasher.update(&creator_address);
        id_hasher.update(&pow_hash);
        let id = *id_hasher.finalize().as_bytes();

        Coin {
            id,
            value: 1, // All new coins have a value of 1
            epoch_hash,
            nonce,
            creator_address,
            pow_hash,
        }
    }

    

    /// Convert coin ID to a leaf hash for the Merkle tree.
    pub fn id_to_leaf_hash(coin_id: &[u8; 32]) -> [u8; 32] {
        crate::crypto::blake3_hash(coin_id)
    }
}