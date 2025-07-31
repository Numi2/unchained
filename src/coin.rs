use serde::{Serialize, Deserialize};

/// A self-contained coin object created via PoW
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Coin {
    pub id: [u8; 32],
    pub value: u64,
    pub epoch_hash: [u8; 32],
    pub nonce: u64,
    pub creator_pubkey: [u8; 32],
    pub pow_hash: [u8; 32],  // result of argon2id(content)
}

impl Coin {
    /// Creates the raw input to hash with Argon2id
    pub fn header_bytes(epoch_hash: &[u8; 32], nonce: u64, creator: &[u8; 32]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(epoch_hash);
        bytes.extend_from_slice(&nonce.to_le_bytes());
        bytes.extend_from_slice(creator);
        bytes
    }

    /// Creates a new coin from raw fields + PoW hash
    pub fn new(epoch_hash: [u8; 32], nonce: u64, creator_pubkey: [u8; 32], pow_hash: [u8; 32]) -> Self {
        let mut id_hasher = blake3::Hasher::new();
        id_hasher.update(&epoch_hash);
        id_hasher.update(&nonce.to_le_bytes());
        id_hasher.update(&creator_pubkey);
        id_hasher.update(&pow_hash);
        let id = *id_hasher.finalize().as_bytes();

        Coin {
            id,
            value: 1,
            epoch_hash,
            nonce,
            creator_pubkey,
            pow_hash,
        }
    }

    /// Checks if PoW hash has enough leading zeros
    pub fn is_valid(&self, difficulty: usize) -> bool {
        self.pow_hash.iter().take_while(|&&b| b == 0).count() >= difficulty
    }

    /// Convenience builder for header bytes
    pub fn header(epoch_hash: [u8; 32], nonce: u64, creator: [u8; 32]) -> Vec<u8> {
        Self::header_bytes(&epoch_hash, nonce, &creator)
    }

    /// Assemble coin from header and pow hash
    pub fn assemble(header: Vec<u8>, pow_hash: [u8; 32]) -> Self {
        let (epoch_hash, rest) = header.split_at(32);
        let (nonce_bytes, creator) = rest.split_at(8);
        let epoch_hash: [u8; 32] = epoch_hash.try_into().unwrap();
        let nonce: [u8; 8] = nonce_bytes.try_into().unwrap();
        let creator: [u8; 32] = creator.try_into().unwrap();
        Coin::new(epoch_hash, u64::from_le_bytes(nonce), creator, pow_hash)
    }

    /// Convert coin ID to leaf hash for Merkle tree
    pub fn id_to_leaf_hash(coin_id: &[u8; 32]) -> [u8; 32] {
        crate::crypto::blake3_hash(coin_id)
    }
}