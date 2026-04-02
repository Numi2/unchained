use crate::crypto::{Address, TaggedSigningPublicKey};
use serde::{Deserialize, Serialize};

/// Confirmed coin committed in an epoch anchor (does not store PoW hash).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Coin {
    pub id: [u8; 32],
    pub value: u64,
    pub epoch_hash: [u8; 32],
    pub nonce: u64,
    pub creator_address: Address,
    /// Full creator signing key tagged with its PQ signature algorithm.
    pub creator_pk: TaggedSigningPublicKey,
    /// Signatureless spend lock: H(preimage_current). For genesis, set by miner.
    #[serde(default)]
    pub lock_hash: [u8; 32],
}

/// Unconfirmed coin candidate used during selection. Contains the PoW hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct CoinCandidate {
    pub id: [u8; 32],
    pub value: u64,
    pub epoch_hash: [u8; 32],
    pub nonce: u64,
    pub creator_address: Address,
    /// Full creator signing key tagged with its PQ signature algorithm.
    pub creator_pk: TaggedSigningPublicKey,
    /// Signatureless spend lock to be committed at confirmation.
    #[serde(default)]
    pub lock_hash: [u8; 32],
    pub pow_hash: [u8; 32],
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

    /// Calculate the coin ID from its components.
    pub fn calculate_id(epoch_hash: &[u8; 32], nonce: u64, creator_address: &Address) -> [u8; 32] {
        let mut id_hasher = blake3::Hasher::new();
        id_hasher.update(epoch_hash);
        id_hasher.update(&nonce.to_le_bytes());
        id_hasher.update(creator_address);
        *id_hasher.finalize().as_bytes()
    }

    /// Creates a new confirmed coin (value=1) from raw fields.
    pub fn new_with_creator_pk_and_lock(
        epoch_hash: [u8; 32],
        nonce: u64,
        creator_address: Address,
        creator_pk: TaggedSigningPublicKey,
        lock_hash: [u8; 32],
    ) -> Self {
        let id = Self::calculate_id(&epoch_hash, nonce, &creator_address);
        Coin {
            id,
            value: 1,
            epoch_hash,
            nonce,
            creator_address,
            creator_pk,
            lock_hash,
        }
    }

    pub fn new(epoch_hash: [u8; 32], nonce: u64, creator_address: Address) -> Self {
        Self::new_with_creator_pk_and_lock(
            epoch_hash,
            nonce,
            creator_address,
            TaggedSigningPublicKey::zero_ml_dsa_65(),
            [0u8; 32],
        )
    }

    /// Convert coin ID to a leaf hash for the Merkle tree.
    pub fn id_to_leaf_hash(coin_id: &[u8; 32]) -> [u8; 32] {
        crate::crypto::blake3_hash(coin_id)
    }
}

impl CoinCandidate {
    pub fn new(
        epoch_hash: [u8; 32],
        nonce: u64,
        creator_address: Address,
        creator_pk: TaggedSigningPublicKey,
        lock_hash: [u8; 32],
        pow_hash: [u8; 32],
    ) -> Self {
        let id = Coin::calculate_id(&epoch_hash, nonce, &creator_address);
        CoinCandidate {
            id,
            value: 1,
            epoch_hash,
            nonce,
            creator_address,
            creator_pk,
            lock_hash,
            pow_hash,
        }
    }

    pub fn into_confirmed(self) -> Coin {
        Coin {
            id: self.id,
            value: self.value,
            epoch_hash: self.epoch_hash,
            nonce: self.nonce,
            creator_address: self.creator_address,
            creator_pk: self.creator_pk,
            lock_hash: self.lock_hash,
        }
    }
}

pub fn decode_coin(bytes: &[u8]) -> Result<Coin, bincode::Error> {
    bincode::deserialize::<Coin>(bytes)
}

pub fn decode_candidate(bytes: &[u8]) -> Result<CoinCandidate, bincode::Error> {
    bincode::deserialize::<CoinCandidate>(bytes)
}
