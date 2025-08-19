use serde::{Serialize, Deserialize};
use crate::crypto::{Address, DILITHIUM3_PK_BYTES};
use serde_big_array::BigArray;


/// Confirmed coin committed in an epoch anchor (does not store PoW hash).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Coin {
    pub id: [u8; 32],
    pub value: u64,
    pub epoch_hash: [u8; 32],
    pub nonce: u64,
    pub creator_address: Address,
    /// New: full Dilithium3 public key of the coin creator (enables genesis V2 spend validation)
    #[serde(with = "BigArray")]
    pub creator_pk: [u8; DILITHIUM3_PK_BYTES],
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
    /// New: full Dilithium3 public key of the coin creator
    #[serde(with = "BigArray")]
    pub creator_pk: [u8; DILITHIUM3_PK_BYTES],
    /// Signatureless spend lock to be committed at confirmation
    #[serde(default)]
    pub lock_hash: [u8; 32],
    pub pow_hash: [u8; 32],
}

/// Backward-compat struct for legacy coin candidates (no creator_pk/lock_hash fields)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct CoinCandidateV1Compat {
    pub id: [u8; 32],
    pub value: u64,
    pub epoch_hash: [u8; 32],
    pub nonce: u64,
    pub creator_address: Address,
    pub pow_hash: [u8; 32],
}

/// Backward-compat struct for legacy confirmed coins that included pow_hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct CoinV1Compat {
    pub id: [u8; 32],
    pub value: u64,
    pub epoch_hash: [u8; 32],
    pub nonce: u64,
    pub creator_address: Address,
    pub pow_hash: [u8; 32],
}

/// Compatibility struct for coins without lock_hash but with creator_pk
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct CoinV2Compat {
    pub id: [u8; 32],
    pub value: u64,
    pub epoch_hash: [u8; 32],
    pub nonce: u64,
    pub creator_address: Address,
    #[serde(with = "BigArray")]
    pub creator_pk: [u8; DILITHIUM3_PK_BYTES],
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

    /// Calculate the coin ID from its components
    pub fn calculate_id(epoch_hash: &[u8; 32], nonce: u64, creator_address: &Address) -> [u8; 32] {
        let mut id_hasher = blake3::Hasher::new();
        id_hasher.update(epoch_hash);
        id_hasher.update(&nonce.to_le_bytes());
        id_hasher.update(creator_address);
        *id_hasher.finalize().as_bytes()
    }

    /// Creates a new confirmed coin (value=1) from raw fields.
    pub fn new_with_creator_pk_and_lock(epoch_hash: [u8; 32], nonce: u64, creator_address: Address, creator_pk: [u8; DILITHIUM3_PK_BYTES], lock_hash: [u8; 32]) -> Self {
        let id = Self::calculate_id(&epoch_hash, nonce, &creator_address);
        Coin { id, value: 1, epoch_hash, nonce, creator_address, creator_pk, lock_hash }
    }

    /// Backward-compatible constructor (no creator_pk stored)
    pub fn new(epoch_hash: [u8; 32], nonce: u64, creator_address: Address) -> Self {
        Self::new_with_creator_pk_and_lock(epoch_hash, nonce, creator_address, [0u8; DILITHIUM3_PK_BYTES], [0u8; 32])
    }

    /// Convert coin ID to a leaf hash for the Merkle tree.
    pub fn id_to_leaf_hash(coin_id: &[u8; 32]) -> [u8; 32] {
        crate::crypto::blake3_hash(coin_id)
    }
}

impl CoinCandidate {
    pub fn new(epoch_hash: [u8; 32], nonce: u64, creator_address: Address, creator_pk: [u8; DILITHIUM3_PK_BYTES], lock_hash: [u8; 32], pow_hash: [u8; 32]) -> Self {
        let id = Coin::calculate_id(&epoch_hash, nonce, &creator_address);
        CoinCandidate { id, value: 1, epoch_hash, nonce, creator_address, creator_pk, lock_hash, pow_hash }
    }

    pub fn into_confirmed(self) -> Coin {
        Coin { id: self.id, value: self.value, epoch_hash: self.epoch_hash, nonce: self.nonce, creator_address: self.creator_address, creator_pk: self.creator_pk, lock_hash: self.lock_hash }
    }

    /// Convert to legacy candidate format for wire compatibility with older nodes
    pub fn to_v1_compat(&self) -> CoinCandidateV1Compat {
        CoinCandidateV1Compat {
            id: self.id,
            value: self.value,
            epoch_hash: self.epoch_hash,
            nonce: self.nonce,
            creator_address: self.creator_address,
            pow_hash: self.pow_hash,
        }
    }
}

/// Decodes a confirmed coin from bytes, supporting legacy encoding with pow_hash.
pub fn decode_coin(bytes: &[u8]) -> Result<Coin, bincode::Error> {
    match bincode::deserialize::<Coin>(bytes) {
        Ok(c) => Ok(c),
        Err(_) => {
            // Try coin-without-lock-hash layout
            if let Ok(v2) = bincode::deserialize::<CoinV2Compat>(bytes) {
                return Ok(Coin {
                    id: v2.id,
                    value: v2.value,
                    epoch_hash: v2.epoch_hash,
                    nonce: v2.nonce,
                    creator_address: v2.creator_address,
                    creator_pk: v2.creator_pk,
                    lock_hash: [0u8; 32],
                });
            }
            // Legacy fallback (no creator_pk/lock_hash fields).
            let v1: CoinV1Compat = bincode::deserialize(bytes)?;
            Ok(Coin {
                id: v1.id,
                value: v1.value,
                epoch_hash: v1.epoch_hash,
                nonce: v1.nonce,
                creator_address: v1.creator_address,
                creator_pk: [0u8; DILITHIUM3_PK_BYTES],
                lock_hash: [0u8; 32],
            })
        }
    }
}

/// Tolerant decoder for `CoinCandidate` supporting legacy wire format.
pub fn decode_candidate(bytes: &[u8]) -> Result<CoinCandidate, bincode::Error> {
    match bincode::deserialize::<CoinCandidate>(bytes) {
        Ok(c) => Ok(c),
        Err(_) => {
            let v1: CoinCandidateV1Compat = bincode::deserialize(bytes)?;
            Ok(CoinCandidate {
                id: v1.id,
                value: v1.value,
                epoch_hash: v1.epoch_hash,
                nonce: v1.nonce,
                creator_address: v1.creator_address,
                creator_pk: [0u8; DILITHIUM3_PK_BYTES],
                lock_hash: [0u8; 32],
                pow_hash: v1.pow_hash,
            })
        }
    }
}