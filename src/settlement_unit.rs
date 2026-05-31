use crate::crypto::{Address, TaggedSigningPublicKey};
use serde::{Deserialize, Serialize};

const CANDIDATE_ADMISSION_DOMAIN: &str = "unchained.settlement-unit-candidate.admission.v1";

/// Bootstrap settlement unit committed in a finalized checkpoint.
///
/// Settlement units are genesis/bootstrap inputs that materialize into the
/// shielded note ledger. Ordinary user balances live as shielded notes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SettlementUnit {
    pub id: [u8; 32],
    pub value: u64,
    pub epoch_hash: [u8; 32],
    pub nonce: u64,
    pub creator_address: Address,
    /// Full creator signing key tagged with its PQ signature algorithm.
    pub creator_pk: TaggedSigningPublicKey,
    /// Signatureless spend lock: H(preimage_current). For genesis, set during
    /// the bootstrap distribution flow.
    #[serde(default)]
    pub lock_hash: [u8; 32],
}

/// Pending bootstrap settlement unit awaiting deterministic checkpoint admission.
///
/// Admission is digest-ordered by finalized checkpoint state and carries no
/// work target or public ordering market.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SettlementUnitCandidate {
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
    pub admission_digest: [u8; 32],
}

impl SettlementUnit {
    /// Creates the canonical bytes that identify a bootstrap settlement unit.
    pub fn header_bytes(epoch_hash: &[u8; 32], nonce: u64, creator_address: &Address) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + 8 + 32);
        bytes.extend_from_slice(epoch_hash);
        bytes.extend_from_slice(&nonce.to_le_bytes());
        bytes.extend_from_slice(creator_address);
        bytes
    }

    /// Calculate the settlement unit ID from its components.
    pub fn calculate_id(epoch_hash: &[u8; 32], nonce: u64, creator_address: &Address) -> [u8; 32] {
        let mut id_hasher = blake3::Hasher::new();
        id_hasher.update(epoch_hash);
        id_hasher.update(&nonce.to_le_bytes());
        id_hasher.update(creator_address);
        *id_hasher.finalize().as_bytes()
    }

    /// Creates a new confirmed settlement unit (value=1) from raw fields.
    pub fn new_with_creator_pk_and_lock(
        epoch_hash: [u8; 32],
        nonce: u64,
        creator_address: Address,
        creator_pk: TaggedSigningPublicKey,
        lock_hash: [u8; 32],
    ) -> Self {
        let id = Self::calculate_id(&epoch_hash, nonce, &creator_address);
        SettlementUnit {
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

    /// Convert settlement unit ID to a leaf hash for the Merkle tree.
    pub fn id_to_leaf_hash(settlement_unit_id: &[u8; 32]) -> [u8; 32] {
        crate::crypto::blake3_hash(settlement_unit_id)
    }
}

impl SettlementUnitCandidate {
    pub fn admission_digest(
        epoch_hash: &[u8; 32],
        nonce: u64,
        creator_address: &Address,
        creator_pk: &TaggedSigningPublicKey,
        lock_hash: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(CANDIDATE_ADMISSION_DOMAIN);
        hasher.update(epoch_hash);
        hasher.update(&nonce.to_le_bytes());
        hasher.update(creator_address);
        hasher.update(creator_pk.as_slice());
        hasher.update(lock_hash);
        *hasher.finalize().as_bytes()
    }

    pub fn new(
        epoch_hash: [u8; 32],
        nonce: u64,
        creator_address: Address,
        creator_pk: TaggedSigningPublicKey,
        lock_hash: [u8; 32],
    ) -> Self {
        let id = SettlementUnit::calculate_id(&epoch_hash, nonce, &creator_address);
        SettlementUnitCandidate {
            id,
            value: 1,
            epoch_hash,
            nonce,
            creator_address,
            creator_pk: creator_pk.clone(),
            lock_hash,
            admission_digest: Self::admission_digest(
                &epoch_hash,
                nonce,
                &creator_address,
                &creator_pk,
                &lock_hash,
            ),
        }
    }

    pub fn into_confirmed(self) -> SettlementUnit {
        SettlementUnit {
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

pub fn decode_settlement_unit(bytes: &[u8]) -> Result<SettlementUnit, bincode::Error> {
    bincode::deserialize::<SettlementUnit>(bytes)
}

pub fn decode_settlement_unit_candidate(bytes: &[u8]) -> Result<SettlementUnitCandidate, bincode::Error> {
    bincode::deserialize::<SettlementUnitCandidate>(bytes)
}
