// staking.rs
// Copyright 2025 The Unchained Authors
// SPDX-License-Identifier: Apache-2.0

//! Staking implementation for Unchained blockchain
//! Implements Sean Bowe's Tachyon plan adapted for Unchained's architecture

use serde::{Serialize, Deserialize};
use anyhow::{Result, anyhow};
use std::collections::HashSet;
use crate::crypto::Address;
use crate::epoch::Anchor;
use crate::transfer::StealthOutput;
use serde_big_array::BigArray;
use pqcrypto_kyber::kyber768::PublicKey as KyberPk;
use crate::crypto::{KYBER768_CT_BYTES, aead_encrypt_xchacha, kem_encapsulate_to_kyber};
use anyhow::Context;

/// 1. External Sync Proofs - Wallet state transition proof format
/// Wallet builds a zk/PCD proof that its local state (set of spendable outputs/nullifiers)
/// is consistent with anchor history. Third-party sync relays can send wallet "diffs"
/// without learning which outputs belong to it.
/// In Unchained: wallet proves that all nullifiers up to epoch N are accounted for;
/// sync server only relays anchors + epoch data.

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncProof {
    /// The epoch number this proof is valid up to
    pub epoch_num: u64,
    /// Root hash of the wallet's state at this epoch
    pub state_root: [u8; 32],
    /// Commitment to the set of nullifiers the wallet knows about
    pub nullifier_commitment: [u8; 32],
    /// Commitment to the set of outputs the wallet owns
    pub output_commitment: [u8; 32],
    /// Proof that this state is consistent with the anchor history
    pub transition_proof: Vec<u8>,
}

impl SyncProof {
    /// Create a new sync proof for a wallet's state transition
    pub fn new(
        epoch_num: u64,
        state_root: [u8; 32],
        nullifier_commitment: [u8; 32],
        output_commitment: [u8; 32],
        transition_proof: Vec<u8>,
    ) -> Self {
        Self {
            epoch_num,
            state_root,
            nullifier_commitment,
            output_commitment,
            transition_proof,
        }
    }

    /// Verify the sync proof against anchor history
    pub fn verify(&self, anchor_history: &[Anchor], wallet_address: &Address) -> Result<bool> {
        // Verify that the state root is consistent with the anchor history
        let computed_root = self.compute_expected_state_root(anchor_history, wallet_address)?;
        if computed_root != self.state_root {
            return Ok(false);
        }

        // Additional proof verification logic would go here
        // For now, we'll implement basic consistency checks

        Ok(true)
    }

    /// Compute the expected state root from anchor history
    fn compute_expected_state_root(&self, anchor_history: &[Anchor], wallet_address: &Address) -> Result<[u8; 32]> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"unchained-stake-sync-root-v1");
        hasher.update(&self.epoch_num.to_le_bytes());
        hasher.update(wallet_address);

        // Include relevant anchor hashes in the computation
        for anchor in anchor_history.iter().take((self.epoch_num + 1) as usize) {
            hasher.update(&anchor.hash);
        }

        Ok(*hasher.finalize().as_bytes())
    }
}

/// 2. Epoch-State Proof Chains - Proof-carrying data for wallet checkpoints
/// Each wallet checkpoint (per anchor) carries a proof that it is derived correctly from prior anchor.
/// Validators/wallets can prune raw history and just keep last proof chain + current anchor.
/// In Unchained: add WalletProofDoc {anchor_hash, state_root, proof_bytes} that can be re-verified from consensus rules.

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WalletProofDoc {
    /// Hash of the anchor this proof is for
    pub anchor_hash: [u8; 32],
    /// Root of the wallet's state at this anchor
    pub state_root: [u8; 32],
    /// The actual proof bytes (format depends on proof system)
    pub proof_bytes: Vec<u8>,
    /// Epoch number for this proof
    pub epoch_num: u64,
}

impl WalletProofDoc {
    /// Create a new wallet proof document
    pub fn new(anchor_hash: [u8; 32], state_root: [u8; 32], proof_bytes: Vec<u8>, epoch_num: u64) -> Self {
        Self {
            anchor_hash,
            state_root,
            proof_bytes,
            epoch_num,
        }
    }

    /// Verify this proof document against consensus rules
    pub fn verify(&self, anchor: &Anchor) -> Result<bool> {
        // Verify that the anchor hash matches
        if self.anchor_hash != anchor.hash {
            return Ok(false);
        }

        // Additional verification logic would go here
        // This would typically involve verifying a zero-knowledge proof

        Ok(true)
    }
}

/// 3. OOB Spend Notes - Out-of-band secrets for spend notes
/// Remove requirement that sender publishes ciphertext in chain.
/// Instead, sender generates "spend note" (stealth key + amount + memo), encrypts it to recipient,
/// and sends OOB (QR code, URI, P2P message).
/// On-chain, only nullifier + commitment are included.
/// In Unchained: extend SendTx format with output_commitment only; wallet expects OOB spend note to unlock.

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StakeSpendNote {
    /// The stealth output containing encrypted spend information
    pub stealth_output: StealthOutput,
    /// Memo field for additional data (e.g., invoice info)
    pub memo: Option<String>,
    /// Epoch when this spend note was created
    pub epoch_created: u64,
    /// Optional stake-specific metadata
    pub stake_metadata: Option<StakeMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StakeMetadata {
    /// Type of stake operation
    pub operation_type: StakeOperationType,
    /// Amount being staked/unstaked
    pub amount: u64,
    /// Optional lock period in epochs
    pub lock_epochs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StakeOperationType {
    Stake,
    Unstake,
    StakeReward,
}

impl StakeSpendNote {
    /// Create a new stake spend note
    pub fn new(
        stealth_output: StealthOutput,
        memo: Option<String>,
        epoch_created: u64,
        stake_metadata: Option<StakeMetadata>,
    ) -> Self {
        Self {
            stealth_output,
            memo,
            epoch_created,
            stake_metadata,
        }
    }

    /// Encrypt this spend note for a recipient
    pub fn encrypt_for_recipient(&self, recipient_kyber_pk_bytes: &[u8]) -> Result<EncryptedStakeSpendNote> {
        // Parse recipient Kyber768 public key
        let pk = KyberPk::from_bytes(recipient_kyber_pk_bytes)
            .map_err(|_| anyhow!("Invalid Kyber768 public key bytes"))?;

        // Kyber KEM to derive an AEAD key and KEM ciphertext
        let (kem_ct, aead_key32) = kem_encapsulate_to_kyber(&pk);

        // Deterministic, uniqueness-bound XChaCha20-Poly1305 nonce (24 bytes) derived from KEM ct
        // Domain separation ensures nonces are unique per encapsulation
        let mut nonce24 = [0u8; 24];
        let mut h = blake3::Hasher::new();
        h.update(b"stake-note.nonce.v1");
        h.update(&kem_ct);
        let out = h.finalize();
        nonce24.copy_from_slice(&out.as_bytes()[..24]);

        // Serialize plaintext note
        let plaintext = bincode::serialize(self).context("serialize stake spend note")?;

        // AEAD encrypt
        let ciphertext = aead_encrypt_xchacha(&aead_key32, &nonce24, &plaintext)
            .context("stake note AEAD encrypt failed")?;

        Ok(EncryptedStakeSpendNote { kem_ct, nonce24, ciphertext })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedStakeSpendNote {
    /// Kyber768 KEM ciphertext produced during encapsulation
    #[serde(with = "BigArray")]
    pub kem_ct: [u8; KYBER768_CT_BYTES],
    /// XChaCha20-Poly1305 nonce (24 bytes), domain-separated from KEM ct
    pub nonce24: [u8; 24],
    /// AEAD ciphertext of the serialized `StakeSpendNote`
    pub ciphertext: Vec<u8>,
}

/// 4. Anchor-Bound Hashes - Simplified nullifiers
/// Nullifier = H(epoch_anchor | spend_secret).
/// Validators only need nullifiers within current sliding window (e.g. last X anchors).
/// Old anchors and nullifiers can be pruned.
/// In Unchained: store nullifiers in RocksDB column with TTL/pruning rules per epoch.

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StakeNullifier {
    /// The nullifier value
    pub nullifier: [u8; 32],
    /// The epoch anchor this nullifier is bound to
    pub anchor_hash: [u8; 32],
    /// Epoch number when this nullifier was created
    pub epoch_num: u64,
}

impl StakeNullifier {
    /// Create a new anchor-bound nullifier
    pub fn new(anchor_hash: [u8; 32], spend_secret: &[u8; 32], epoch_num: u64) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"unchained-stake-nullifier-v1");
        hasher.update(&anchor_hash);
        hasher.update(spend_secret);

        let nullifier = *hasher.finalize().as_bytes();

        Self {
            nullifier,
            anchor_hash,
            epoch_num,
        }
    }

    /// Verify this nullifier against an anchor
    pub fn verify(&self, spend_secret: &[u8; 32], anchor: &Anchor) -> bool {
        let expected = Self::new(anchor.hash, spend_secret, self.epoch_num);
        expected.nullifier == self.nullifier
    }
}

/// 5. Anchor-Aggregated Actions - Batched spends/outputs into single epoch action proof
/// Allow multiple spends/outputs to be batched into a single epoch action proof.
/// Create a compact structure ("EpochStamp") proving validity of many nullifiers + commitments at once.
/// In Unchained: miner bundles multiple spends in one "EpochActionProof" verified against current anchor.

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StakeEpochProof {
    /// The epoch anchor this proof is for
    pub anchor_hash: [u8; 32],
    /// Epoch number
    pub epoch_num: u64,
    /// Set of nullifiers being spent in this epoch
    pub nullifiers: Vec<StakeNullifier>,
    /// Set of new commitments being created in this epoch
    pub commitments: Vec<[u8; 32]>,
    /// Aggregate proof of validity
    pub aggregate_proof: Vec<u8>,
    /// Merkle root of all coins included in this epoch
    pub merkle_root: [u8; 32],
}

impl StakeEpochProof {
    /// Create a new stake epoch proof
    pub fn new(
        anchor_hash: [u8; 32],
        epoch_num: u64,
        nullifiers: Vec<StakeNullifier>,
        commitments: Vec<[u8; 32]>,
        aggregate_proof: Vec<u8>,
        merkle_root: [u8; 32],
    ) -> Self {
        Self {
            anchor_hash,
            epoch_num,
            nullifiers,
            commitments,
            aggregate_proof,
            merkle_root,
        }
    }

    /// Verify this epoch proof
    pub fn verify(&self, anchor: &Anchor) -> Result<bool> {
        if self.anchor_hash != anchor.hash {
            return Ok(false);
        }

        // Additional verification would go here
        // This would typically involve batch verification of the aggregate proof

        Ok(true)
    }
}

/// 6. Merkle-Prunable Anchors - Validator pruning
/// Anchors commit to full nullifier/commitment set.
/// Validators can prune old epochs after checkpointing anchor hashes.
/// In Unchained: maintain rolling "AnchorRootSet" of last K epochs, drop older state.

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnchorRootSet {
    /// Rolling set of recent anchor hashes (last K epochs)
    pub anchor_hashes: Vec<[u8; 32]>,
    /// Maximum number of anchors to keep
    pub max_anchors: usize,
    /// Current epoch number
    pub current_epoch: u64,
}

impl AnchorRootSet {
    /// Create a new anchor root set
    pub fn new(max_anchors: usize) -> Self {
        Self {
            anchor_hashes: Vec::new(),
            max_anchors,
            current_epoch: 0,
        }
    }

    /// Add a new anchor to the rolling set
    pub fn add_anchor(&mut self, anchor_hash: [u8; 32], epoch_num: u64) {
        self.anchor_hashes.push(anchor_hash);
        self.current_epoch = epoch_num;

        // Prune old anchors if we exceed the limit
        if self.anchor_hashes.len() > self.max_anchors {
            let keep_count = self.anchor_hashes.len() - self.max_anchors;
            self.anchor_hashes = self.anchor_hashes.split_off(keep_count);
        }
    }

    /// Check if an anchor is in the current rolling set
    pub fn contains_anchor(&self, anchor_hash: &[u8; 32]) -> bool {
        self.anchor_hashes.contains(anchor_hash)
    }

    /// Get all anchors newer than a given epoch
    pub fn get_anchors_since(&self, _epoch_num: u64) -> Vec<[u8; 32]> {
        // This is a simplified implementation
        // In practice, we'd need to track epoch numbers with anchor hashes
        self.anchor_hashes.clone()
    }
}

/// 7. Infrastructure - Wallet state management
/// Core wallet state for staking operations

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StakeState {
    /// Wallet's current staked amount
    pub staked_amount: u64,
    /// Total rewards earned
    pub total_rewards: u64,
    /// Epoch when staking started
    pub stake_start_epoch: Option<u64>,
    /// Epoch when staking can be unstaked (if locked)
    pub unlock_epoch: Option<u64>,
    /// Epoch of the last reward distribution checkpoint
    #[serde(default)]
    pub last_reward_epoch: Option<u64>,
    /// Set of coin IDs that are currently staked
    pub staked_coins: HashSet<[u8; 32]>,
    /// Current sync proof for this wallet
    pub current_sync_proof: Option<SyncProof>,
}

impl StakeState {
    /// Create a new stake state
    pub fn new() -> Self {
        Self {
            staked_amount: 0,
            total_rewards: 0,
            stake_start_epoch: None,
            unlock_epoch: None,
            last_reward_epoch: None,
            staked_coins: HashSet::new(),
            current_sync_proof: None,
        }
    }

    /// Stake coins in this wallet
    pub fn stake_coins(&mut self, coin_ids: Vec<[u8; 32]>, amount: u64, current_epoch: u64) -> Result<()> {
        if coin_ids.is_empty() {
            return Err(anyhow!("No coins to stake"));
        }

        let total_stake_amount: u64 = coin_ids.len() as u64;
        if total_stake_amount != amount {
            return Err(anyhow!("Stake amount mismatch"));
        }

        // Update stake state
        self.staked_amount = self.staked_amount.saturating_add(amount);
        self.stake_start_epoch = Some(current_epoch);
        self.staked_coins.extend(coin_ids);

        Ok(())
    }

    /// Unstake coins from this wallet
    pub fn unstake_coins(&mut self, coin_ids: Vec<[u8; 32]>, current_epoch: u64) -> Result<()> {
        if coin_ids.is_empty() {
            return Err(anyhow!("No coins to unstake"));
        }

        // Check if staking period has expired
        if let Some(unlock_epoch) = self.unlock_epoch {
            if current_epoch < unlock_epoch {
                return Err(anyhow!("Staking period not yet expired"));
            }
        }

        // Update stake state
        let unstake_amount = coin_ids.len() as u64;
        self.staked_amount = self.staked_amount.saturating_sub(unstake_amount);
        for coin_id in coin_ids {
            self.staked_coins.remove(&coin_id);
        }

        Ok(())
    }

    /// Add staking rewards
    pub fn add_rewards(&mut self, reward_amount: u64) {
        self.total_rewards = self.total_rewards.saturating_add(reward_amount);
        self.staked_amount = self.staked_amount.saturating_add(reward_amount);
    }

    /// Check if wallet has any staked coins
    pub fn is_staking(&self) -> bool {
        !self.staked_coins.is_empty()
    }
}

/// Stealth coin structure - extends regular coins with staking information
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct StealthCoin {
    /// Base coin ID
    pub coin_id: [u8; 32],
    /// Amount staked (in base coin units)
    pub staked_amount: u64,
    /// Epoch when this coin was staked
    pub stake_epoch: u64,
    /// Epoch when this stake can be unstaked
    pub unlock_epoch: Option<u64>,
    /// Staking rewards earned by this coin
    pub rewards_earned: u64,
    /// Whether this stake is active
    pub is_active: bool,
}

impl StealthCoin {
    /// Create a new stake coin
    pub fn new(coin_id: [u8; 32], staked_amount: u64, stake_epoch: u64, unlock_epoch: Option<u64>) -> Self {
        Self {
            coin_id,
            staked_amount,
            stake_epoch,
            unlock_epoch,
            rewards_earned: 0,
            is_active: true,
        }
    }

    /// Check if this stake can be unstaked at the given epoch
    pub fn can_unstake(&self, current_epoch: u64) -> bool {
        if !self.is_active {
            return false;
        }

        match self.unlock_epoch {
            Some(unlock_epoch) => current_epoch >= unlock_epoch,
            None => true, // No lock period
        }
    }
}

/// Stake spend - extends regular spends with staking operations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StakeSpend {
    /// Base spend information
    pub base_spend: crate::transfer::Spend,
    /// Staking operation type
    pub operation: StakeOperationType,
    /// Amount being staked/unstaked
    pub stake_amount: u64,
    /// Associated stake coin
    pub stake_coin: Option<StealthCoin>,
}

impl StakeSpend {
    /// Create a new stake spend
    pub fn new(
        base_spend: crate::transfer::Spend,
        operation: StakeOperationType,
        stake_amount: u64,
        stake_coin: Option<StealthCoin>,
    ) -> Self {
        Self {
            base_spend,
            operation,
            stake_amount,
            stake_coin,
        }
    }

    /// Validate this stake spend
    pub fn validate(&self, db: &crate::storage::Store) -> Result<()> {
        // Validate base spend first
        self.base_spend.validate(db)?;

        // Additional stake-specific validation
        match self.operation {
            StakeOperationType::Stake => {
                if self.stake_amount == 0 {
                    return Err(anyhow!("Stake amount must be greater than 0"));
                }
            }
            StakeOperationType::Unstake => {
                if let Some(stake_coin) = &self.stake_coin {
                    if !stake_coin.is_active {
                        return Err(anyhow!("Cannot unstake inactive stake"));
                    }
                }
            }
            StakeOperationType::StakeReward => {
                // Rewards are automatically calculated and added
            }
        }

        Ok(())
    }
}
