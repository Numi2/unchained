use crate::consensus::{
    ConsensusPosition, OrderingPath, QuorumCertificate, ValidatorSet, VoteTarget,
    DEFAULT_SLOTS_PER_EPOCH, MAX_COINS_PER_CHECKPOINT,
};
use crate::sync::SyncState;
use crate::{coin::Coin, network::NetHandle, storage::Store};
use anyhow::{bail, Result as AnyResult};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, sync::Arc};
use tokio::{sync::broadcast, time};

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct AnchorProposal {
    pub num: u64,
    pub hash: [u8; 32],
    pub parent_hash: Option<[u8; 32]>,
    pub position: ConsensusPosition,
    pub ordering_path: OrderingPath,
    pub merkle_root: [u8; 32],
    pub coin_count: u32,
    pub dag_round: u64,
    pub dag_frontier: Vec<[u8; 32]>,
    pub ordered_batch_ids: Vec<[u8; 32]>,
    pub ordered_tx_root: [u8; 32],
    pub ordered_tx_count: u32,
    pub validator_set: ValidatorSet,
}

impl AnchorProposal {
    pub fn position_for_num(num: u64) -> ConsensusPosition {
        let slots_per_epoch = DEFAULT_SLOTS_PER_EPOCH as u64;
        ConsensusPosition {
            epoch: num / slots_per_epoch,
            slot: (num % slots_per_epoch) as u32,
        }
    }

    pub fn compute_hash(
        num: u64,
        parent_hash: Option<[u8; 32]>,
        position: ConsensusPosition,
        ordering_path: OrderingPath,
        merkle_root: [u8; 32],
        coin_count: u32,
        dag_round: u64,
        dag_frontier: &[[u8; 32]],
        ordered_batch_ids: &[[u8; 32]],
        ordered_tx_root: [u8; 32],
        ordered_tx_count: u32,
        validator_set: &ValidatorSet,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("unchained.finalized-checkpoint.digest.v1");
        hasher.update(&num.to_le_bytes());
        match parent_hash {
            Some(parent_hash) => {
                hasher.update(&[1]);
                hasher.update(&parent_hash);
            }
            None => {
                hasher.update(&[0]);
            }
        }
        hasher.update(&position.epoch.to_le_bytes());
        hasher.update(&position.slot.to_le_bytes());
        hasher.update(&[match ordering_path {
            OrderingPath::FastPathPrivateTransfer => 0,
            OrderingPath::DagBftSharedState => 1,
        }]);
        hasher.update(&merkle_root);
        hasher.update(&coin_count.to_le_bytes());
        hasher.update(&dag_round.to_le_bytes());
        hasher.update(&(dag_frontier.len() as u64).to_le_bytes());
        for batch_id in dag_frontier {
            hasher.update(batch_id);
        }
        hasher.update(&(ordered_batch_ids.len() as u64).to_le_bytes());
        for batch_id in ordered_batch_ids {
            hasher.update(batch_id);
        }
        hasher.update(&ordered_tx_root);
        hasher.update(&ordered_tx_count.to_le_bytes());
        hasher.update(&validator_set.committee_hash());
        *hasher.finalize().as_bytes()
    }

    pub fn new(
        num: u64,
        parent_hash: Option<[u8; 32]>,
        ordering_path: OrderingPath,
        merkle_root: [u8; 32],
        coin_count: u32,
        dag_round: u64,
        dag_frontier: Vec<[u8; 32]>,
        ordered_batch_ids: Vec<[u8; 32]>,
        ordered_tx_root: [u8; 32],
        ordered_tx_count: u32,
        validator_set: ValidatorSet,
    ) -> AnyResult<Self> {
        let mut dag_frontier = dag_frontier;
        dag_frontier.sort();
        let position = Anchor::position_for_num(num);
        let hash = Self::compute_hash(
            num,
            parent_hash,
            position,
            ordering_path,
            merkle_root,
            coin_count,
            dag_round,
            &dag_frontier,
            &ordered_batch_ids,
            ordered_tx_root,
            ordered_tx_count,
            &validator_set,
        );
        let proposal = Self {
            num,
            hash,
            parent_hash,
            position,
            ordering_path,
            merkle_root,
            coin_count,
            dag_round,
            dag_frontier,
            ordered_batch_ids,
            ordered_tx_root,
            ordered_tx_count,
            validator_set,
        };
        validate_proposal_invariants(&proposal)?;
        Ok(proposal)
    }

    pub fn vote_target(&self) -> VoteTarget {
        VoteTarget {
            position: self.position,
            ordering_path: self.ordering_path,
            block_digest: self.hash,
        }
    }

    pub fn validate_against_parent(&self, parent: Option<&Anchor>) -> AnyResult<()> {
        validate_proposal_fields(self, parent)
    }

    pub fn finalize(self, qc: QuorumCertificate) -> AnyResult<Anchor> {
        validate_proposal_invariants(&self)?;
        qc.validate(&self.validator_set)?;
        if qc.target != self.vote_target() {
            bail!("checkpoint QC target does not match proposal");
        }
        let anchor = Anchor {
            num: self.num,
            hash: self.hash,
            parent_hash: self.parent_hash,
            position: self.position,
            ordering_path: self.ordering_path,
            merkle_root: self.merkle_root,
            coin_count: self.coin_count,
            dag_round: self.dag_round,
            dag_frontier: self.dag_frontier,
            ordered_batch_ids: self.ordered_batch_ids,
            ordered_tx_root: self.ordered_tx_root,
            ordered_tx_count: self.ordered_tx_count,
            validator_set: self.validator_set,
            qc,
        };
        Ok(anchor)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub num: u64,
    pub hash: [u8; 32],
    pub parent_hash: Option<[u8; 32]>,
    pub position: ConsensusPosition,
    pub ordering_path: OrderingPath,
    pub merkle_root: [u8; 32],
    pub coin_count: u32,
    pub dag_round: u64,
    pub dag_frontier: Vec<[u8; 32]>,
    pub ordered_batch_ids: Vec<[u8; 32]>,
    pub ordered_tx_root: [u8; 32],
    pub ordered_tx_count: u32,
    pub validator_set: ValidatorSet,
    pub qc: QuorumCertificate,
}

impl Anchor {
    pub fn position_for_num(num: u64) -> ConsensusPosition {
        AnchorProposal::position_for_num(num)
    }

    pub fn compute_hash(
        num: u64,
        parent_hash: Option<[u8; 32]>,
        position: ConsensusPosition,
        ordering_path: OrderingPath,
        merkle_root: [u8; 32],
        coin_count: u32,
        dag_round: u64,
        dag_frontier: &[[u8; 32]],
        ordered_batch_ids: &[[u8; 32]],
        ordered_tx_root: [u8; 32],
        ordered_tx_count: u32,
        validator_set: &ValidatorSet,
    ) -> [u8; 32] {
        AnchorProposal::compute_hash(
            num,
            parent_hash,
            position,
            ordering_path,
            merkle_root,
            coin_count,
            dag_round,
            dag_frontier,
            ordered_batch_ids,
            ordered_tx_root,
            ordered_tx_count,
            validator_set,
        )
    }

    pub fn new(
        num: u64,
        parent_hash: Option<[u8; 32]>,
        ordering_path: OrderingPath,
        merkle_root: [u8; 32],
        coin_count: u32,
        dag_round: u64,
        dag_frontier: Vec<[u8; 32]>,
        ordered_batch_ids: Vec<[u8; 32]>,
        ordered_tx_root: [u8; 32],
        ordered_tx_count: u32,
        validator_set: ValidatorSet,
        qc: QuorumCertificate,
    ) -> AnyResult<Self> {
        AnchorProposal::new(
            num,
            parent_hash,
            ordering_path,
            merkle_root,
            coin_count,
            dag_round,
            dag_frontier,
            ordered_batch_ids,
            ordered_tx_root,
            ordered_tx_count,
            validator_set,
        )?
        .finalize(qc)
    }

    pub fn validate_against_parent(&self, parent: Option<&Anchor>) -> AnyResult<()> {
        validate_proposal_fields(
            &AnchorProposal {
                num: self.num,
                hash: self.hash,
                parent_hash: self.parent_hash,
                position: self.position,
                ordering_path: self.ordering_path,
                merkle_root: self.merkle_root,
                coin_count: self.coin_count,
                dag_round: self.dag_round,
                dag_frontier: self.dag_frontier.clone(),
                ordered_batch_ids: self.ordered_batch_ids.clone(),
                ordered_tx_root: self.ordered_tx_root,
                ordered_tx_count: self.ordered_tx_count,
                validator_set: self.validator_set.clone(),
            },
            parent,
        )?;
        self.qc.validate(&self.validator_set)?;
        if self.qc.target.position != self.position {
            bail!("checkpoint QC position mismatch");
        }
        if self.qc.target.ordering_path != self.ordering_path {
            bail!("checkpoint QC ordering path mismatch");
        }
        if self.qc.target.block_digest != self.hash {
            bail!("checkpoint QC block digest mismatch");
        }

        match parent {
            None => {
                if self.num != 0 {
                    bail!("non-genesis checkpoint requires a parent");
                }
                if self.parent_hash.is_some() {
                    bail!("genesis checkpoint cannot reference a parent hash");
                }
            }
            Some(parent) => {
                if self.num != parent.num.saturating_add(1) {
                    bail!("checkpoint numbering must be contiguous");
                }
                if self.parent_hash != Some(parent.hash) {
                    bail!("checkpoint parent hash mismatch");
                }
                if self.ordering_path == OrderingPath::DagBftSharedState {
                    let parent_round = if self.position.epoch == parent.position.epoch {
                        parent.dag_round
                    } else {
                        0
                    };
                    if self.dag_round <= parent_round {
                        bail!(
                            "shared-state DAG round must increase beyond the finalized parent round"
                        );
                    }
                }
                if self.position.epoch == parent.position.epoch {
                    if self.validator_set.committee_hash() != parent.validator_set.committee_hash()
                    {
                        bail!("validator committee changes are only admitted at epoch boundaries");
                    }
                } else if self.position.epoch != parent.position.epoch.saturating_add(1)
                    || self.position.slot != 0
                {
                    bail!("validator committee changes must happen exactly at epoch boundaries");
                }
            }
        }
        Ok(())
    }
}

fn validate_proposal_fields(proposal: &AnchorProposal, parent: Option<&Anchor>) -> AnyResult<()> {
    validate_proposal_invariants(proposal)?;
    match parent {
        None => {
            if proposal.num != 0 {
                bail!("non-genesis checkpoint requires a parent");
            }
            if proposal.parent_hash.is_some() {
                bail!("genesis checkpoint cannot reference a parent hash");
            }
        }
        Some(parent) => {
            if proposal.num != parent.num.saturating_add(1) {
                bail!("checkpoint numbering must be contiguous");
            }
            if proposal.parent_hash != Some(parent.hash) {
                bail!("checkpoint parent hash mismatch");
            }
            if proposal.ordering_path == OrderingPath::DagBftSharedState {
                let parent_round = if proposal.position.epoch == parent.position.epoch {
                    parent.dag_round
                } else {
                    0
                };
                if proposal.dag_round <= parent_round {
                    bail!("shared-state DAG round must increase beyond the finalized parent round");
                }
            }
            if proposal.position.epoch == parent.position.epoch {
                if proposal.validator_set.committee_hash() != parent.validator_set.committee_hash()
                {
                    bail!("validator committee changes are only admitted at epoch boundaries");
                }
            } else if proposal.position.epoch != parent.position.epoch.saturating_add(1)
                || proposal.position.slot != 0
            {
                bail!("validator committee changes must happen exactly at epoch boundaries");
            }
        }
    }
    Ok(())
}

fn validate_proposal_invariants(proposal: &AnchorProposal) -> AnyResult<()> {
    if proposal.coin_count > MAX_COINS_PER_CHECKPOINT {
        bail!(
            "checkpoint coin count exceeds protocol cap: {} > {}",
            proposal.coin_count,
            MAX_COINS_PER_CHECKPOINT
        );
    }
    let expected_position = Anchor::position_for_num(proposal.num);
    if proposal.position != expected_position {
        bail!(
            "checkpoint position mismatch: expected epoch {} slot {}, got epoch {} slot {}",
            expected_position.epoch,
            expected_position.slot,
            proposal.position.epoch,
            proposal.position.slot
        );
    }
    if proposal.validator_set.epoch != proposal.position.epoch {
        bail!("validator set epoch must match checkpoint epoch");
    }
    match proposal.ordering_path {
        OrderingPath::FastPathPrivateTransfer => {
            if proposal.ordered_tx_count != 0
                || proposal.ordered_tx_root != [0u8; 32]
                || proposal.dag_round != 0
                || !proposal.dag_frontier.is_empty()
                || !proposal.ordered_batch_ids.is_empty()
            {
                bail!("fast-path checkpoints cannot commit shared-state batches");
            }
        }
        OrderingPath::DagBftSharedState => {
            if proposal.coin_count != 0 || proposal.merkle_root != [0u8; 32] {
                bail!("shared-state checkpoints cannot carry ordinary transfer coin commitments");
            }
            if proposal.dag_round == 0 {
                bail!("shared-state checkpoints must commit a non-zero DAG round");
            }
            if proposal.dag_frontier.is_empty() {
                bail!("shared-state checkpoints must commit a non-empty DAG frontier");
            }
            if proposal.ordered_batch_ids.is_empty() {
                bail!("shared-state checkpoints must commit ordered DAG batch ids");
            }
            if proposal.ordered_tx_count == 0 || proposal.ordered_tx_root == [0u8; 32] {
                bail!("shared-state checkpoints must commit a non-empty ordered tx batch");
            }
        }
    }
    let mut last_frontier = None;
    for batch_id in &proposal.dag_frontier {
        if *batch_id == [0u8; 32] {
            bail!("DAG frontier batch id cannot be zero");
        }
        if last_frontier == Some(*batch_id) {
            bail!("DAG frontier contains duplicate batch ids");
        }
        last_frontier = Some(*batch_id);
    }
    let mut seen_ordered = std::collections::BTreeSet::new();
    for batch_id in &proposal.ordered_batch_ids {
        if *batch_id == [0u8; 32] {
            bail!("ordered DAG batch id cannot be zero");
        }
        if !seen_ordered.insert(*batch_id) {
            bail!("ordered DAG batch list contains duplicate ids");
        }
    }
    let expected_hash = Anchor::compute_hash(
        proposal.num,
        proposal.parent_hash,
        proposal.position,
        proposal.ordering_path,
        proposal.merkle_root,
        proposal.coin_count,
        proposal.dag_round,
        &proposal.dag_frontier,
        &proposal.ordered_batch_ids,
        proposal.ordered_tx_root,
        proposal.ordered_tx_count,
        &proposal.validator_set,
    );
    if proposal.hash != expected_hash {
        bail!("checkpoint hash mismatch");
    }
    Ok(())
}

pub struct MerkleTree;
impl MerkleTree {
    /// Build all Merkle levels from sorted leaves. levels[0] = sorted leaves, levels.last()[0] = root.
    pub fn build_levels_from_sorted_leaves(sorted_leaves: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
        let mut levels: Vec<Vec<[u8; 32]>> = Vec::new();
        if sorted_leaves.is_empty() {
            return levels;
        }
        let mut level: Vec<[u8; 32]> = sorted_leaves.to_vec();
        levels.push(level.clone());
        while level.len() > 1 {
            let mut next_level: Vec<[u8; 32]> = Vec::with_capacity(level.len().div_ceil(2));
            for chunk in level.chunks(2) {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&chunk[0]);
                hasher.update(chunk.get(1).unwrap_or(&chunk[0]));
                next_level.push(*hasher.finalize().as_bytes());
            }
            levels.push(next_level.clone());
            level = next_level;
        }
        levels
    }

    /// Build proof using precomputed levels and target leaf hash. levels[0] must contain target_leaf.
    pub fn build_proof_from_levels(
        levels: &Vec<Vec<[u8; 32]>>,
        target_leaf: &[u8; 32],
    ) -> Option<Vec<([u8; 32], bool)>> {
        if levels.is_empty() {
            return None;
        }
        let mut index = levels[0].iter().position(|h| h == target_leaf)?;
        let mut proof: Vec<([u8; 32], bool)> = Vec::new();
        for level in &levels[..levels.len() - 1] {
            if level.is_empty() {
                return None;
            }
            let (sibling_hash, sibling_is_left) = if index % 2 == 0 {
                let sib = *level.get(index + 1).unwrap_or(&level[index]);
                (sib, false)
            } else {
                let sib = level[index - 1];
                (sib, true)
            };
            proof.push((sibling_hash, sibling_is_left));
            index /= 2;
        }
        Some(proof)
    }
    /// Compute Merkle root from a set of coin IDs. This method:
    /// - Hashes each coin id into a leaf using `Coin::id_to_leaf_hash`
    /// - Sorts leaves ascending to obtain a canonical order
    /// - Reduces pairwise (duplicate last when odd) using BLAKE3
    pub fn build_root(coin_ids: &HashSet<[u8; 32]>) -> [u8; 32] {
        if coin_ids.is_empty() {
            return [0u8; 32];
        }
        let mut leaves: Vec<[u8; 32]> = coin_ids.iter().map(Coin::id_to_leaf_hash).collect();
        leaves.sort();
        Self::compute_root_from_sorted_leaves(&leaves)
    }
}
impl MerkleTree {
    /// Compute Merkle root from a precomputed sorted leaf list.
    /// The `sorted_leaves` slice MUST be sorted ascending.
    pub fn compute_root_from_sorted_leaves(sorted_leaves: &[[u8; 32]]) -> [u8; 32] {
        if sorted_leaves.is_empty() {
            return [0u8; 32];
        }
        let mut level: Vec<[u8; 32]> = sorted_leaves.to_vec();
        while level.len() > 1 {
            let mut next_level = Vec::with_capacity(level.len().div_ceil(2));
            for chunk in level.chunks(2) {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&chunk[0]);
                hasher.update(chunk.get(1).unwrap_or(&chunk[0]));
                next_level.push(*hasher.finalize().as_bytes());
            }
            level = next_level;
        }
        level[0]
    }
    pub fn build_proof(
        coin_ids: &HashSet<[u8; 32]>,
        target_id: &[u8; 32],
    ) -> Option<Vec<([u8; 32], bool)>> {
        if coin_ids.is_empty() {
            return None;
        }
        let mut leaves: Vec<[u8; 32]> = coin_ids.iter().map(Coin::id_to_leaf_hash).collect();
        leaves.sort();
        let leaf_hash = Coin::id_to_leaf_hash(target_id);
        let mut index = leaves.iter().position(|h| h == &leaf_hash)?;
        let mut level = leaves;
        let mut proof: Vec<([u8; 32], bool)> = Vec::new();
        while level.len() > 1 {
            let (sibling_hash, sibling_is_left) = if index % 2 == 0 {
                let sib = *level.get(index + 1).unwrap_or(&level[index]);
                (sib, false)
            } else {
                let sib = level[index - 1];
                (sib, true)
            };
            proof.push((sibling_hash, sibling_is_left));
            let mut next_level = Vec::with_capacity(level.len().div_ceil(2));
            for chunk in level.chunks(2) {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&chunk[0]);
                hasher.update(chunk.get(1).unwrap_or(&chunk[0]));
                next_level.push(*hasher.finalize().as_bytes());
            }
            index /= 2;
            level = next_level;
        }
        Some(proof)
    }

    /// Build a Merkle proof using a precomputed sorted leaf list.
    /// `sorted_leaves` must be sorted ascending and contain `target_leaf`.
    pub fn build_proof_from_leaves(
        sorted_leaves: &[[u8; 32]],
        target_leaf: &[u8; 32],
    ) -> Option<Vec<([u8; 32], bool)>> {
        if sorted_leaves.is_empty() {
            return None;
        }
        let mut index = sorted_leaves.iter().position(|h| h == target_leaf)?;
        let mut level: Vec<[u8; 32]> = sorted_leaves.to_vec();
        let mut proof: Vec<([u8; 32], bool)> = Vec::new();
        while level.len() > 1 {
            let (sibling_hash, sibling_is_left) = if index % 2 == 0 {
                let sib = *level.get(index + 1).unwrap_or(&level[index]);
                (sib, false)
            } else {
                let sib = level[index - 1];
                (sib, true)
            };
            proof.push((sibling_hash, sibling_is_left));
            let mut next_level = Vec::with_capacity(level.len().div_ceil(2));
            for chunk in level.chunks(2) {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&chunk[0]);
                hasher.update(chunk.get(1).unwrap_or(&chunk[0]));
                next_level.push(*hasher.finalize().as_bytes());
            }
            index /= 2;
            level = next_level;
        }
        Some(proof)
    }

    /// Maximum accepted Merkle depth for proofs. Conservative upper bound to
    /// reject pathological inputs without affecting valid trees.
    pub const MAX_PROOF_DEPTH: usize = 64;

    pub fn verify_proof(leaf_hash: &[u8; 32], proof: &[([u8; 32], bool)], root: &[u8; 32]) -> bool {
        // Basic sanity bound: prevents absurdly large proofs from causing CPU burn.
        if proof.len() > Self::MAX_PROOF_DEPTH {
            return false;
        }
        let mut computed = *leaf_hash;
        for (sibling, sibling_is_left) in proof {
            let mut hasher = blake3::Hasher::new();
            if *sibling_is_left {
                hasher.update(sibling);
                hasher.update(&computed);
            } else {
                hasher.update(&computed);
                hasher.update(sibling);
            }
            computed = *hasher.finalize().as_bytes();
        }
        &computed == root
    }

    /// Expected proof length (tree height) for a Merkle tree with `coin_count` leaves,
    /// using the canonical odd-node duplication strategy. For example:
    /// - 1 -> 0, 2 -> 1, 3..4 -> 2, 5..8 -> 3, etc.
    #[inline]
    pub fn expected_proof_len(coin_count: u32) -> usize {
        if coin_count <= 1 {
            0
        } else {
            (32 - (coin_count - 1).leading_zeros()) as usize
        }
    }
}

pub struct Manager {
    db: Arc<Store>,
    net_cfg: crate::config::Net,
    net: NetHandle,
    anchor_tx: broadcast::Sender<Anchor>,
    shutdown_rx: broadcast::Receiver<()>,
    sync_state: std::sync::Arc<std::sync::Mutex<SyncState>>,
}
impl Manager {
    pub fn new(
        db: Arc<Store>,
        net_cfg: crate::config::Net,
        net: NetHandle,
        shutdown_rx: broadcast::Receiver<()>,
        sync_state: std::sync::Arc<std::sync::Mutex<SyncState>>,
    ) -> Self {
        let anchor_tx = net.anchor_sender();
        Self {
            db,
            net_cfg,
            net,
            anchor_tx,
            shutdown_rx,
            sync_state,
        }
    }

    pub fn spawn_loop(mut self) {
        tokio::spawn(async move {
            let mut current_epoch = match self.db.get::<Anchor>("epoch", b"latest") {
                Ok(Some(anchor)) => anchor.num + 1,
                Ok(None) => 0,
                Err(_) => 0,
            };

            if current_epoch == 0 {
                println!("🔄 Initial network synchronization phase...");
                self.net.request_latest_epoch().await;

                let sync_timeout = tokio::time::Duration::from_secs(self.net_cfg.sync_timeout_secs);
                let sync_start = tokio::time::Instant::now();

                while sync_start.elapsed() < sync_timeout {
                    if let Ok(Some(latest_anchor)) = self.db.get::<Anchor>("epoch", b"latest") {
                        if latest_anchor.num > 0 {
                            current_epoch = latest_anchor.num + 1;
                            println!(
                                "✅ Network synchronization complete! Starting from epoch {}",
                                current_epoch
                            );
                            break;
                        }
                    }
                    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;
                }

                if current_epoch == 0 {
                    if self.net_cfg.bootstrap.is_empty() {
                        println!("⚠️  Network synchronization timeout or no peers found. Starting from genesis (no bootstrap configured).");
                    } else {
                        println!("⚠️  Network sync timed out but bootstrap peers are configured; not creating local genesis. Waiting for network.");
                    }
                }
            }

            // Tick immediately on startup for all cases; no restart grace period
            let checkpoint_cadence = time::Duration::from_millis(
                (crate::protocol::CURRENT.slots_per_epoch as u64)
                    .saturating_mul(crate::protocol::CURRENT.slot_duration_ms)
                    .max(1),
            );
            let mut ticker = time::interval_at(time::Instant::now(), checkpoint_cadence);
            // Prevent bursty catch-up ticks from causing multiple seals in quick succession.
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            loop {
                tokio::select! {
                    biased;
                    _ = self.shutdown_rx.recv() => {
                        println!("🛑 Epoch manager received shutdown signal");
                        break;
                    }
                    _ = ticker.tick() => {
                        if let Ok(Some(latest_anchor)) = self.db.get::<Anchor>("epoch", b"latest") {
                            if latest_anchor.num >= current_epoch {
                                current_epoch = latest_anchor.num.saturating_add(1);
                            }
                        }

                        // When bootstrap peers are configured, strictly avoid producing epochs until fully synced with peers.
                        if !self.net_cfg.bootstrap.is_empty() {
                            let (synced, highest_seen, peer_confirmed) = self
                                .sync_state
                                .lock()
                                .map(|s| (s.synced, s.highest_seen_epoch, s.peer_confirmed_tip))
                                .unwrap_or((false, 0, false));
                            let local_latest = self.db.get::<Anchor>("epoch", b"latest").unwrap_or(None).map(|a| a.num).unwrap_or(0);
                            let fully_caught_up = local_latest >= highest_seen && highest_seen > 0;
                            if !(synced && fully_caught_up && peer_confirmed) {
                                // Keep requesting latest and fast-forward our cursor to any newly stored tip
                                self.net.request_latest_epoch().await;
                                if current_epoch > 0 {
                                    if let Ok(Some(latest_anchor)) = self.db.get::<Anchor>("epoch", b"latest") {
                                        if latest_anchor.num >= current_epoch {
                                            current_epoch = latest_anchor.num + 1;
                                        }
                                    }
                                }
                                println!(
                                    "⏳ Waiting for full sync before producing: local={}, network={}, peer-confirmed={}",
                                    local_latest, highest_seen, peer_confirmed
                                );
                                continue;
                            }
                        }


                        if current_epoch == 0 {
                            if self.net_cfg.bootstrap.is_empty() {
                                println!("🌱 No existing epochs found. Creating genesis anchor (no bootstrap configured)...");
                            } else {
                                // Avoid creating a forked genesis when we expect a network
                                println!("⏳ Waiting for network genesis (bootstrap configured), not creating local genesis.");
                                continue;
                            }
                        }


                        match self.net.select_pending_shared_state_batch() {
                            Ok(Some(shared_state_batch)) => {
                                if let Err(err) = self
                                    .net
                                    .author_local_shared_state_batch(&shared_state_batch)
                                    .await
                                {
                                    eprintln!("⚠️ Failed authoring shared-state DAG batch: {}", err);
                                }
                            }
                            Ok(None) => {}
                            Err(err) => {
                                eprintln!("⚠️ Failed selecting shared-state batch: {}", err);
                            }
                        }

                        match self.net.finalize_available_fast_path_anchor().await {
                            Ok(Some(anchor)) => {
                                crate::metrics::EPOCH_HEIGHT.set(anchor.num as i64);
                                crate::metrics::SELECTED_COINS.set(anchor.coin_count as i64);
                                if let Err(e) = self.anchor_tx.send(anchor.clone()) {
                                    eprintln!("⚠️  Failed to broadcast fast-path anchor: {}", e);
                                }
                                current_epoch = anchor.num.saturating_add(1);
                                ticker =
                                    time::interval_at(time::Instant::now() + checkpoint_cadence, checkpoint_cadence);
                                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                                continue;
                            }
                            Ok(None) => {}
                            Err(err) => {
                                eprintln!(
                                    "⏳ Local fast-path checkpoint {} not certified: {}",
                                    current_epoch, err
                                );
                            }
                        }

                        match self.net.finalize_available_shared_state_anchor().await {
                            Ok(Some(anchor)) => {
                                crate::metrics::EPOCH_HEIGHT.set(anchor.num as i64);
                                if let Err(e) = self.anchor_tx.send(anchor.clone()) {
                                    eprintln!("⚠️  Failed to broadcast shared-state anchor: {}", e);
                                }
                                current_epoch = anchor.num.saturating_add(1);
                                ticker =
                                    time::interval_at(time::Instant::now() + checkpoint_cadence, checkpoint_cadence);
                                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                                continue;
                            }
                            Ok(None) => {}
                            Err(err) => {
                                eprintln!(
                                    "⏳ Local shared-state checkpoint {} not certified: {}",
                                    current_epoch, err
                                );
                            }
                        }
                    }
                }
            }
            println!("✅ Epoch manager shutdown complete");
        });
    }
}

/// Select candidates for a specific epoch based on parent anchor and capacity
/// This function is used during reorgs to reconstruct the selected set
pub fn select_candidates_for_epoch(
    db: &crate::storage::Store,
    parent: &Anchor,
    cap: usize,
    buffer: Option<&std::collections::HashSet<[u8; 32]>>,
) -> (Vec<crate::coin::CoinCandidate>, usize) {
    // Collect candidates for this epoch hash and optionally merge locally buffered ids
    let mut candidates = match db.get_coin_candidates_by_epoch_hash(&parent.hash) {
        Ok(v) => v,
        Err(_) => Vec::new(),
    };
    // Track existing candidate IDs to avoid O(n^2) scans during merge
    let mut candidate_ids: std::collections::HashSet<[u8; 32]> =
        std::collections::HashSet::from_iter(candidates.iter().map(|c| c.id));
    if let Some(buf) = buffer {
        for id in buf.iter() {
            if candidate_ids.contains(id) {
                continue;
            }
            let key = crate::storage::Store::candidate_key(&parent.hash, id);
            if let Ok(Some(c)) = db.get::<crate::coin::CoinCandidate>("coin_candidate", &key) {
                candidate_ids.insert(c.id);
                candidates.push(c);
            }
        }
    }

    if cap == 0 {
        return (Vec::new(), 0);
    }

    let mut filtered: Vec<crate::coin::CoinCandidate> = Vec::new();
    let mut total_candidates = 0usize;
    for cand in candidates.into_iter() {
        total_candidates += 1;
        filtered.push(cand);
    }

    // Global order by admission digest, then id (deterministic)
    filtered.sort_by(|a, b| {
        a.admission_digest
            .cmp(&b.admission_digest)
            .then_with(|| a.id.cmp(&b.id))
    });

    // Fair, round-based selection across creators while preserving global order.
    use std::collections::{HashMap, HashSet};
    let mut picked: Vec<crate::coin::CoinCandidate> = Vec::with_capacity(cap);
    let mut by_creator: HashMap<[u8; 32], usize> = HashMap::new();
    let mut round: usize = 0;
    let mut picked_ids: HashSet<[u8; 32]> = HashSet::new();

    while picked.len() < cap {
        let mut advanced = false;
        for c in filtered.iter() {
            if picked.len() >= cap {
                break;
            }
            let cnt = *by_creator.get(&c.creator_address).unwrap_or(&0);
            if cnt == round && !picked_ids.contains(&c.id) {
                picked.push(c.clone());
                picked_ids.insert(c.id);
                by_creator.insert(c.creator_address, cnt + 1);
                advanced = true;
                if picked.len() >= cap {
                    break;
                }
            }
        }
        if !advanced {
            break;
        }
        round += 1;
    }

    // Ensure deterministic ordering of the selected set
    picked.sort_by(|a, b| {
        a.admission_digest
            .cmp(&b.admission_digest)
            .then_with(|| a.id.cmp(&b.id))
    });

    (picked, total_candidates)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{Validator, ValidatorKeys, ValidatorVote, VoteTarget};
    use crate::crypto::{ml_dsa_65_generate, ml_dsa_65_public_key_spki, ml_dsa_65_sign};
    use aws_lc_rs::unstable::signature::PqdsaKeyPair;

    fn validator(voting_power: u64) -> (Validator, PqdsaKeyPair) {
        let hot_key = ml_dsa_65_generate().unwrap();
        let cold_key = ml_dsa_65_generate().unwrap();
        (
            Validator::new(
                voting_power,
                ValidatorKeys {
                    hot_ml_dsa_65_spki: ml_dsa_65_public_key_spki(&hot_key).unwrap(),
                    cold_governance_key: ml_dsa_65_public_key_spki(&cold_key).unwrap(),
                },
            )
            .unwrap(),
            hot_key,
        )
    }

    fn anchor_with_validator_set(
        num: u64,
        parent_hash: Option<[u8; 32]>,
        validator_set: ValidatorSet,
        signing_keys: &[&PqdsaKeyPair],
    ) -> Anchor {
        let position = Anchor::position_for_num(num);
        let hash = Anchor::compute_hash(
            num,
            parent_hash,
            position,
            OrderingPath::FastPathPrivateTransfer,
            [num as u8; 32],
            0,
            0,
            &[],
            &[],
            [0u8; 32],
            0,
            &validator_set,
        );
        let target = VoteTarget {
            position,
            ordering_path: OrderingPath::FastPathPrivateTransfer,
            block_digest: hash,
        };
        let target_bytes = target.signing_bytes();
        let votes = validator_set
            .validators
            .iter()
            .zip(signing_keys.iter())
            .map(|(validator, signing_key)| ValidatorVote {
                voter: validator.id,
                target: target.clone(),
                signature: ml_dsa_65_sign(signing_key, &target_bytes).unwrap(),
            })
            .collect::<Vec<_>>();
        let qc = QuorumCertificate::from_votes(&validator_set, target, votes).unwrap();
        Anchor::new(
            num,
            parent_hash,
            OrderingPath::FastPathPrivateTransfer,
            [num as u8; 32],
            0,
            0,
            Vec::new(),
            Vec::new(),
            [0u8; 32],
            0,
            validator_set,
            qc,
        )
        .unwrap()
    }

    #[test]
    fn validator_committees_change_only_at_epoch_boundaries() {
        let (validator_a, signer_a) = validator(5);
        let (validator_b, signer_b) = validator(7);
        let epoch0_set = ValidatorSet::new(0, vec![validator_a.clone()]).unwrap();
        let epoch0_changed = ValidatorSet::new(0, vec![validator_b.clone()]).unwrap();
        let epoch1_set = ValidatorSet::new(1, vec![validator_b]).unwrap();

        let genesis = anchor_with_validator_set(0, None, epoch0_set.clone(), &[&signer_a]);
        let invalid_same_epoch =
            anchor_with_validator_set(1, Some(genesis.hash), epoch0_changed, &[&signer_b]);
        let epoch_boundary_parent =
            anchor_with_validator_set(255, Some([9u8; 32]), epoch0_set, &[&signer_a]);
        let valid_epoch_boundary = anchor_with_validator_set(
            256,
            Some(epoch_boundary_parent.hash),
            epoch1_set,
            &[&signer_b],
        );

        let err = invalid_same_epoch
            .validate_against_parent(Some(&genesis))
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("only admitted at epoch boundaries"));
        valid_epoch_boundary
            .validate_against_parent(Some(&epoch_boundary_parent))
            .unwrap();
    }
}
