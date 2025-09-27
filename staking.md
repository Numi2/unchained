
- **Stake model**: Per-wallet `StakeState` tracks staked units and per-coin stakes (`StealthCoin`). Wallet creates on-chain spends to self to “stake” coins (1 coin = 1 unit). Rewards are periodically minted as additional stake “coins” recorded in stake storage.
- **Consensus accounting**: Each epoch `Anchor` records staking metrics derived from `stake_spend` entries for that epoch: `total_staked`, `stake_count`, and a Merkle `stake_root`.
- **Persistence**: RocksDB column families store stake state, coins, spends, and (future) proofs.

### Storage layout (RocksDB CFs)
```87:116:/Users/home/unchgit/unchained/src/storage.rs
        let cf_names = [
            "default",
            "epoch",
            "coin",
            "coin_candidate",
            "epoch_selected", // per-epoch selected coin IDs
            "epoch_leaves",   // per-epoch sorted leaf hashes for proofs
            "epoch_levels",   // per-epoch merkle levels for fast proofs
            "coin_epoch",     // coin_id -> epoch number mapping (child epoch that committed the coin)
            "head",
            "wallet",
            "anchor",
            "spend",
            "nullifier",
            "commitment_used",
            "meta_authz_used",  // EIP-3009-style meta-transfer replay protection (from||nonce)
            "otp_sk",
            "otp_index",
            "peers",
            "wallet_scan_pending", // FIXED: pending wallet scans waiting for coin synchronization
            "meta",                 // miscellaneous metadata (e.g., cursors)
            // Staking-related CFs
            "stake_state",          // wallet_address -> StakeState
            "stake_coin",           // coin_id -> StealthCoin (name kept for compatibility)
            "stake_nullifier",      // nullifier -> StakeNullifier (with TTL)
            "stake_spend",          // coin_id -> StakeSpend
            "stake_proof",          // epoch_num -> StakeEpochProof
            "sync_proof",           // wallet_address -> SyncProof
            "wallet_proof_doc",     // anchor_hash -> WalletProofDoc
            "anchor_root_set",      // anchor_hash -> AnchorRootSet entry
```

### Core staking types
- **StakeState** (per wallet): staked amount, rewards, locks, and set of staked coin IDs.
```344:361:/Users/home/unchgit/unchained/src/staking.rs
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
```

- **StakeState transitions**:
```377:429:/Users/home/unchgit/unchained/src/staking.rs
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
```

- **Per-coin stake record**:
```431:459:/Users/home/unchgit/unchained/src/staking.rs
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
```

- **StakeSpend**: wraps a normal spend with stake operation metadata and extra checks.
```475:529:/Users/home/unchgit/unchained/src/staking.rs
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
```

### Wallet staking flows
- **Stake**: Select coins (1 unit per coin), create hashlock spend to self anchored at genesis, persist `StealthCoin` and `StakeSpend`, update `StakeState`, gossip the spend.
```1112:1179:/Users/home/unchgit/unchained/src/wallet.rs
pub async fn stake(&self, amount: u64, lock_epochs: Option<u64>, network: &crate::network::NetHandle) -> Result<()> {
    let store = self._db.upgrade().ok_or_else(|| anyhow!("Database connection dropped"))?;
    let mut stake_state = self.get_stake_state()?;
    let current_epoch = store.get::<crate::epoch::Anchor>("epoch", b"latest")?
        .map(|a| a.num).unwrap_or(0);

    // Select coins to stake (value=1 per coin). select_inputs returns minimal set ≥ amount.
    let mut coins_to_stake = self.select_inputs(amount)?;
    let total_selected: u64 = coins_to_stake.iter().map(|c| c.value).sum();
    if total_selected < amount { return Err(anyhow!("Insufficient funds for staking: need {} have {}", amount, total_selected)); }

    // Prepare self receiver handle (stealth address)
    let self_paycode = self.export_stealth_address();
    let chain_id = store.get_chain_id()?;

    // Optional global unlock epoch on the wallet stake state
    if let Some(le) = lock_epochs { stake_state.unlock_epoch = Some(current_epoch.saturating_add(le)); }
    if stake_state.stake_start_epoch.is_none() { stake_state.stake_start_epoch = Some(current_epoch); }

    // Use genesis-only anchor/proof per V3 validate path
    let anchor_used: crate::epoch::Anchor = store
        .get("epoch", &0u64.to_le_bytes())?
        .ok_or_else(|| anyhow!("Genesis anchor not found"))?;
    let empty_proof: Vec<([u8; 32], bool)> = Vec::new();

    // Build, validate, apply and gossip per-coin staking spends; persist stake metadata
    for coin in coins_to_stake.drain(..) {
        // Receiver commitment to self (no note binding)
        let rc = self.build_receiver_commitment_for_coin(&self_paycode, &coin, &[], &chain_id)?;
        // Compute current unlock preimage for the input coin
        let unlock_preimage = self.compute_current_unlock_preimage(&coin, &chain_id, &[])?;
        // Create V3 hashlock spend to self
        let mut spend = crate::transfer::Spend::create_hashlock(
            coin.id,
            &anchor_used,
            empty_proof.clone(),
            unlock_preimage,
            &rc,
            coin.value,
            &chain_id,
        )?;
        // Validate, apply, gossip
        spend.validate(&store)?;
        spend.apply(&store)?;
        network.gossip_spend(&spend).await;

        // Persist stake coin and stake spend accounting
        let stake_coin = StealthCoin::new(
            coin.id,
            coin.value,
            current_epoch,
            lock_epochs.map(|le| current_epoch.saturating_add(le)),
        );
        store.put_stake_coin(&stake_coin)?;

        let stake_spend = StakeSpend::new(spend.clone(), StakeOperationType::Stake, coin.value, Some(stake_coin.clone()));
        store.put_stake_spend(&stake_spend)?;

        // Update in-memory state
        stake_state.stake_coins(vec![coin.id], coin.value, current_epoch)?;
    }

    // Persist updated stake state
    self.update_stake_state(&stake_state)?;

    Ok(())
}
```

- **Unstake**: Enforce global/per-coin unlock epochs, create spend-to-self, mark `StealthCoin` inactive, update `StakeState`, persist `StakeSpend::Unstake`, gossip.
```1182:1239:/Users/home/unchgit/unchained/src/wallet.rs
pub async fn unstake(&self, coin_ids: Vec<[u8; 32]>, network: &crate::network::NetHandle) -> Result<()> {
    let store = self._db.upgrade().ok_or_else(|| anyhow!("Database connection dropped"))?;
    let mut stake_state = self.get_stake_state()?;
    let current_epoch = store.get::<crate::epoch::Anchor>("epoch", b"latest")?
        .map(|a| a.num).unwrap_or(0);

    // Enforce global unlock if set
    if let Some(unlock_epoch) = stake_state.unlock_epoch { if current_epoch < unlock_epoch { anyhow::bail!("Staking period not yet expired (global)"); } }

    // Prepare self receiver handle
    let self_paycode = self.export_stealth_address();
    let chain_id = store.get_chain_id()?;
    let anchor_used: crate::epoch::Anchor = store
        .get("epoch", &0u64.to_le_bytes())?
        .ok_or_else(|| anyhow!("Genesis anchor not found"))?;
    let empty_proof: Vec<([u8; 32], bool)> = Vec::new();

    for coin_id in coin_ids.into_iter() {
        // Must be currently staked
        if !stake_state.staked_coins.contains(&coin_id) {
            anyhow::bail!("Coin is not currently staked: {}", hex::encode(coin_id));
        }
        // Per-coin unlock gating if present
        if let Some(mut sc) = store.get_stake_coin(&coin_id)? {
            if let Some(u) = sc.unlock_epoch { if current_epoch < u { anyhow::bail!("Staking period not yet expired for coin {}", hex::encode(coin_id)); } }
            // Build spend to self to roll the lock forward (normal next-hop)
            let coin = store.get_coin(&coin_id)?.ok_or_else(|| anyhow!("Coin not found for unstake"))?;
            let rc = self.build_receiver_commitment_for_coin(&self_paycode, &coin, &[], &chain_id)?;
            let unlock_preimage = self.compute_current_unlock_preimage(&coin, &chain_id, &[])?;
            let mut spend = crate::transfer::Spend::create_hashlock(
                coin.id,
                &anchor_used,
                empty_proof.clone(),
                unlock_preimage,
                &rc,
                coin.value,
                &chain_id,
            )?;
            spend.validate(&store)?;
            spend.apply(&store)?;
            network.gossip_spend(&spend).await;

            // Update stake coin/state and persist stake spend record
            sc.is_active = false;
            store.put_stake_coin(&sc)?;
            stake_state.unstake_coins(vec![coin_id], current_epoch)?;

            let stake_spend = StakeSpend::new(spend, StakeOperationType::Unstake, coin.value, Some(sc));
            store.put_stake_spend(&stake_spend)?;
        } else {
            anyhow::bail!("Stake coin record missing for {}", hex::encode(coin_id));
        }
    }

    self.update_stake_state(&stake_state)?;
    Ok(())
}
```

### Epoch consensus accounting and rewards
- **Anchor staking fields** (per-epoch):
```16:30:/Users/home/unchgit/unchained/src/epoch.rs
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Anchor {
    pub num:          u64,
    pub hash:         [u8; 32],
    pub merkle_root:  [u8; 32],
    pub difficulty:   usize,
    pub coin_count:   u32,
    pub cumulative_work: u128,
    pub mem_kib:      u32,
    /// Total amount staked in this epoch
    pub total_staked: u64,
    /// Number of stake operations in this epoch
    pub stake_count: u32,
    /// Merkle root of stake operations in this epoch
    pub stake_root: [u8; 32],
}
```

- **Compute per-epoch stake metrics**: sum stake amounts from `stake_spend` entries whose input coin first appears in this epoch; include `Stake` (and supports `StakeReward` if present) to build `stake_root`.
```633:682:/Users/home/unchgit/unchained/src/epoch.rs
fn calculate_epoch_staking_info(&self, _selected_ids: &HashSet<[u8; 32]>, epoch_num: u64) -> anyhow::Result<(u64, u32, [u8; 32])> {
    let mut total_staked = 0u64;
    let mut stake_operations = Vec::new();

    // Check for stake spends in this epoch
    if let Some(spend_cf) = self.db.db.cf_handle("stake_spend") {
        let iter = self.db.db.iterator_cf(spend_cf, rocksdb::IteratorMode::Start);
        for item in iter {
            let (_key, value) = item?;
            if let Ok(stake_spend) = bincode::deserialize::<StakeSpend>(&value) {
                // Only count stakes from this epoch
                if let Some(coin) = self.db.get::<Coin>("coin", &stake_spend.base_spend.coin_id)? {
                    if let Some(coin_epoch) = self.db.get_epoch_for_coin(&coin.id)? {
                        if coin_epoch == epoch_num {
                            match stake_spend.operation {
                                StakeOperationType::Stake => {
                                    total_staked = total_staked.saturating_add(stake_spend.stake_amount);
                                }
                                StakeOperationType::StakeReward => {
                                    total_staked = total_staked.saturating_add(stake_spend.stake_amount);
                                }
                                _ => {}
                            }
                            stake_operations.push(stake_spend);
                        }
                    }
                }
            }
        }
    }

    // Create Merkle root of stake operations
    let stake_root = if stake_operations.is_empty() {
        [0u8; 32]
    } else {
        let mut stake_hashes: Vec<[u8; 32]> = stake_operations.iter().map(|s| {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&s.base_spend.coin_id);
            hasher.update(&s.base_spend.nullifier);
            *hasher.finalize().as_bytes()
        }).collect();

        stake_hashes.sort();
        MerkleTree::compute_root_from_sorted_leaves(&stake_hashes)
    };

    Ok((total_staked, stake_operations.len() as u32, stake_root))
}
```

- **Reward distribution**: periodic, driven by epoch progression; for every 100 staked per hour, mint 1 reward unit as a new `StealthCoin`, compound by adding to `staked_amount`, checkpoint via `last_reward_epoch`.
```684:757:/Users/home/unchgit/unchained/src/epoch.rs
fn distribute_staking_rewards(&self, anchor: &Anchor, _selected_ids: &HashSet<[u8; 32]>) -> anyhow::Result<()> {
    // Only distribute rewards if there are staked coins
    if anchor.total_staked == 0 {
        return Ok(());
    }

    // Epochs per hour (ceil), based on configured epoch seconds
    let secs_per_epoch = self.cfg.seconds.max(1);
    let epochs_per_hour = (3600 + secs_per_epoch - 1) / secs_per_epoch;
    if epochs_per_hour == 0 { return Ok(()); }

    // Get all stake states
    if let Some(stake_state_cf) = self.db.db.cf_handle("stake_state") {
        let iter = self.db.db.iterator_cf(stake_state_cf, rocksdb::IteratorMode::Start);

        for item in iter {
            let (key, value) = item?;
            if let Ok(mut stake_state) = bincode::deserialize::<StakeState>(&value) {
                // Determine elapsed epochs since last reward checkpoint
                let last_epoch = stake_state.last_reward_epoch.unwrap_or_else(|| stake_state.stake_start_epoch.unwrap_or(anchor.num));
                if anchor.num <= last_epoch { continue; }
                let epochs_elapsed = anchor.num.saturating_sub(last_epoch);
                if epochs_elapsed < epochs_per_hour as u64 { continue; }

                let reward_hours = (epochs_elapsed / epochs_per_hour as u64) as u64;
                if reward_hours == 0 { continue; }

                // Compute reward units: 1 StealthCoin per 100 staked per hour
                let units_per_hour = stake_state.staked_amount / 100;
                if units_per_hour == 0 { 
                    // Still advance checkpoint to avoid repeated scans
                    stake_state.last_reward_epoch = Some(last_epoch + reward_hours * epochs_per_hour as u64);
                    let mut wallet_addr = [0u8; 32]; wallet_addr.copy_from_slice(&key[0..32]);
                    self.db.put_stake_state(&wallet_addr, &stake_state)?;
                    continue; 
                }
                let reward_units = units_per_hour.saturating_mul(reward_hours);
                if reward_units == 0 { 
                    stake_state.last_reward_epoch = Some(last_epoch + reward_hours * epochs_per_hour as u64);
                    let mut wallet_addr = [0u8; 32]; wallet_addr.copy_from_slice(&key[0..32]);
                    self.db.put_stake_state(&wallet_addr, &stake_state)?;
                    continue; 
                }

                // Create reward StealthCoins deterministically and update state
                let mut wallet_addr = [0u8; 32];
                wallet_addr.copy_from_slice(&key[0..32]);
                for i in 0..reward_units {
                    let mut h = blake3::Hasher::new();
                    h.update(b"unchained.stake.reward.v1");
                    h.update(&wallet_addr);
                    h.update(&anchor.hash);
                    h.update(&anchor.num.to_le_bytes());
                    h.update(&stake_state.total_rewards.to_le_bytes());
                    h.update(&i.to_le_bytes());
                    let coin_id = *h.finalize().as_bytes();
                    let reward_coin = StealthCoin::new(coin_id, 1, anchor.num, None);
                    // Persist reward coin and reflect in state
                    let _ = self.db.put_stake_coin(&reward_coin);
                    stake_state.staked_coins.insert(coin_id);
                }
                // Increase rewards and staked amount (compounding)
                stake_state.add_rewards(reward_units);
                // Advance reward checkpoint by consumed hours worth of epochs
                stake_state.last_reward_epoch = Some(last_epoch + reward_hours * epochs_per_hour as u64);
                self.db.put_stake_state(&wallet_addr, &stake_state)?;
            }
        }
    }

    Ok(())
}
```

### Notable behaviors and constraints
- **Unit semantics**: Each coin counts as 1 stake unit; `stake_amount` must equal number of coins staked; the code enforces this.
- **Locks**: Optional global wallet-level `unlock_epoch` plus per-coin `unlock_epoch`; both are enforced on unstake.
- **Rewards**:
  - Calculated in discrete “hours” derived from epoch length; rewards compound by increasing `staked_amount`.
  - Reward coins are recorded in `stake_coin` CF and added to the wallet’s `staked_coins`.
  - Gate: rewards are skipped if `anchor.total_staked == 0` for the epoch; this means no periodic rewards are issued in epochs without any stake operations.
- **Consensus accounting**: `total_staked/stake_count/stake_root` are derived from `stake_spend` entries whose input coin was first committed in the current epoch.
- **Placeholders/future hooks**: `StakeReward` type, `StakeNullifier`, `StakeEpochProof`, and `SyncProof` structures are present; verification/proving paths are only partially implemented and not wired into staking flows.

- **Security posture**:
  - Stake/unstake spends are validated using the base spend’s validation (`transfer::Spend::validate`) and then annotated as staking actions.
  - Current staking spends are created against the genesis anchor (simplified path noted in the comments), using hashlock spends to self.

- **Persistence API**: Store has typed getters/putters for all staking entities (`put/get_stake_state`, `put/get_stake_coin`, `put/get_stake_spend`, `put/get_stake_epoch_proof`, etc.).

