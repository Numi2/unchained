use crate::{
    coin::{Coin, CoinCandidate},
    crypto::{self, Address, TaggedSigningPublicKey},
    epoch::Anchor,
    node_control::{
        MiningWork, NodeControlClient, NodeControlStateEnvelope, RECENT_FINALIZED_SELECTION_WINDOW,
    },
    wallet_control::{MiningIdentity, WalletControlClient, WalletControlStateEnvelope},
};
use anyhow::{anyhow, bail, Result as AnyResult};
use rand::Rng;
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::{
    sync::{broadcast::Receiver, watch},
    task,
    time::{self, Duration},
};

static ALLOW_ROUTINE_MINER: AtomicBool = AtomicBool::new(false);
macro_rules! miner_routine { ($($arg:tt)*) => { if ALLOW_ROUTINE_MINER.load(Ordering::Relaxed) { println!($($arg)*); } } }
#[allow(unused_imports)]
use miner_routine;

pub fn spawn(
    cfg: crate::config::Mining,
    node_control: NodeControlClient,
    wallet_control: WalletControlClient,
    shutdown_rx: Receiver<()>,
) -> task::JoinHandle<()> {
    task::spawn(async move {
        let mut miner = Miner::new(
            cfg,
            node_control,
            MinerWalletAuthority::new(wallet_control),
            shutdown_rx,
        );
        miner.run().await;
    })
}

#[derive(Clone)]
struct MinerWalletAuthority {
    control: WalletControlClient,
    identity: Option<MiningIdentity>,
}

impl MinerWalletAuthority {
    fn new(control: WalletControlClient) -> Self {
        Self {
            control,
            identity: None,
        }
    }

    fn bind_or_verify_identity(&mut self, identity: MiningIdentity) -> AnyResult<()> {
        match self.identity.as_ref() {
            Some(current) if current != &identity => {
                bail!("wallet mining identity changed while miner was running; restart the miner intentionally")
            }
            Some(_) => Ok(()),
            None => {
                self.identity = Some(identity);
                Ok(())
            }
        }
    }

    fn address(&self) -> AnyResult<Address> {
        self.identity
            .as_ref()
            .map(|identity| identity.address)
            .ok_or_else(|| anyhow!("wallet mining identity not yet bound"))
    }

    fn public_key(&self) -> AnyResult<&TaggedSigningPublicKey> {
        self.identity
            .as_ref()
            .map(|identity| &identity.signing_pk)
            .ok_or_else(|| anyhow!("wallet mining identity not yet bound"))
    }

    async fn derive_genesis_lock_secret(
        &self,
        coin_id: [u8; 32],
        chain_id: [u8; 32],
    ) -> AnyResult<[u8; 32]> {
        self.control
            .derive_genesis_lock_secret(coin_id, chain_id)
            .await
    }
}

struct Miner {
    cfg: crate::config::Mining,
    node: NodeControlClient,
    wallet: MinerWalletAuthority,
    shutdown_rx: Receiver<()>,
    current_epoch: Option<u64>,
    consecutive_failures: u32,
    max_consecutive_failures: u32,
    recent_candidates: VecDeque<(u64, [u8; 32])>,
    reported_candidates: HashSet<[u8; 32]>,
}

enum MineEpochOutcome {
    AwaitStateChange,
    Reevaluate(NodeControlStateEnvelope),
}

impl Miner {
    fn new(
        cfg: crate::config::Mining,
        node: NodeControlClient,
        wallet: MinerWalletAuthority,
        shutdown_rx: Receiver<()>,
    ) -> Self {
        Self {
            cfg,
            node,
            wallet,
            shutdown_rx,
            current_epoch: None,
            consecutive_failures: 0,
            max_consecutive_failures: crate::config::default_max_consecutive_failures(),
            recent_candidates: VecDeque::new(),
            reported_candidates: HashSet::new(),
        }
    }

    async fn run(&mut self) {
        let mut wallet_state_rx = match self.wallet.control.subscribe_state() {
            Ok(rx) => rx,
            Err(err) => {
                eprintln!("Failed to subscribe to wallet state: {err}");
                return;
            }
        };
        let mut wallet_sequence = match self
            .wait_for_wallet_authority(&mut wallet_state_rx, None)
            .await
        {
            Ok(state) => Some(state.sequence),
            Err(err) if err.to_string() == "Shutdown" => {
                println!("🛑 Miner shut down gracefully");
                return;
            }
            Err(err) => {
                eprintln!("Failed to bind wallet mining identity: {err}");
                return;
            }
        };
        let mut state_rx = match self.node.subscribe_state() {
            Ok(rx) => rx,
            Err(err) => {
                eprintln!("Failed to subscribe to node state: {err}");
                return;
            }
        };
        let mut state = match self
            .wait_for_mineable_work(&mut state_rx, &mut wallet_state_rx, &mut wallet_sequence)
            .await
        {
            Ok(state) => state,
            Err(err) if err.to_string() == "Shutdown" => {
                println!("🛑 Miner shut down gracefully");
                return;
            }
            Err(err) => {
                eprintln!("Failed to fetch mining work: {err}");
                return;
            }
        };
        loop {
            let work = state.state.mining_work.clone();

            if let Err(err) = self.report_selection_results(&work) {
                eprintln!("⚠️  Could not report selection results: {err}");
            }

            let Some(anchor) = work.latest_anchor.clone() else {
                match self
                    .wait_for_next_state(
                        &mut state_rx,
                        &mut wallet_state_rx,
                        &mut wallet_sequence,
                        Some(state.sequence),
                    )
                    .await
                {
                    Ok(next_state) => {
                        state = next_state;
                    }
                    Err(err) if err.to_string() == "Shutdown" => {
                        println!("🛑 Miner shut down gracefully");
                        return;
                    }
                    Err(err) => {
                        eprintln!("Failed to fetch mining work: {err}");
                        if self.wait_or_shutdown(Duration::from_secs(1)).await.is_err() {
                            println!("🛑 Miner shut down gracefully");
                            return;
                        }
                    }
                }
                continue;
            };

            if !work.mining_ready {
                miner_routine!(
                    "⌛ Waiting for mineable node state… local {} / net {} (peer-confirmed: {})",
                    work.local_tip,
                    work.highest_seen_epoch,
                    work.peer_confirmed_tip
                );
                match self
                    .wait_for_mineable_work(
                        &mut state_rx,
                        &mut wallet_state_rx,
                        &mut wallet_sequence,
                    )
                    .await
                {
                    Ok(next_state) => {
                        state = next_state;
                        self.consecutive_failures = 0;
                    }
                    Err(err) if err.to_string() == "Shutdown" => {
                        println!("🛑 Miner shut down gracefully");
                        return;
                    }
                    Err(err) => {
                        eprintln!("Failed to fetch mining work: {err}");
                        if self.wait_or_shutdown(Duration::from_secs(1)).await.is_err() {
                            println!("🛑 Miner shut down gracefully");
                            return;
                        }
                    }
                }
                continue;
            }

            if self.current_epoch == Some(anchor.num) {
                match self
                    .wait_for_next_state(
                        &mut state_rx,
                        &mut wallet_state_rx,
                        &mut wallet_sequence,
                        Some(state.sequence),
                    )
                    .await
                {
                    Ok(next_state) => {
                        state = next_state;
                    }
                    Err(err) if err.to_string() == "Shutdown" => {
                        println!("🛑 Miner shut down gracefully");
                        return;
                    }
                    Err(err) => {
                        eprintln!("Failed to fetch mining work: {err}");
                        if self
                            .wait_or_shutdown(Duration::from_millis(250))
                            .await
                            .is_err()
                        {
                            println!("🛑 Miner shut down gracefully");
                            return;
                        }
                    }
                }
                continue;
            }

            self.current_epoch = Some(anchor.num);
            match self
                .mine_epoch(
                    &work,
                    anchor,
                    &mut state_rx,
                    &mut wallet_state_rx,
                    &mut wallet_sequence,
                    state.sequence,
                )
                .await
            {
                Ok(MineEpochOutcome::AwaitStateChange) => {
                    self.consecutive_failures = 0;
                    match self
                        .wait_for_next_state(
                            &mut state_rx,
                            &mut wallet_state_rx,
                            &mut wallet_sequence,
                            Some(state.sequence),
                        )
                        .await
                    {
                        Ok(next_state) => state = next_state,
                        Err(err) if err.to_string() == "Shutdown" => {
                            println!("🛑 Miner shut down gracefully");
                            return;
                        }
                        Err(err) => {
                            eprintln!("Failed to fetch mining work: {err}");
                            if self
                                .wait_or_shutdown(Duration::from_millis(250))
                                .await
                                .is_err()
                            {
                                println!("🛑 Miner shut down gracefully");
                                return;
                            }
                        }
                    }
                }
                Ok(MineEpochOutcome::Reevaluate(next_state)) => {
                    self.consecutive_failures = 0;
                    state = next_state;
                }
                Err(err) if err.to_string() == "Shutdown" => {
                    println!("🛑 Miner shut down gracefully");
                    return;
                }
                Err(err) => {
                    self.consecutive_failures += 1;
                    eprintln!(
                        "(attempt {}/{}) : {}",
                        self.consecutive_failures, self.max_consecutive_failures, err
                    );
                    let backoff = Duration::from_secs(2u64.pow(self.consecutive_failures.min(6)));
                    if self.wait_or_shutdown(backoff).await.is_err() {
                        println!("🛑 Miner shut down gracefully");
                        return;
                    }
                }
            }
        }
    }

    async fn wait_for_mineable_work(
        &mut self,
        state_rx: &mut watch::Receiver<Option<NodeControlStateEnvelope>>,
        wallet_state_rx: &mut watch::Receiver<Option<WalletControlStateEnvelope>>,
        wallet_sequence: &mut Option<u64>,
    ) -> Result<NodeControlStateEnvelope, Box<dyn std::error::Error + Send + Sync>> {
        let mut last_sequence = None;
        loop {
            let state = self
                .wait_for_next_state(state_rx, wallet_state_rx, wallet_sequence, last_sequence)
                .await?;
            last_sequence = Some(state.sequence);
            let work = state.state.mining_work.clone();
            if let Err(err) = self.report_selection_results(&work) {
                eprintln!("⚠️  Could not report selection results: {err}");
            }
            if work.mining_ready {
                miner_routine!("🚀 Node is fully synced – starting mining");
                return Ok(state);
            }
            miner_routine!(
                "⌛ Waiting for mineable node state… local {} / net {} (peer-confirmed: {})",
                work.local_tip,
                work.highest_seen_epoch,
                work.peer_confirmed_tip
            );
        }
    }

    async fn wait_for_next_state(
        &mut self,
        state_rx: &mut watch::Receiver<Option<NodeControlStateEnvelope>>,
        wallet_state_rx: &mut watch::Receiver<Option<WalletControlStateEnvelope>>,
        wallet_sequence: &mut Option<u64>,
        current_sequence: Option<u64>,
    ) -> Result<NodeControlStateEnvelope, Box<dyn std::error::Error + Send + Sync>> {
        loop {
            if let Some(state) = state_rx.borrow().clone() {
                if current_sequence.map_or(true, |sequence| state.sequence != sequence) {
                    return Ok(state);
                }
            }
            tokio::select! {
                _ = self.shutdown_rx.recv() => {
                    return Err("Shutdown".into());
                }
                changed = state_rx.changed() => {
                    if changed.is_err() {
                        return Err("node control state stream closed".into());
                    }
                }
                changed = wallet_state_rx.changed() => {
                    if changed.is_err() {
                        return Err("wallet control state stream closed".into());
                    }
                    self.drain_wallet_state_updates(wallet_state_rx, wallet_sequence)?;
                }
            }
        }
    }

    async fn wait_or_shutdown(
        &mut self,
        duration: Duration,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tokio::select! {
            _ = self.shutdown_rx.recv() => Err("Shutdown".into()),
            _ = time::sleep(duration) => Ok(()),
        }
    }

    fn report_selection_results(
        &mut self,
        work: &MiningWork,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        for selection in &work.recent_finalized_selections {
            let our_candidates: Vec<[u8; 32]> = self
                .recent_candidates
                .iter()
                .filter_map(|(epoch, id)| {
                    if *epoch == selection.candidate_epoch && !self.reported_candidates.contains(id)
                    {
                        Some(*id)
                    } else {
                        None
                    }
                })
                .collect();
            if our_candidates.is_empty() {
                continue;
            }
            let selected_set: HashSet<[u8; 32]> = selection.coin_ids.iter().copied().collect();
            for id in our_candidates {
                if selected_set.contains(&id) {
                    println!(
                        "🎉 Epoch #{} finalized: your coin {} was SELECTED",
                        selection.candidate_epoch,
                        hex::encode(id)
                    );
                }
                self.reported_candidates.insert(id);
            }
        }

        if let Some(anchor) = &work.latest_anchor {
            let retain_from_epoch = anchor.num.saturating_sub(RECENT_FINALIZED_SELECTION_WINDOW);
            while let Some((epoch, id)) = self.recent_candidates.front().copied() {
                if epoch < retain_from_epoch {
                    self.recent_candidates.pop_front();
                    self.reported_candidates.remove(&id);
                } else {
                    break;
                }
            }
            self.reported_candidates.retain(|id| {
                self.recent_candidates
                    .iter()
                    .any(|(_, candidate_id)| candidate_id == id)
            });
        }
        Ok(())
    }

    async fn mine_epoch(
        &mut self,
        work: &MiningWork,
        anchor: Anchor,
        state_rx: &mut watch::Receiver<Option<NodeControlStateEnvelope>>,
        wallet_state_rx: &mut watch::Receiver<Option<WalletControlStateEnvelope>>,
        wallet_sequence: &mut Option<u64>,
        mut current_sequence: u64,
    ) -> Result<MineEpochOutcome, Box<dyn std::error::Error + Send + Sync>> {
        let creator_address = self.wallet.address()?;
        let mem_kib = anchor.mem_kib;
        let difficulty = anchor.difficulty;
        let mut attempts = 0u64;
        let max_attempts = self.cfg.max_attempts;

        println!(
            "⛏️  Mining epoch #{} (difficulty={} zero-bytes, mem={} KiB)",
            anchor.num, difficulty, mem_kib
        );

        const PROGRESS_LOG_INTERVAL_ATTEMPTS: u64 = 10_000;
        let mut last_progress_instant = std::time::Instant::now();
        let mut last_progress_attempts = 0u64;
        let check_every = self.cfg.check_interval_attempts.max(1);
        let mut next_nonce: u64 = rand::thread_rng().gen();
        let epoch_hash = anchor.hash;
        let creator_addr = creator_address;

        loop {
            if attempts >= max_attempts {
                eprintln!(
                    "⚠️  Reached max attempts ({}) for epoch #{}, waiting for the next epoch",
                    max_attempts, anchor.num
                );
                return Ok(MineEpochOutcome::AwaitStateChange);
            }

            let batch_size = std::cmp::min(check_every, max_attempts - attempts);
            let (found_opt, batch_attempts) = if self.cfg.offload_blocking {
                task::spawn_blocking({
                    let epoch_hash = epoch_hash;
                    let creator_addr = creator_addr;
                    let start_nonce = next_nonce;
                    move || -> Result<(Option<(u64, [u8; 32])>, u64), anyhow::Error> {
                        let mut header = [0u8; 32 + 8 + 32];
                        header[..32].copy_from_slice(&epoch_hash);
                        header[40..].copy_from_slice(&creator_addr);

                        let mut nonce = start_nonce;
                        let mut local_attempts = 0u64;
                        while local_attempts < batch_size {
                            header[32..40].copy_from_slice(&nonce.to_le_bytes());
                            let pow_hash = crate::crypto::argon2id_pow(&header, mem_kib)?;
                            local_attempts += 1;
                            if pow_hash.iter().take(difficulty).all(|byte| *byte == 0) {
                                return Ok((Some((nonce, pow_hash)), local_attempts));
                            }
                            nonce = nonce.wrapping_add(1);
                        }
                        Ok((None, local_attempts))
                    }
                })
                .await
                .map_err(|err| anyhow::anyhow!("join error: {}", err))??
            } else {
                let mut found_opt = None;
                let mut header = [0u8; 32 + 8 + 32];
                header[..32].copy_from_slice(&epoch_hash);
                header[40..].copy_from_slice(&creator_addr);
                let mut nonce = next_nonce;
                let mut local_attempts = 0u64;
                while local_attempts < batch_size {
                    header[32..40].copy_from_slice(&nonce.to_le_bytes());
                    let pow_hash = crypto::argon2id_pow(&header, mem_kib)?;
                    local_attempts += 1;
                    if pow_hash.iter().take(difficulty).all(|byte| *byte == 0) {
                        found_opt = Some((nonce, pow_hash));
                        break;
                    }
                    nonce = nonce.wrapping_add(1);
                }
                (found_opt, local_attempts)
            };

            attempts += batch_attempts;
            next_nonce = next_nonce.wrapping_add(batch_attempts);
            crate::metrics::MINING_ATTEMPTS.inc_by(batch_attempts);

            if let Some((nonce, pow_hash)) = found_opt {
                let creator_pk = self.wallet.public_key()?.clone();
                let candidate_id = Coin::calculate_id(&anchor.hash, nonce, &creator_addr);
                let s0 = self
                    .wallet
                    .derive_genesis_lock_secret(candidate_id, work.chain_id)
                    .await?;
                let lock_hash =
                    crate::crypto::lock_hash_from_preimage(&work.chain_id, &candidate_id, &s0);
                let candidate = CoinCandidate::new(
                    anchor.hash,
                    nonce,
                    creator_addr,
                    creator_pk,
                    lock_hash,
                    pow_hash,
                );
                let accepted_id = self.node.submit_coin_candidate(&candidate)?;
                if accepted_id != candidate.id {
                    return Err("node control returned mismatched coin id".into());
                }
                println!(
                    "✅ Found a new coin! ID: {} (attempts: {})",
                    hex::encode(candidate.id),
                    attempts
                );
                crate::metrics::MINING_FOUND.inc();
                self.recent_candidates.push_back((anchor.num, candidate.id));
                if self.recent_candidates.len() > 64 {
                    self.recent_candidates.pop_front();
                }
                return Ok(MineEpochOutcome::AwaitStateChange);
            }

            if attempts % PROGRESS_LOG_INTERVAL_ATTEMPTS == 0 {
                let elapsed = last_progress_instant.elapsed();
                if elapsed >= std::time::Duration::from_secs(2) {
                    let delta_attempts = attempts.saturating_sub(last_progress_attempts);
                    let rate = if elapsed.as_secs_f64() > 0.0 {
                        delta_attempts as f64 / elapsed.as_secs_f64()
                    } else {
                        0.0
                    };
                    println!(
                        "⏳ Mining epoch #{}: {} attempts (≈{:.1}/s)",
                        anchor.num, attempts, rate
                    );
                    last_progress_instant = std::time::Instant::now();
                    last_progress_attempts = attempts;
                }
            }

            if let Some(next_state) = self.drain_state_updates(state_rx, &mut current_sequence)? {
                let latest_work = next_state.state.mining_work.clone();
                if !latest_work.mining_ready {
                    return Ok(MineEpochOutcome::Reevaluate(next_state));
                }
                if let Some(latest_anchor) = latest_work.latest_anchor.clone() {
                    if latest_anchor.num > anchor.num
                        || (latest_anchor.num == anchor.num && latest_anchor.hash != anchor.hash)
                    {
                        println!(
                            "🔄 Newer epoch #{} detected while mining #{} – switching",
                            latest_anchor.num, anchor.num
                        );
                        return Ok(MineEpochOutcome::Reevaluate(next_state));
                    }
                }
            }
            self.drain_wallet_state_updates(wallet_state_rx, wallet_sequence)?;

            match self.shutdown_rx.try_recv() {
                Ok(_) | Err(tokio::sync::broadcast::error::TryRecvError::Closed) => {
                    return Err("Shutdown".into());
                }
                Err(tokio::sync::broadcast::error::TryRecvError::Lagged(skipped)) => {
                    return Err(
                        format!("Shutdown channel lagged, skipped {skipped} messages").into(),
                    );
                }
                Err(tokio::sync::broadcast::error::TryRecvError::Empty) => {}
            }

            tokio::task::yield_now().await;
        }
    }

    fn drain_state_updates(
        &mut self,
        state_rx: &mut watch::Receiver<Option<NodeControlStateEnvelope>>,
        current_sequence: &mut u64,
    ) -> Result<Option<NodeControlStateEnvelope>, Box<dyn std::error::Error + Send + Sync>> {
        let mut latest_state = None;
        loop {
            match state_rx.has_changed() {
                Ok(false) => break,
                Ok(true) => match state_rx.borrow_and_update().clone() {
                    Some(state) if state.sequence != *current_sequence => {
                        *current_sequence = state.sequence;
                        latest_state = Some(state);
                    }
                    Some(_) => {}
                    None => {
                        return Err("node control state stream disconnected".into());
                    }
                },
                Err(_) => return Err("node control state stream closed".into()),
            }
        }
        Ok(latest_state)
    }

    async fn wait_for_wallet_authority(
        &mut self,
        state_rx: &mut watch::Receiver<Option<WalletControlStateEnvelope>>,
        current_sequence: Option<u64>,
    ) -> Result<WalletControlStateEnvelope, Box<dyn std::error::Error + Send + Sync>> {
        loop {
            if let Some(state) = state_rx.borrow().clone() {
                if current_sequence.map_or(true, |sequence| state.sequence != sequence) {
                    self.wallet
                        .bind_or_verify_identity(state.identity.clone())?;
                    return Ok(state);
                }
            }
            tokio::select! {
                _ = self.shutdown_rx.recv() => {
                    return Err("Shutdown".into());
                }
                changed = state_rx.changed() => {
                    if changed.is_err() {
                        return Err("wallet control state stream closed".into());
                    }
                }
            }
        }
    }

    fn drain_wallet_state_updates(
        &mut self,
        state_rx: &mut watch::Receiver<Option<WalletControlStateEnvelope>>,
        current_sequence: &mut Option<u64>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        loop {
            match state_rx.has_changed() {
                Ok(false) => break,
                Ok(true) => match state_rx.borrow_and_update().clone() {
                    Some(state)
                        if current_sequence.map_or(true, |sequence| state.sequence != sequence) =>
                    {
                        self.wallet
                            .bind_or_verify_identity(state.identity.clone())?;
                        *current_sequence = Some(state.sequence);
                    }
                    Some(_) => {}
                    None => {
                        return Err("wallet control state stream disconnected".into());
                    }
                },
                Err(_) => return Err("wallet control state stream closed".into()),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::TaggedSigningPublicKey;

    #[test]
    fn miner_wallet_authority_rejects_identity_drift() {
        let client = WalletControlClient::new("/tmp/unchained-miner-wallet-authority-test");
        let mut authority = MinerWalletAuthority::new(client);
        let first = MiningIdentity {
            address: [1u8; 32],
            signing_pk: TaggedSigningPublicKey::zero_ml_dsa_65(),
        };
        authority
            .bind_or_verify_identity(first.clone())
            .expect("bind initial identity");
        authority
            .bind_or_verify_identity(first)
            .expect("same identity remains valid");

        let drifted = MiningIdentity {
            address: [2u8; 32],
            signing_pk: TaggedSigningPublicKey::from_ml_dsa_65_array([3u8; 1952]),
        };
        assert!(authority.bind_or_verify_identity(drifted).is_err());
    }
}
