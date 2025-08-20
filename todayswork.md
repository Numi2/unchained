## Goal

Replace the broken V2 (Dilithium signature) transfer path with a robust V3 hashlock mechanism end-to-end, eliminate any requirement or warnings about signed stealth addresses, and ensure transfers work reliably between wallets. Maintain a safe, minimal compatibility path only to upgrade legacy coins that lack `lock_hash`.

## Notes on commitment scheme rationale

Hashlocks implement a binding commitment: receiver commits to the next owner’s lock state by providing `next_lock_hash = H(s_next)` while keeping `s_next` hidden; the sender constructs a spend that is valid only when the holder reveals the correct preimage for the previous hop. This preserves hiding (preimage not revealed until spend) and binding (hash preimage must match), aligning with commitment scheme properties.

Let me scan the Rust code in `src` to locate where chain reorgs/fork resolution and rollbacks are implemented, and how state and wallets are updated during a reorg. I'll search broadly and in parallel for consensus, rollback, and fork handling.


I'll open the specific section in `src/network.rs` around the reorg logic to inspect `attempt_reorg` and how it updates DB state during a reorg.
Ran tool

### Where reorgs are detected and triggered
- **Buffer alternates**: When an incoming anchor’s parent is missing or its hash conflicts, it’s buffered by height in `orphan_anchors`, and a reorg attempt is triggered.
  - On parent-missing: buffered as orphan.
  - On hash-mismatch: buffered as an alternate fork and parents backfilled (`REORG_BACKFILL = 16`).
- **Trigger points**: Reorg attempts are called after validating/handling anchors throughout `network.rs`.

```469:573:src/network.rs
// Attempt to reorg to a better chain using buffered anchors.
fn attempt_reorg(
    db: &Store,
    orphan_anchors: &mut HashMap<u64, Vec<Anchor>>,
    anchor_tx: &broadcast::Sender<Anchor>,
    sync_state: &Arc<Mutex<SyncState>>,
    command_tx: &mpsc::UnboundedSender<NetworkCommand>,
) {
    let current_latest = match db.get::<Anchor>("epoch", b"latest") {
        Ok(Some(a)) => a,
        _ => return,
    };
    let Some(&max_buf_height) = orphan_anchors.keys().max() else { return };
    if max_buf_height <= current_latest.num { return; }

    // Find earliest contiguous orphan segment, compute fork height (segment start - 1)
    // ...

    // Build candidate parents at the fork: local parent and any alternates at fork height
    // If missing, proactively request backfill and return.
    // ...

    // Try to assemble a linked alternate chain from first_height..=max_buf_height:
    // - Verify header link: alt.hash == H(alt.merkle_root || parent.hash)
    // - Verify difficulty accounting: alt.cumulative_work == parent.cumulative_work + expected_work(difficulty)
    // If mismatch, backfill parents and abort this attempt.
    // ...

    // Skip adoption if candidate tip’s cumulative work is not strictly better than current tip.
    // ...
}
```

### Fork choice and validation
- **Fork choice rule**: Cumulative work (tie-breaker: higher height). An alternate segment is only adopted if its tip has strictly higher `cumulative_work` than current `latest`.
- **Header linkage**: Each candidate anchor in the alternate segment must:
  - Recompute to `hash = blake3(merkle_root || parent.hash)`.
  - Have `cumulative_work = parent.cumulative_work + expected_work(difficulty)`.

### Adoption and rollback scope
- **What is rolled back/replaced**: For each epoch in the adopted alternate segment:
  - Overwrite `epoch[num]`, `epoch["latest"]`, and `anchor[hash]` with the alternate anchor.
  - Remove previously confirmed coins and their `coin->epoch` index for that height.
  - Remove any recorded spends for those removed coins and their `nullifier` entries.
  - Clear per-epoch `epoch_selected` entries and `epoch_leaves`.

- **Reconstruct confirmed state from candidates**:
  - Rebuild the selected set by scanning local `coin_candidate`s keyed by the new parent’s hash, enforcing parent’s PoW difficulty, deterministically picking `coin_count` best candidates, and recomputing the Merkle root.
  - If recomputed root equals the anchor’s `merkle_root` and counts match, persist coins, `coin_epoch`, `epoch_selected`, and `epoch_leaves`. Otherwise, log a warning (anchor is still adopted, but per-epoch indices/leaves may be incomplete until healed by gossip/backfill).

```585:663:src/network.rs
// Overwrite epoch/anchor mappings for this height
batch.put_cf(epoch_cf, alt.num.to_le_bytes(), &ser);
batch.put_cf(epoch_cf, b"latest", &ser);
batch.put_cf(anchor_cf, &alt.hash, &ser);

// Remove coins/spends/nullifiers from the replaced branch at this height
if let Ok(prev_selected_ids) = db.get_selected_coin_ids_for_epoch(alt.num) {
    for id in prev_selected_ids {
        batch.delete_cf(coin_cf, &id);
        batch.delete_cf(coin_epoch_cf, &id);
        if let Ok(Some(sp)) = db.get::<crate::transfer::Spend>("spend", &id) {
            batch.delete_cf(spend_cf, &id);
            batch.delete_cf(nullifier_cf, &sp.nullifier);
        }
    }
}

// Clear old epoch_selected entries and leaves for this height
// ...

// Reconstruct selected set from local candidates (by new parent hash) and PoW filter
// Deterministically pick up to alt.coin_count, recompute leaves/merkle_root
// If matches the anchor: persist coins, coin_epoch, epoch_selected, epoch_leaves
// Else: warn; continue (anchor adopted, indices may be healed later)
```

- **Finalize adoption**: Atomically write the batch, broadcast adopted anchors to subscribers, advance sync state, and prune used alternates from the orphan buffer.

```688:703:src/network.rs
if let Err(e) = db.db.write(batch) { /* abort */ }
for alt in &chosen_chain { let _ = anchor_tx.send(alt.clone()); }
if let Ok(mut st) = sync_state.lock() { st.highest_seen_epoch = seg_tip.num; }
for alt in &chosen_chain {
    if let Some(vec) = orphan_anchors.get_mut(&alt.num) {
        vec.retain(|a| a.hash != alt.hash);
        if vec.is_empty() { orphan_anchors.remove(&alt.num); }
    }
}
```

### How alternates are buffered and backfilled
- **Buffering**: `orphan_anchors: HashMap<u64, Vec<Anchor>>` keyed by height; capped by `MAX_ORPHAN_ANCHORS`.
- **Backfill strategy**: On missing fork parents or linkage mismatches, proactively request up to `REORG_BACKFILL` predecessors and the fork point; continuous reorg is re-attempted as data arrives.
- **Metrics**: `ORPHAN_BUFFER_LEN` reflects buffered alternates.

### Miner behavior during reorgs
- **Ignore stale/unalopted anchors**: The miner only mines on the adopted tip; historical and non-adopted alternates are ignored during reorg replay.

```169:191:src/miner.rs
// Ignore historical or non-adopted alternate anchors during reorg replay
if anchor.num < db_latest_num { /* ignore */ }
if let Ok(Some(existing_at_height)) = self.db.get::<Anchor>("epoch", &anchor.num.to_le_bytes()) {
    if existing_at_height.hash != anchor.hash {
        // Ignore alternate fork anchor at this height (not adopted)
        continue;
    }
}
```

### Sync/backoff tie-ins
- **Tip tracking**: `SyncState.highest_seen_epoch` and `peer_confirmed_tip` are updated as valid anchors arrive; the epoch manager waits for at least one peer confirmation (when bootstrap peers exist) before emitting epochs to reduce fork surface.
- **Backoff**: Periodically requests latest epochs and missing ranges, with backoff to avoid re-request spam when a reorg cannot proceed due to missing parents.

### Storage/indexes relevant to reorgs
- **Indexes maintained**: `epoch`, `anchor`, `epoch_selected`, `epoch_leaves`, `coin`, `coin_epoch`, `spend`, `nullifier`.
- **Reorg deletes**: Replaced coins, spend records, and nullifiers are explicitly removed for affected heights. A helper exists for the coin→epoch index:
```633:639:src/storage.rs
/// Delete a mapping coin_id -> epoch number (used during reorgs)
pub fn delete_coin_epoch(&self, coin_id: &[u8;32]) -> Result<()> {
    let cf = self.db.cf_handle("coin_epoch")?;
    self.db.delete_cf(cf, coin_id)?;
    Ok(())
}
```

### Notable constraints and risks
- **No explicit finality window**: Reorg depth is implicitly bounded by how much is buffered/backfilled; there’s no checkpoint/finality rule in `src`.
- **Partial reconstruction tolerated**: If local candidates can’t reproduce the anchor’s merkle root, the anchor is still adopted and indices/leaves may lag until healed via gossip/backfill.
- **Security invariant for headers**: Alternate headers must link correctly and have consistent cumulative work; coin-level validation relies on matching merkle roots when reconstructable.

- Reorg handling core is in `network.rs` (`attempt_reorg`), with miner ignoring non-adopted forks and sync logic aiding backfill. State rollback/adoption touches coins, spends, nullifiers, and per-epoch indexes atomically, then rebroadcasts the adopted anchors.


