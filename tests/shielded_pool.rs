use std::sync::Arc;

use anyhow::Result;
use tempfile::TempDir;
use unchained::{
    crypto::{TaggedKemPublicKey, TaggedSigningPublicKey},
    shielded::{
        ArchivedNullifierEpoch, HistoricalUnspentCheckpoint, NoteCommitmentTree, ShieldedNote,
        ShieldedSyncServer,
    },
    Store,
};

fn fixed_note(
    birth_epoch: u64,
    note_key: [u8; 32],
    rho: [u8; 32],
    note_randomizer: [u8; 32],
) -> ShieldedNote {
    ShieldedNote::new(
        42,
        birth_epoch,
        TaggedSigningPublicKey::zero_ml_dsa_65(),
        TaggedKemPublicKey::zero_ml_kem_768(),
        note_key,
        rho,
        note_randomizer,
    )
}

#[test]
fn shielded_note_commitment_and_evolving_nullifiers_are_epoch_scoped() -> Result<()> {
    let note_key = [7u8; 32];
    let note = fixed_note(5, note_key, [9u8; 32], [11u8; 32]);
    note.validate()?;

    let chain_id = [3u8; 32];
    let nullifier_5 = note.derive_evolving_nullifier(&note_key, &chain_id, 5)?;
    let nullifier_6 = note.derive_evolving_nullifier(&note_key, &chain_id, 6)?;
    let nullifier_6_repeat = note.derive_evolving_nullifier(&note_key, &chain_id, 6)?;

    assert_ne!(nullifier_5, nullifier_6);
    assert_eq!(nullifier_6, nullifier_6_repeat);
    assert!(note
        .derive_evolving_nullifier(&note_key, &chain_id, 4)
        .is_err());
    Ok(())
}

#[test]
fn note_commitment_tree_membership_proof_verifies() -> Result<()> {
    let notes = vec![
        fixed_note(1, [1u8; 32], [2u8; 32], [3u8; 32]),
        fixed_note(1, [4u8; 32], [5u8; 32], [6u8; 32]),
        fixed_note(1, [7u8; 32], [8u8; 32], [9u8; 32]),
    ];
    let mut tree = NoteCommitmentTree::new();
    for note in &notes {
        tree.append(note.commitment)?;
    }

    let proof = tree
        .prove_membership(&notes[1].commitment)
        .expect("membership proof");
    assert!(proof.verify());
    assert_eq!(proof.root, tree.root());
    Ok(())
}

#[test]
fn archived_nullifier_epoch_absence_proof_verifies_boundaries() -> Result<()> {
    let epoch =
        ArchivedNullifierEpoch::new(9, vec![[10u8; 32], [20u8; 32], [30u8; 32], [40u8; 32]]);
    let queried = [25u8; 32];
    let proof = epoch.prove_absence(queried)?;
    proof.verify()?;
    assert_eq!(proof.epoch, 9);
    assert_eq!(proof.queried_nullifier, queried);
    assert!(epoch.prove_absence([20u8; 32]).is_err());
    Ok(())
}

#[test]
fn checkpoint_extensions_are_portable_across_providers() -> Result<()> {
    let note_key = [13u8; 32];
    let note = fixed_note(5, note_key, [14u8; 32], [15u8; 32]);
    let chain_id = [44u8; 32];

    let mut provider_a = ShieldedSyncServer::new();
    let mut provider_b = ShieldedSyncServer::new();
    for (epoch, set) in [
        (5u64, vec![[90u8; 32], [91u8; 32]]),
        (6u64, vec![[92u8; 32]]),
        (7u64, vec![[93u8; 32], [94u8; 32], [95u8; 32]]),
    ] {
        provider_a.archive_epoch(epoch, set.clone())?;
        provider_b.archive_epoch(epoch, set)?;
    }

    let checkpoint0 = HistoricalUnspentCheckpoint::genesis(note.commitment, note.birth_epoch);
    let query5 = note.derive_evolving_nullifier(&note_key, &chain_id, 5)?;
    let query6 = note.derive_evolving_nullifier(&note_key, &chain_id, 6)?;
    let query7 = note.derive_evolving_nullifier(&note_key, &chain_id, 7)?;

    let extension_a = provider_a.extend_checkpoint(
        &checkpoint0,
        &[
            unchained::shielded::EvolvingNullifierQuery {
                epoch: 5,
                nullifier: query5,
            },
            unchained::shielded::EvolvingNullifierQuery {
                epoch: 6,
                nullifier: query6,
            },
        ],
    )?;
    let checkpoint1 = checkpoint0.apply_extension(&extension_a, provider_b.root_ledger())?;
    assert_eq!(checkpoint1.covered_through_epoch, 6);

    let extension_b = provider_b.extend_checkpoint(
        &checkpoint1,
        &[unchained::shielded::EvolvingNullifierQuery {
            epoch: 7,
            nullifier: query7,
        }],
    )?;
    let checkpoint2 = checkpoint1.apply_extension(&extension_b, provider_a.root_ledger())?;
    assert_eq!(checkpoint2.covered_through_epoch, 7);
    assert_eq!(checkpoint2.verified_epoch_count, 3);
    Ok(())
}

#[test]
fn checkpoint_extensions_can_be_batched_across_notes() -> Result<()> {
    let chain_id = [77u8; 32];
    let note_a_key = [17u8; 32];
    let note_b_key = [27u8; 32];
    let note_a = fixed_note(5, note_a_key, [18u8; 32], [19u8; 32]);
    let note_b = fixed_note(6, note_b_key, [28u8; 32], [29u8; 32]);

    let mut provider = ShieldedSyncServer::new();
    for (epoch, set) in [
        (5u64, vec![[90u8; 32], [91u8; 32]]),
        (6u64, vec![[92u8; 32], [93u8; 32]]),
        (7u64, vec![[94u8; 32], [95u8; 32]]),
    ] {
        provider.archive_epoch(epoch, set)?;
    }

    let checkpoint_a = HistoricalUnspentCheckpoint::genesis(note_a.commitment, note_a.birth_epoch);
    let checkpoint_b = HistoricalUnspentCheckpoint::genesis(note_b.commitment, note_b.birth_epoch);
    let batch = provider.extend_checkpoints_batch(&[
        unchained::shielded::CheckpointExtensionRequest {
            checkpoint: checkpoint_a.clone(),
            queries: vec![
                unchained::shielded::EvolvingNullifierQuery {
                    epoch: 5,
                    nullifier: note_a.derive_evolving_nullifier(&note_a_key, &chain_id, 5)?,
                },
                unchained::shielded::EvolvingNullifierQuery {
                    epoch: 6,
                    nullifier: note_a.derive_evolving_nullifier(&note_a_key, &chain_id, 6)?,
                },
                unchained::shielded::EvolvingNullifierQuery {
                    epoch: 7,
                    nullifier: note_a.derive_evolving_nullifier(&note_a_key, &chain_id, 7)?,
                },
            ],
        },
        unchained::shielded::CheckpointExtensionRequest {
            checkpoint: checkpoint_b.clone(),
            queries: vec![
                unchained::shielded::EvolvingNullifierQuery {
                    epoch: 6,
                    nullifier: note_b.derive_evolving_nullifier(&note_b_key, &chain_id, 6)?,
                },
                unchained::shielded::EvolvingNullifierQuery {
                    epoch: 7,
                    nullifier: note_b.derive_evolving_nullifier(&note_b_key, &chain_id, 7)?,
                },
            ],
        },
    ])?;
    assert_eq!(batch.len(), 2);
    assert_eq!(batch[0].through_epoch, 7);
    assert_eq!(batch[1].through_epoch, 7);
    assert_eq!(batch[0].records.len(), 3);
    assert_eq!(batch[1].records.len(), 2);
    Ok(())
}

#[test]
fn checkpoint_presentations_are_blinded() -> Result<()> {
    let note = fixed_note(3, [21u8; 32], [22u8; 32], [23u8; 32]);
    let checkpoint = HistoricalUnspentCheckpoint::genesis(note.commitment, note.birth_epoch);
    let presentation_a = checkpoint.presentation([1u8; 32]);
    let presentation_b = checkpoint.presentation([2u8; 32]);

    assert!(presentation_a.verify());
    assert!(presentation_b.verify());
    assert_ne!(
        presentation_a.presentation_digest,
        presentation_b.presentation_digest
    );
    Ok(())
}

#[test]
fn storage_roundtrip_persists_shielded_state() -> Result<()> {
    let tempdir = TempDir::new()?;
    let db = Arc::new(Store::open(&tempdir.path().to_string_lossy())?);

    let note = fixed_note(8, [31u8; 32], [32u8; 32], [33u8; 32]);
    let mut tree = NoteCommitmentTree::new();
    tree.append(note.commitment)?;
    let epoch = ArchivedNullifierEpoch::new(8, vec![[41u8; 32], [42u8; 32]]);
    let mut provider = ShieldedSyncServer::new();
    provider.archive_epoch(epoch.epoch, epoch.nullifiers.clone())?;
    let checkpoint = HistoricalUnspentCheckpoint::genesis(note.commitment, note.birth_epoch);

    db.store_shielded_note_tree(&tree)?;
    db.store_shielded_nullifier_epoch(&epoch)?;
    db.store_shielded_root_ledger(provider.root_ledger())?;
    db.store_shielded_checkpoint(&checkpoint)?;

    let loaded_tree = db.load_shielded_note_tree()?.expect("tree");
    let loaded_epoch = db.load_shielded_nullifier_epoch(8)?.expect("epoch");
    let loaded_ledger = db.load_shielded_root_ledger()?.expect("ledger");
    let loaded_checkpoint = db
        .load_shielded_checkpoint(&note.commitment)?
        .expect("checkpoint");

    assert_eq!(loaded_tree, tree);
    assert_eq!(loaded_epoch, epoch);
    assert_eq!(loaded_ledger, provider.root_ledger().clone());
    assert_eq!(loaded_checkpoint, checkpoint);

    db.close()?;
    Ok(())
}
