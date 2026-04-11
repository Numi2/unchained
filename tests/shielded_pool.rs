use std::sync::Arc;

use anyhow::Result;
use tempfile::TempDir;
use unchained::{
    crypto::{TaggedKemPublicKey, TaggedSigningPublicKey},
    shielded::{
        HistoricalNullifierWindow, NoteCommitmentTree, ShieldedNote, ShieldedSyncServer,
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
fn historical_nullifier_window_absence_proof_verifies_boundaries() -> Result<()> {
    let epoch =
        HistoricalNullifierWindow::new(9, vec![[10u8; 32], [20u8; 32], [30u8; 32], [40u8; 32]]);
    let queried = [25u8; 32];
    let proof = epoch.prove_absence(queried)?;
    proof.verify()?;
    assert_eq!(proof.epoch, 9);
    assert_eq!(proof.queried_nullifier, queried);
    assert!(epoch.prove_absence([20u8; 32]).is_err());
    Ok(())
}

#[test]
fn storage_roundtrip_persists_shielded_state() -> Result<()> {
    let tempdir = TempDir::new()?;
    let db = Arc::new(Store::open(&tempdir.path().to_string_lossy())?);

    let note = fixed_note(8, [31u8; 32], [32u8; 32], [33u8; 32]);
    let mut tree = NoteCommitmentTree::new();
    tree.append(note.commitment)?;
    let epoch = HistoricalNullifierWindow::new(8, vec![[41u8; 32], [42u8; 32]]);
    let mut provider = ShieldedSyncServer::new();
    provider.finalized_history_epoch(epoch.epoch, epoch.nullifiers.clone())?;

    db.store_shielded_note_tree(&tree)?;
    db.store_shielded_historical_nullifier_window(&epoch)?;
    db.store_shielded_root_ledger(provider.root_ledger())?;

    let loaded_tree = db.load_shielded_note_tree()?.expect("tree");
    let loaded_epoch = db
        .load_shielded_historical_nullifier_window(8)?
        .expect("epoch");
    let loaded_ledger = db.load_shielded_root_ledger()?.expect("ledger");

    assert_eq!(loaded_tree, tree);
    assert_eq!(loaded_epoch, epoch);
    assert_eq!(loaded_ledger, provider.root_ledger().clone());

    db.close()?;
    Ok(())
}
