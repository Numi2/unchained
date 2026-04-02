use std::sync::Arc;

use anyhow::Result;
use tempfile::TempDir;
use unchained::{
    crypto::{TaggedKemPublicKey, TaggedSigningPublicKey},
    shielded::{
        assigned_archive_custodians, local_archive_custody_commitments,
        local_archive_provider_manifest, local_archive_replica_attestations,
        route_checkpoint_requests, ArchiveDirectory, ArchiveRetrievalKind, ArchiveRetrievalReceipt,
        ArchiveServiceLedger, ArchivedNullifierEpoch, CheckpointExtensionRequest,
        EvolvingNullifierQuery, HistoricalUnspentCheckpoint, HistoricalUnspentExtension,
        NoteCommitmentTree, ShieldedNote, ShieldedSyncServer,
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
    let available_epochs = provider_a.root_ledger().roots.keys().copied().collect();
    let manifest_a =
        local_archive_provider_manifest([1u8; 32], provider_a.root_ledger(), 2, &available_epochs)?;
    let manifest_b =
        local_archive_provider_manifest([2u8; 32], provider_b.root_ledger(), 2, &available_epochs)?;
    let directory = ArchiveDirectory::from_root_ledger_and_providers(
        provider_a.root_ledger(),
        2,
        vec![manifest_a.clone(), manifest_b.clone()],
    )?;

    let checkpoint0 = HistoricalUnspentCheckpoint::genesis(note.commitment, note.birth_epoch);
    let query5 = note.derive_evolving_nullifier(&note_key, &chain_id, 5)?;
    let query6 = note.derive_evolving_nullifier(&note_key, &chain_id, 6)?;
    let query7 = note.derive_evolving_nullifier(&note_key, &chain_id, 7)?;

    let response_a = provider_a.serve_checkpoint(
        &manifest_a,
        &checkpoint0,
        &[
            EvolvingNullifierQuery {
                epoch: 5,
                nullifier: query5,
            },
            EvolvingNullifierQuery {
                epoch: 6,
                nullifier: query6,
            },
        ],
    )?;
    response_a.verify_against_manifest(&manifest_a, &directory)?;
    let extension_a = HistoricalUnspentExtension::aggregate(
        &checkpoint0,
        vec![response_a.rerandomize([1u8; 32])],
        [3u8; 32],
    )?;
    let checkpoint1 = checkpoint0.apply_extension(&extension_a, provider_b.root_ledger())?;
    assert_eq!(checkpoint1.covered_through_epoch, 6);

    let response_b = provider_b.serve_checkpoint(
        &manifest_b,
        &checkpoint1,
        &[EvolvingNullifierQuery {
            epoch: 7,
            nullifier: query7,
        }],
    )?;
    response_b.verify_against_manifest(&manifest_b, &directory)?;
    let extension_b = HistoricalUnspentExtension::aggregate(
        &checkpoint1,
        vec![response_b.rerandomize([2u8; 32])],
        [4u8; 32],
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
    let available_epochs = provider.root_ledger().roots.keys().copied().collect();
    let manifest =
        local_archive_provider_manifest([3u8; 32], provider.root_ledger(), 2, &available_epochs)?;
    let _directory = ArchiveDirectory::from_root_ledger_and_providers(
        provider.root_ledger(),
        2,
        vec![manifest.clone()],
    )?;

    let checkpoint_a = HistoricalUnspentCheckpoint::genesis(note_a.commitment, note_a.birth_epoch);
    let checkpoint_b = HistoricalUnspentCheckpoint::genesis(note_b.commitment, note_b.birth_epoch);
    let batch = provider.serve_checkpoints_batch(
        &manifest,
        &[
            CheckpointExtensionRequest {
                checkpoint: checkpoint_a.clone(),
                queries: vec![
                    EvolvingNullifierQuery {
                        epoch: 5,
                        nullifier: note_a.derive_evolving_nullifier(&note_a_key, &chain_id, 5)?,
                    },
                    EvolvingNullifierQuery {
                        epoch: 6,
                        nullifier: note_a.derive_evolving_nullifier(&note_a_key, &chain_id, 6)?,
                    },
                    EvolvingNullifierQuery {
                        epoch: 7,
                        nullifier: note_a.derive_evolving_nullifier(&note_a_key, &chain_id, 7)?,
                    },
                ],
            },
            CheckpointExtensionRequest {
                checkpoint: checkpoint_b.clone(),
                queries: vec![
                    EvolvingNullifierQuery {
                        epoch: 6,
                        nullifier: note_b.derive_evolving_nullifier(&note_b_key, &chain_id, 6)?,
                    },
                    EvolvingNullifierQuery {
                        epoch: 7,
                        nullifier: note_b.derive_evolving_nullifier(&note_b_key, &chain_id, 7)?,
                    },
                ],
            },
        ],
    )?;
    assert_eq!(batch.len(), 2);
    assert_eq!(batch[0].through_epoch, 7);
    assert_eq!(batch[1].through_epoch, 7);
    assert_eq!(batch[0].records.len(), 3);
    assert_eq!(batch[1].records.len(), 2);
    let rerandomized_a = HistoricalUnspentExtension::aggregate(
        &checkpoint_a,
        vec![batch[0].rerandomize([7u8; 32])],
        [9u8; 32],
    )?;
    let rerandomized_b = HistoricalUnspentExtension::aggregate(
        &checkpoint_b,
        vec![batch[1].rerandomize([8u8; 32])],
        [10u8; 32],
    )?;
    assert_ne!(
        rerandomized_a.new_transcript_root,
        rerandomized_b.new_transcript_root
    );
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
fn provider_rotation_changes_query_assignment_across_rounds() -> Result<()> {
    let chain_id = [55u8; 32];
    let note_key = [56u8; 32];
    let note = fixed_note(5, note_key, [57u8; 32], [58u8; 32]);
    let mut provider = ShieldedSyncServer::new();
    for epoch in 5u64..=8 {
        provider.archive_epoch(epoch, vec![[epoch as u8; 32]])?;
    }
    let available_epochs = provider.root_ledger().roots.keys().copied().collect();
    let manifests = (0u8..4)
        .map(|seed| {
            local_archive_provider_manifest(
                [seed + 10; 32],
                provider.root_ledger(),
                2,
                &available_epochs,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let directory =
        ArchiveDirectory::from_root_ledger_and_providers(provider.root_ledger(), 2, manifests)?;
    let checkpoint = HistoricalUnspentCheckpoint::genesis(note.commitment, note.birth_epoch);
    let request = CheckpointExtensionRequest {
        checkpoint: checkpoint.clone(),
        queries: (5u64..=8)
            .map(|epoch| {
                Ok(EvolvingNullifierQuery {
                    epoch,
                    nullifier: note.derive_evolving_nullifier(&note_key, &chain_id, epoch)?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
    };
    let mut providers = std::collections::BTreeSet::new();
    for round in 0u64..8 {
        let batches =
            route_checkpoint_requests(&directory, std::slice::from_ref(&request), round, 4, 16)?;
        assert!(!batches.is_empty());
        providers.insert(batches[0].provider_id);
    }
    assert!(providers.len() > 1);
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

#[test]
fn route_checkpoint_requests_stripes_one_note_across_multiple_providers() -> Result<()> {
    let chain_id = [66u8; 32];
    let note_key = [67u8; 32];
    let note = fixed_note(5, note_key, [68u8; 32], [69u8; 32]);
    let mut provider = ShieldedSyncServer::new();
    for epoch in 5u64..=8 {
        provider.archive_epoch(epoch, vec![[epoch as u8; 32]])?;
    }
    let available_epochs = provider.root_ledger().roots.keys().copied().collect();
    let manifests = (0u8..3)
        .map(|seed| {
            local_archive_provider_manifest(
                [seed + 20; 32],
                provider.root_ledger(),
                2,
                &available_epochs,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    let directory =
        ArchiveDirectory::from_root_ledger_and_providers(provider.root_ledger(), 2, manifests)?;
    let checkpoint = HistoricalUnspentCheckpoint::genesis(note.commitment, note.birth_epoch);
    let request = CheckpointExtensionRequest {
        checkpoint,
        queries: (5u64..=8)
            .map(|epoch| {
                Ok(EvolvingNullifierQuery {
                    epoch,
                    nullifier: note.derive_evolving_nullifier(&note_key, &chain_id, epoch)?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
    };
    let batches = route_checkpoint_requests(&directory, std::slice::from_ref(&request), 11, 2, 8)?;
    let routed_providers = batches
        .iter()
        .flat_map(|batch| batch.requests.iter())
        .filter_map(|request| request.request_index.map(|_| request.provider_id))
        .collect::<std::collections::BTreeSet<_>>();
    assert!(routed_providers.len() > 1);
    Ok(())
}

#[test]
fn archive_replica_reports_and_custody_assignments_track_durability() -> Result<()> {
    let mut provider = ShieldedSyncServer::new();
    for epoch in 5u64..=8 {
        provider.archive_epoch(epoch, vec![[epoch as u8; 32]])?;
    }
    let available_epochs = provider.root_ledger().roots.keys().copied().collect();
    let manifest_a =
        local_archive_provider_manifest([31u8; 32], provider.root_ledger(), 2, &available_epochs)?;
    let manifest_b =
        local_archive_provider_manifest([32u8; 32], provider.root_ledger(), 2, &available_epochs)?;
    let base_directory = ArchiveDirectory::from_root_ledger_and_providers(
        provider.root_ledger(),
        2,
        vec![manifest_a.clone(), manifest_b.clone()],
    )?;
    let mut replicas =
        local_archive_replica_attestations(manifest_a.provider_id, &base_directory, 32)?;
    replicas.extend(local_archive_replica_attestations(
        manifest_b.provider_id,
        &base_directory,
        64,
    )?);
    let directory = ArchiveDirectory::from_root_ledger_and_providers_and_replicas(
        provider.root_ledger(),
        2,
        vec![manifest_a.clone(), manifest_b.clone()],
        replicas,
    )?;

    let report = directory.replica_report(0)?;
    assert_eq!(report.replica_count, 2);
    assert!(report.retention_through_epoch >= 37);
    assert!(!directory.under_replicated_shards(3).is_empty());

    let custodians = assigned_archive_custodians(
        0,
        &directory.shard(0).expect("shard").root_digest,
        &[[1u8; 32], [2u8; 32], [3u8; 32]],
        2,
    );
    assert_eq!(custodians.len(), 2);
    assert_ne!(custodians[0], custodians[1]);
    Ok(())
}

#[test]
fn checkpoint_extensions_packetize_large_segment_sets() -> Result<()> {
    let chain_id = [81u8; 32];
    let note_key = [82u8; 32];
    let note = fixed_note(5, note_key, [83u8; 32], [84u8; 32]);
    let checkpoint = HistoricalUnspentCheckpoint::genesis(note.commitment, note.birth_epoch);
    let mut provider = ShieldedSyncServer::new();
    for epoch in 5u64..=10 {
        provider.archive_epoch(epoch, vec![[epoch as u8; 32]])?;
    }
    let available_epochs = provider.root_ledger().roots.keys().copied().collect();
    let manifest =
        local_archive_provider_manifest([44u8; 32], provider.root_ledger(), 1, &available_epochs)?;

    let mut segments = Vec::new();
    for epoch in 5u64..=10 {
        let segment_checkpoint = HistoricalUnspentCheckpoint {
            version: checkpoint.version,
            note_commitment: checkpoint.note_commitment,
            birth_epoch: checkpoint.birth_epoch,
            covered_through_epoch: epoch.saturating_sub(1),
            transcript_root: checkpoint.transcript_root,
            verified_epoch_count: checkpoint.verified_epoch_count,
        };
        let response = provider.serve_checkpoint(
            &manifest,
            &segment_checkpoint,
            &[EvolvingNullifierQuery {
                epoch,
                nullifier: note.derive_evolving_nullifier(&note_key, &chain_id, epoch)?,
            }],
        )?;
        segments.push(response.rerandomize([epoch as u8; 32]));
    }

    let extension = HistoricalUnspentExtension::aggregate(&checkpoint, segments, [91u8; 32])?;
    assert!(extension.strata.len() >= 1);
    assert_eq!(
        extension
            .strata
            .iter()
            .flat_map(|stratum| stratum.packets.iter())
            .map(|packet| packet.segments.len())
            .sum::<usize>(),
        6
    );
    let updated = checkpoint.apply_extension(&extension, provider.root_ledger())?;
    assert_eq!(updated.covered_through_epoch, 10);
    Ok(())
}

#[test]
fn archive_operator_scorecards_reward_long_retention() -> Result<()> {
    let mut provider = ShieldedSyncServer::new();
    for epoch in 5u64..=8 {
        provider.archive_epoch(epoch, vec![[epoch as u8; 32]])?;
    }
    let available_epochs = provider.root_ledger().roots.keys().copied().collect();
    let manifest_a =
        local_archive_provider_manifest([51u8; 32], provider.root_ledger(), 2, &available_epochs)?;
    let manifest_b =
        local_archive_provider_manifest([52u8; 32], provider.root_ledger(), 2, &available_epochs)?;
    let base_directory = ArchiveDirectory::from_root_ledger_and_providers(
        provider.root_ledger(),
        2,
        vec![manifest_a.clone(), manifest_b.clone()],
    )?;
    let mut replicas =
        local_archive_replica_attestations(manifest_a.provider_id, &base_directory, 16)?;
    replicas.extend(local_archive_replica_attestations(
        manifest_b.provider_id,
        &base_directory,
        64,
    )?);
    let directory = ArchiveDirectory::from_root_ledger_and_providers_and_replicas(
        provider.root_ledger(),
        2,
        vec![manifest_a.clone(), manifest_b.clone()],
        replicas,
    )?;
    let mut commitments =
        local_archive_custody_commitments(manifest_a.provider_id, &directory, 2, 32)?;
    commitments.extend(local_archive_custody_commitments(
        manifest_b.provider_id,
        &directory,
        2,
        32,
    )?);
    let directory = ArchiveDirectory::from_root_ledger_and_providers_and_replicas_and_evidence(
        provider.root_ledger(),
        2,
        vec![manifest_a.clone(), manifest_b.clone()],
        directory.replicas.clone(),
        Vec::new(),
        commitments,
        Vec::new(),
    )?;

    let mut scorecards = directory.operator_scorecards(2, 32);
    scorecards.sort_by_key(|scorecard| scorecard.provider_id);
    assert_eq!(scorecards.len(), 2);
    let score_a = &scorecards[0];
    let score_b = &scorecards[1];
    assert!(score_b.retention_surplus_epochs > score_a.retention_surplus_epochs);
    assert!(score_b.reward_weight > score_a.reward_weight);
    Ok(())
}

#[test]
fn archive_service_ledgers_feed_availability_certificates() -> Result<()> {
    let mut provider = ShieldedSyncServer::new();
    for epoch in 5u64..=8 {
        provider.archive_epoch(epoch, vec![[epoch as u8; 32]])?;
    }
    let available_epochs = provider.root_ledger().roots.keys().copied().collect();
    let manifest_a =
        local_archive_provider_manifest([61u8; 32], provider.root_ledger(), 2, &available_epochs)?;
    let manifest_b =
        local_archive_provider_manifest([62u8; 32], provider.root_ledger(), 2, &available_epochs)?;
    let base_directory = ArchiveDirectory::from_root_ledger_and_providers(
        provider.root_ledger(),
        2,
        vec![manifest_a.clone(), manifest_b.clone()],
    )?;
    let mut replicas =
        local_archive_replica_attestations(manifest_a.provider_id, &base_directory, 512)?;
    replicas.extend(local_archive_replica_attestations(
        manifest_b.provider_id,
        &base_directory,
        512,
    )?);
    let mut ledger_a =
        ArchiveServiceLedger::new(manifest_a.provider_id, manifest_a.manifest_digest);
    ledger_a.record_checkpoint_failure();
    let mut ledger_b =
        ArchiveServiceLedger::new(manifest_b.provider_id, manifest_b.manifest_digest);
    ledger_b.record_checkpoint_success(4, 12, 1_000);
    ledger_b.record_archive_shard_success(2, 1_001);
    let replica_directory = ArchiveDirectory::from_root_ledger_and_providers_and_replicas(
        provider.root_ledger(),
        2,
        vec![manifest_a.clone(), manifest_b.clone()],
        replicas,
    )?;
    let commitments_b =
        local_archive_custody_commitments(manifest_b.provider_id, &replica_directory, 2, 32)?;
    let directory = ArchiveDirectory::from_root_ledger_and_providers_and_replicas_and_evidence(
        provider.root_ledger(),
        2,
        vec![manifest_a.clone(), manifest_b.clone()],
        replica_directory.replicas.clone(),
        vec![ledger_a, ledger_b],
        commitments_b,
        Vec::new(),
    )?;

    let shard_id = directory.shards.first().expect("shard").shard_id;
    let cert = directory
        .availability_certificate(shard_id)
        .expect("availability cert");
    assert!(cert.certified_providers.contains(&manifest_b.provider_id));
    assert!(!cert.certified_providers.contains(&manifest_a.provider_id));
    let score_a = directory.operator_scorecard(&manifest_a.provider_id, 2, 32)?;
    let score_b = directory.operator_scorecard(&manifest_b.provider_id, 2, 32)?;
    assert!(score_b.service_success_bps > score_a.service_success_bps);
    assert!(score_b.reward_weight > score_a.reward_weight);
    Ok(())
}

#[test]
fn archive_custody_commitments_gate_certification_and_rewards() -> Result<()> {
    let mut provider = ShieldedSyncServer::new();
    for epoch in 5u64..=8 {
        provider.archive_epoch(epoch, vec![[epoch as u8; 32]])?;
    }
    let available_epochs = provider.root_ledger().roots.keys().copied().collect();
    let manifest_a =
        local_archive_provider_manifest([71u8; 32], provider.root_ledger(), 2, &available_epochs)?;
    let manifest_b =
        local_archive_provider_manifest([72u8; 32], provider.root_ledger(), 2, &available_epochs)?;
    let base_directory = ArchiveDirectory::from_root_ledger_and_providers(
        provider.root_ledger(),
        2,
        vec![manifest_a.clone(), manifest_b.clone()],
    )?;
    let mut replicas =
        local_archive_replica_attestations(manifest_a.provider_id, &base_directory, 512)?;
    replicas.extend(local_archive_replica_attestations(
        manifest_b.provider_id,
        &base_directory,
        512,
    )?);
    let replica_directory = ArchiveDirectory::from_root_ledger_and_providers_and_replicas(
        provider.root_ledger(),
        2,
        vec![manifest_a.clone(), manifest_b.clone()],
        replicas.clone(),
    )?;
    let commitments_b =
        local_archive_custody_commitments(manifest_b.provider_id, &replica_directory, 2, 32)?;
    let directory = ArchiveDirectory::from_root_ledger_and_providers_and_replicas_and_evidence(
        provider.root_ledger(),
        2,
        vec![manifest_a.clone(), manifest_b.clone()],
        replicas,
        Vec::new(),
        commitments_b,
        Vec::new(),
    )?;

    let shard_id = directory.shards.first().expect("shard").shard_id;
    let cert = directory
        .availability_certificate(shard_id)
        .expect("availability cert");
    assert!(cert.certified_providers.contains(&manifest_b.provider_id));
    assert!(!cert.certified_providers.contains(&manifest_a.provider_id));

    let score_a = directory.operator_scorecard(&manifest_a.provider_id, 2, 32)?;
    let score_b = directory.operator_scorecard(&manifest_b.provider_id, 2, 32)?;
    assert_eq!(score_a.committed_custody_count, 0);
    assert!(score_b.committed_custody_count > 0);
    assert!(score_b.availability_bps > score_a.availability_bps);
    assert!(score_b.reward_weight > score_a.reward_weight);
    Ok(())
}

#[test]
fn archive_retrieval_receipts_override_local_service_bias() -> Result<()> {
    let mut provider = ShieldedSyncServer::new();
    for epoch in 5u64..=8 {
        provider.archive_epoch(epoch, vec![[epoch as u8; 32]])?;
    }
    let available_epochs = provider.root_ledger().roots.keys().copied().collect();
    let manifest_a =
        local_archive_provider_manifest([81u8; 32], provider.root_ledger(), 2, &available_epochs)?;
    let manifest_b =
        local_archive_provider_manifest([82u8; 32], provider.root_ledger(), 2, &available_epochs)?;
    let base_directory = ArchiveDirectory::from_root_ledger_and_providers(
        provider.root_ledger(),
        2,
        vec![manifest_a.clone(), manifest_b.clone()],
    )?;
    let mut replicas =
        local_archive_replica_attestations(manifest_a.provider_id, &base_directory, 512)?;
    replicas.extend(local_archive_replica_attestations(
        manifest_b.provider_id,
        &base_directory,
        512,
    )?);
    let replica_directory = ArchiveDirectory::from_root_ledger_and_providers_and_replicas(
        provider.root_ledger(),
        2,
        vec![manifest_a.clone(), manifest_b.clone()],
        replicas.clone(),
    )?;
    let mut commitments =
        local_archive_custody_commitments(manifest_a.provider_id, &replica_directory, 2, 32)?;
    commitments.extend(local_archive_custody_commitments(
        manifest_b.provider_id,
        &replica_directory,
        2,
        32,
    )?);
    let mut optimistic_ledger_a =
        ArchiveServiceLedger::new(manifest_a.provider_id, manifest_a.manifest_digest);
    optimistic_ledger_a.record_checkpoint_success(4, 12, 1_000);
    let receipt_a = ArchiveRetrievalReceipt::new(
        [9u8; 32],
        manifest_a.provider_id,
        manifest_a.manifest_digest,
        ArchiveRetrievalKind::CheckpointBatch,
        [1u8; 32],
        None,
        5,
        8,
        None,
        0,
        false,
        21,
        1_111,
    );
    let receipt_b = ArchiveRetrievalReceipt::new(
        [9u8; 32],
        manifest_b.provider_id,
        manifest_b.manifest_digest,
        ArchiveRetrievalKind::CheckpointBatch,
        [2u8; 32],
        Some([3u8; 32]),
        5,
        8,
        None,
        4,
        true,
        11,
        1_112,
    );
    let directory = ArchiveDirectory::from_root_ledger_and_providers_and_replicas_and_evidence(
        provider.root_ledger(),
        2,
        vec![manifest_a.clone(), manifest_b.clone()],
        replicas,
        vec![optimistic_ledger_a],
        commitments,
        vec![receipt_a, receipt_b],
    )?;

    let score_a = directory.operator_scorecard(&manifest_a.provider_id, 2, 32)?;
    let score_b = directory.operator_scorecard(&manifest_b.provider_id, 2, 32)?;
    assert_eq!(score_a.successful_retrieval_receipts, 0);
    assert_eq!(score_a.failed_retrieval_receipts, 1);
    assert_eq!(score_a.service_success_bps, 0);
    assert_eq!(score_b.successful_retrieval_receipts, 1);
    assert_eq!(score_b.failed_retrieval_receipts, 0);
    assert_eq!(score_b.service_success_bps, 10_000);
    assert!(score_b.reward_weight > score_a.reward_weight);
    Ok(())
}
