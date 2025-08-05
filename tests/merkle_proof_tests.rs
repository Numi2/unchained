// Merkle proof generation & verification tests
// These tests ensure that the newly–added MerkleTree::build_proof and
// MerkleTree::verify_proof work correctly and catch incorrect proofs.

use std::collections::HashSet;
use unchained::epoch::MerkleTree;
use unchained::coin::Coin;

#[tokio::test]
async fn test_merkle_proof_generation_and_verification() {
    // Build a sample set of coin IDs
    let mut coin_ids: HashSet<[u8; 32]> = HashSet::new();
    for i in 0..6u8 {
        coin_ids.insert([i; 32]);
    }

    // Choose one target ID from the set
    let target_id = [3u8; 32];
    assert!(coin_ids.contains(&target_id));

    // Compute Merkle root using library function
    let root = MerkleTree::build_root(&coin_ids);
    assert_ne!(root, [0u8; 32], "Root should not be zero for non-empty tree");

    // Generate inclusion proof
    let proof = MerkleTree::build_proof(&coin_ids, &target_id)
        .expect("Proof should be generated for existing element");
    assert!(!proof.is_empty(), "Proof should have at least one sibling");

    // Verify inclusion using library verify function
    let leaf_hash = Coin::id_to_leaf_hash(&target_id);
    assert!(MerkleTree::verify_proof(&leaf_hash, &proof, &root), "Proof must verify for correct data");

    // --------------------------------------------------------------------
    // Negative tests – mutate proof / leaf / root and ensure verification fails
    // --------------------------------------------------------------------

    // 1. Mutate leaf hash
    let mut bad_leaf = leaf_hash;
    bad_leaf[0] ^= 0x01;
    assert!(!MerkleTree::verify_proof(&bad_leaf, &proof, &root), "Modified leaf hash should fail verification");

    // 2. Mutate one sibling in the proof
    let mut bad_proof = proof.clone();
    bad_proof[0].0[0] ^= 0x01;
    assert!(
        !MerkleTree::verify_proof(&leaf_hash, &bad_proof, &root),
        "Corrupted proof should fail verification"
    );

    // 3. Use wrong root
    let wrong_root = [0xAAu8; 32];
    assert!(
        !MerkleTree::verify_proof(&leaf_hash, &proof, &wrong_root),
        "Wrong root should fail verification"
    );

    println!("✅ Merkle proof generation & verification tests passed");
}
