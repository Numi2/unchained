// ADVERSARIAL Merkle proof generation & verification tests
// These tests validate the Merkle proof system against known attacks and edge cases.

use std::collections::HashSet;
use unchained::epoch::MerkleTree;
use unchained::coin::Coin;

// Helper to create a set of coin IDs for testing
fn generate_coin_ids(count: u8) -> HashSet<[u8; 32]> {
    let mut coin_ids = HashSet::new();
    for i in 0..count {
        coin_ids.insert([i; 32]);
    }
    coin_ids
}

#[tokio::test]
async fn test_merkle_proof_edge_cases() {
    println!("🧪 Testing Merkle proof edge cases...");

    // Test case 1: Single-element tree
    let coin_ids_single = generate_coin_ids(1);
    let target_id_single = [0u8; 32];
    let root_single = MerkleTree::build_root(&coin_ids_single);
    let proof_single = MerkleTree::build_proof(&coin_ids_single, &target_id_single)
        .expect("Proof should be generated for single element");
    
    assert!(proof_single.is_empty(), "Proof for a single-element tree should be empty");
    let leaf_hash_single = Coin::id_to_leaf_hash(&target_id_single);
    assert!(MerkleTree::verify_proof(&leaf_hash_single, &proof_single, &root_single), "Proof for single element should verify");
    println!("  ✅ Single-element tree proof verified");

    // Test case 2: Two-element tree
    let coin_ids_two = generate_coin_ids(2);
    let target_id_two = [1u8; 32];
    let root_two = MerkleTree::build_root(&coin_ids_two);
    let proof_two = MerkleTree::build_proof(&coin_ids_two, &target_id_two)
        .expect("Proof should be generated for two elements");

    assert_eq!(proof_two.len(), 1, "Proof for a two-element tree should have one sibling");
    let leaf_hash_two = Coin::id_to_leaf_hash(&target_id_two);
    assert!(MerkleTree::verify_proof(&leaf_hash_two, &proof_two, &root_two), "Proof for two elements should verify");
    println!("  ✅ Two-element tree proof verified");

    // Test case 3: Odd-numbered tree (e.g., 5 elements)
    let coin_ids_odd = generate_coin_ids(5);
    let target_id_odd = [3u8; 32]; // An element in the middle
    let root_odd = MerkleTree::build_root(&coin_ids_odd);
    let proof_odd = MerkleTree::build_proof(&coin_ids_odd, &target_id_odd)
        .expect("Proof should be generated for odd-numbered tree");
    
    let leaf_hash_odd = Coin::id_to_leaf_hash(&target_id_odd);
    assert!(MerkleTree::verify_proof(&leaf_hash_odd, &proof_odd, &root_odd), "Proof for odd-numbered tree should verify");
    println!("  ✅ Odd-numbered (5) element tree proof verified");

    // Test case 4: Proof for first and last elements
    let coin_ids_many = generate_coin_ids(8);
    let root_many = MerkleTree::build_root(&coin_ids_many);
    
    let target_first = [0u8; 32];
    let proof_first = MerkleTree::build_proof(&coin_ids_many, &target_first).unwrap();
    let leaf_first = Coin::id_to_leaf_hash(&target_first);
    assert!(MerkleTree::verify_proof(&leaf_first, &proof_first, &root_many), "Proof for first element should verify");
    
    let target_last = [7u8; 32];
    let proof_last = MerkleTree::build_proof(&coin_ids_many, &target_last).unwrap();
    let leaf_last = Coin::id_to_leaf_hash(&target_last);
    assert!(MerkleTree::verify_proof(&leaf_last, &proof_last, &root_many), "Proof for last element should verify");
    println!("  ✅ Proofs for first and last elements verified");
    
    println!("✅ Merkle proof edge cases test passed");
}

#[tokio::test]
async fn test_merkle_proof_adversarial() {
    println!("🧪 Testing adversarial Merkle proofs...");
    let coin_ids = generate_coin_ids(8);
    let target_id = [4u8; 32];
    let root = MerkleTree::build_root(&coin_ids);
    let leaf_hash = Coin::id_to_leaf_hash(&target_id);
    let valid_proof = MerkleTree::build_proof(&coin_ids, &target_id).unwrap();

    // Attack 1: Proof for a non-existent element
    let non_existent_id = [99u8; 32];
    assert!(!coin_ids.contains(&non_existent_id));
    let proof_non_existent = MerkleTree::build_proof(&coin_ids, &non_existent_id);
    assert!(proof_non_existent.is_none(), "Should not be able to generate a proof for a non-existent element");
    println!("  ✅ Cannot generate proof for non-existent element");

    // Attack 2: Malformed proof - incorrect length
    let mut short_proof = valid_proof.clone();
    short_proof.pop();
    assert!(!MerkleTree::verify_proof(&leaf_hash, &short_proof, &root), "Verification should fail for a proof that is too short");
    println!("  ✅ Verification fails for short proof");

    // Attack 3: Malformed proof - swapped sibling order (left vs. right)
    let mut swapped_proof = valid_proof.clone();
    if swapped_proof.len() >= 1 {
        let (hash, is_left) = swapped_proof[0];
        swapped_proof[0] = (hash, !is_left); // Flip the position
        assert!(!MerkleTree::verify_proof(&leaf_hash, &swapped_proof, &root), "Verification should fail if sibling position is wrong");
        println!("  ✅ Verification fails for swapped sibling proof");
    }

    // Attack 4: Malformed proof - contains a duplicate hash
    let mut duplicate_proof = valid_proof.clone();
    if duplicate_proof.len() >= 2 {
        duplicate_proof[1] = duplicate_proof[0];
        assert!(!MerkleTree::verify_proof(&leaf_hash, &duplicate_proof, &root), "Verification should fail for a proof with duplicate hashes");
        println!("  ✅ Verification fails for proof with duplicate hashes");
    }
    
    // Attack 5: Second pre-image attempt (using a different leaf to generate the same root)
    // This is hard to test directly without finding a hash collision.
    // Instead, we verify that a proof for one leaf is not valid for another leaf.
    let other_target_id = [5u8; 32];
    let other_leaf_hash = Coin::id_to_leaf_hash(&other_target_id);
    assert_ne!(leaf_hash, other_leaf_hash);
    assert!(!MerkleTree::verify_proof(&other_leaf_hash, &valid_proof, &root), "Proof for one leaf should not be valid for another");
    println!("  ✅ Proof for one leaf is not valid for another");

    println!("✅ Adversarial Merkle proof test passed");
}
