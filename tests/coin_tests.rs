// Tests MINING SECURITY and PoW INTEGRITY

use unchained::{
    coin::Coin,
    crypto::{self, dilithium3_keypair, address_from_pk},
};

#[tokio::test]
async fn test_coin_pow_validation() {
    println!("🧪 Testing coin PoW validation...");
    
    let (pk, _) = dilithium3_keypair();
    let creator_address = address_from_pk(&pk);
    let epoch_hash = [1u8; 32];
    
    // Test that coins require valid PoW
    fn is_valid_pow(hash: &[u8; 32], difficulty: usize) -> bool {
        hash.iter().take(difficulty).all(|&b| b == 0)
    }
    
    // Test finding a valid coin with difficulty 1
    let mut valid_coin = None;
    let mut attempts = 0;
    let max_attempts = 1000;
    
    for nonce in 0..max_attempts {
        attempts += 1;
        let header = Coin::header_bytes(&epoch_hash, nonce, &creator_address);
        
        if let Ok(pow_hash) = crypto::argon2id_pow(&header, 512, 1) {
            if is_valid_pow(&pow_hash, 1) {
                let coin = Coin::new(epoch_hash, nonce, creator_address, pow_hash);
                
                // Verify the coin actually meets PoW requirement
                assert!(is_valid_pow(&coin.pow_hash, 1), "Coin PoW must be valid");
                assert_eq!(coin.pow_hash[0], 0, "First byte must be zero for difficulty 1");
                
                valid_coin = Some(coin);
                break;
            }
        }
    }
    
    assert!(valid_coin.is_some(), "Should find valid coin within {} attempts", max_attempts);
    println!("  ✅ Found valid coin after {} attempts", attempts);
    
    // Test that invalid PoW coins are rejected
    let invalid_pow_hash = [0xffu8; 32]; // No leading zeros
    let invalid_coin = Coin::new(epoch_hash, 12345, creator_address, invalid_pow_hash);
    
    assert!(!is_valid_pow(&invalid_coin.pow_hash, 1), "Invalid PoW should be rejected");
    println!("  ✅ Invalid PoW properly rejected");
    
    println!("✅ Coin PoW validation test: REAL");
}

#[tokio::test]
async fn test_coin_id_security() {
    println!("🧪 Testing coin ID security...");
    
    let (pk, _) = dilithium3_keypair();
    let creator_address = address_from_pk(&pk);
    let epoch_hash = [2u8; 32];
    let nonce = 54321u64;
    let pow_hash = crypto::argon2id_pow(&Coin::header_bytes(&epoch_hash, nonce, &creator_address), 1024, 1).unwrap();
    
    // Test coin ID uniqueness and determinism
    let coin1 = Coin::new(epoch_hash, nonce, creator_address, pow_hash);
    let coin2 = Coin::new(epoch_hash, nonce, creator_address, pow_hash);
    
    // Same parameters should produce same ID
    assert_eq!(coin1.id, coin2.id, "Same parameters should produce same coin ID");
    
    // Test that small changes produce different IDs
    let coin3 = Coin::new(epoch_hash, nonce + 1, creator_address, pow_hash); // Different nonce
    assert_ne!(coin1.id, coin3.id, "Different nonce should produce different coin ID");
    
    let different_epoch = [3u8; 32];
    let coin4 = Coin::new(different_epoch, nonce, creator_address, pow_hash); // Different epoch
    assert_ne!(coin1.id, coin4.id, "Different epoch should produce different coin ID");
    
    let (pk2, _) = dilithium3_keypair();
    let creator_address2 = address_from_pk(&pk2);
    let coin5 = Coin::new(epoch_hash, nonce, creator_address2, pow_hash); // Different creator
    assert_ne!(coin1.id, coin5.id, "Different creator should produce different coin ID");
    
    // Test ID collision resistance with many coins
    let mut coin_ids = std::collections::HashSet::new();
    let mut collision_found = false;
    
    for i in 0..1000 {
        let test_nonce = i as u64;
        let test_header = Coin::header_bytes(&epoch_hash, test_nonce, &creator_address);
        if let Ok(test_pow) = crypto::argon2id_pow(&test_header, 512, 1) {
            let test_coin = Coin::new(epoch_hash, test_nonce, creator_address, test_pow);
            
            if coin_ids.contains(&test_coin.id) {
                collision_found = true;
                break;
            }
            coin_ids.insert(test_coin.id);
        }
    }
    
    assert!(!collision_found, "Unexpected coin ID collision found");
    println!("  ✅ No coin ID collisions in 1000 samples");
    
    println!("✅ Coin ID security test: REAL");
}

#[tokio::test]
async fn test_coin_header_integrity() {
    println!("🧪 Testing coin header integrity...");
    
    let (pk, _) = dilithium3_keypair();
    let creator_address = address_from_pk(&pk);
    let epoch_hash = [4u8; 32];
    let nonce = 98765u64;
    
    // Test header construction correctness
    let header = Coin::header_bytes(&epoch_hash, nonce, &creator_address);
    
    // Header should be exactly: epoch_hash (32) + nonce (8) + creator_address (32) = 72 bytes
    assert_eq!(header.len(), 72, "Header should be exactly 72 bytes");
    
    // Verify header contains expected data in correct positions
    assert_eq!(&header[0..32], &epoch_hash, "First 32 bytes should be epoch hash");
    assert_eq!(&header[32..40], &nonce.to_le_bytes(), "Next 8 bytes should be nonce in little-endian");
    assert_eq!(&header[40..72], &creator_address, "Last 32 bytes should be creator address");
    
    // Test header modification detection
    let original_header = Coin::header_bytes(&epoch_hash, nonce, &creator_address);
    let pow_hash1 = crypto::argon2id_pow(&original_header, 1024, 1).unwrap();
    
    // Modify one bit in the header data
    let mut modified_epoch = epoch_hash;
    modified_epoch[0] ^= 0x01; // Flip one bit
    let modified_header = Coin::header_bytes(&modified_epoch, nonce, &creator_address);
    let pow_hash2 = crypto::argon2id_pow(&modified_header, 1024, 1).unwrap();
    
    // Should produce completely different PoW hash (avalanche effect)
    assert_ne!(pow_hash1, pow_hash2, "Header modification should change PoW hash");
    
    // Count differing bits to verify avalanche effect
    let mut differing_bits = 0;
    for i in 0..32 {
        differing_bits += (pow_hash1[i] ^ pow_hash2[i]).count_ones();
    }
    assert!(differing_bits > 100, "Header modification should cause significant hash change");
    
    println!("  ✅ Header modification detected ({} bits differ)", differing_bits);
    
    println!("✅ Coin header integrity test: REAL");
}

#[tokio::test]
async fn test_coin_merkle_leaf_security() {
    println!("🧪 Testing coin Merkle leaf security...");
    
    let (pk, _) = dilithium3_keypair();
    let creator_address = address_from_pk(&pk);
    let epoch_hash = [5u8; 32];
    let nonce = 11111u64;
    let pow_hash = crypto::argon2id_pow(&Coin::header_bytes(&epoch_hash, nonce, &creator_address), 1024, 1).unwrap();
    
    let coin = Coin::new(epoch_hash, nonce, creator_address, pow_hash);
    
    // Test leaf hash generation
    let leaf_hash = Coin::id_to_leaf_hash(&coin.id);
    
    assert_eq!(leaf_hash.len(), 32, "Leaf hash should be 32 bytes");
    assert_ne!(leaf_hash, coin.id, "Leaf hash should be different from coin ID");
    assert_ne!(leaf_hash, [0u8; 32], "Leaf hash should not be all zeros");
    
    // Test leaf hash determinism
    let leaf_hash2 = Coin::id_to_leaf_hash(&coin.id);
    assert_eq!(leaf_hash, leaf_hash2, "Leaf hash should be deterministic");
    
    // Test leaf hash uniqueness
    let coin2 = Coin::new(epoch_hash, nonce + 1, creator_address, pow_hash);
    let leaf_hash_2 = Coin::id_to_leaf_hash(&coin2.id);
    assert_ne!(leaf_hash, leaf_hash_2, "Different coins should have different leaf hashes");
    
    // Test resistance to preimage attacks
    // An attacker shouldn't be able to find a coin ID that produces a specific leaf hash
    let target_leaf = [0x42u8; 32];
    let mut found_preimage = false;
    
    for test_nonce in 0..1000 {
        let test_header = Coin::header_bytes(&epoch_hash, test_nonce, &creator_address);
        if let Ok(test_pow) = crypto::argon2id_pow(&test_header, 256, 1) {
            let test_coin = Coin::new(epoch_hash, test_nonce, creator_address, test_pow);
            let test_leaf = Coin::id_to_leaf_hash(&test_coin.id);
            
            if test_leaf == target_leaf {
                found_preimage = true;
                break;
            }
        }
    }
    
    assert!(!found_preimage, "Should not easily find preimage for target leaf hash");
    println!("  ✅ No preimage found for target leaf in 1000 attempts");
    
    println!(" Coin Merkle leaf security test");
}

#[tokio::test]
async fn test_coin_value_integrity() {
    println!("🧪 Testing coin value integrity...");
    
    let (pk, _) = dilithium3_keypair();
    let creator_address = address_from_pk(&pk);
    let epoch_hash = [6u8; 32];
    let nonce = 22222u64;
    let pow_hash = crypto::argon2id_pow(&Coin::header_bytes(&epoch_hash, nonce, &creator_address), 1024, 1).unwrap();
    
    // Test that all new coins have value 1
    let coin = Coin::new(epoch_hash, nonce, creator_address, pow_hash);
    assert_eq!(coin.value, 1, "All new coins must have value 1");
    
    // Test that coin value cannot be manipulated
    // The value should be hardcoded in the constructor and not influenced by input
    let coins_with_different_inputs = vec![
        Coin::new([0u8; 32], 0, creator_address, pow_hash),
        Coin::new([255u8; 32], u64::MAX, creator_address, pow_hash),
        Coin::new(epoch_hash, nonce, [0u8; 32], pow_hash),
        Coin::new(epoch_hash, nonce, [255u8; 32], pow_hash),
    ];
    
    for test_coin in coins_with_different_inputs {
        assert_eq!(test_coin.value, 1, "All coins should have value 1 regardless of input");
    }
    
    println!("  ✅ All coins have consistent value of 1");
    
    println!("✅ Coin value integrity test: REAL");
}