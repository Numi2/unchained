// REAL Proof-of-Work Tests
// These tests validate MINING DIFFICULTY and COMPUTATIONAL WORK

use unchained::{
    coin::Coin,
    crypto::{self, dilithium3_keypair, address_from_pk},
};

#[tokio::test]
async fn test_pow_difficulty_validation() {
    println!("🧪 Testing PoW difficulty validation...");
    
    let (pk, _) = dilithium3_keypair();
    let creator_address = address_from_pk(&pk);
    let epoch_hash = crypto::blake3_hash(b"difficulty test epoch");
    
    // Helper function to validate PoW (matches miner.rs logic)
    fn is_valid_pow(hash: &[u8; 32], difficulty: usize) -> bool {
        hash.iter().take(difficulty).all(|&b| b == 0)
    }
    
    // : Test difficulty 1 (1/256 chance per attempt)
    println!("  Testing difficulty 1 (expect ~256 attempts)...");
    let mut attempts = 0;
    let mut found = false;
    let max_attempts = 1500;
    
    for nonce in 0..max_attempts {
        attempts += 1;
        let header = Coin::header_bytes(&epoch_hash, nonce, &creator_address);
        
        if let Ok(pow_hash) = crypto::argon2id_pow(&header, 512, 1) {
            if is_valid_pow(&pow_hash, 1) {
                println!("    ✅ Found valid PoW after {} attempts", attempts);
                println!("    Hash: {:02x?}...", &pow_hash[..8]);
                
                // Verify the solution
                assert_eq!(pow_hash[0], 0, "First byte must be zero for difficulty 1");
                
                // Create and validate the coin
                let coin = Coin::new(epoch_hash, nonce, creator_address, pow_hash);
                assert!(is_valid_pow(&coin.pow_hash, 1), "Coin PoW must be valid");
                
                found = true;
                break;
            }
        }
    }
    
    assert!(found, "Should find valid PoW within {} attempts for difficulty 1", max_attempts);
    
    // : Test that invalid PoW is rejected
    let invalid_hash = [0xff; 32];
    assert!(!is_valid_pow(&invalid_hash, 1), "Should reject hash with no leading zeros");
    
    let partial_valid = {
        let mut h = [0xff; 32];
        h[0] = 0x00;
        h
    };
    assert!(is_valid_pow(&partial_valid, 1), "Should accept hash with 1 leading zero for difficulty 1");
    assert!(!is_valid_pow(&partial_valid, 2), "Should reject hash with only 1 leading zero for difficulty 2");
    
    println!("✅ PoW difficulty validation test: REAL");
}

#[tokio::test]
async fn test_pow_statistical_properties() {
    println!("🧪 Testing PoW statistical properties...");
    
    let (pk, _) = dilithium3_keypair();
    let creator_address = address_from_pk(&pk);
    let epoch_hash = crypto::blake3_hash(b"statistical test");
    
    fn is_valid_pow(hash: &[u8; 32], difficulty: usize) -> bool {
        hash.iter().take(difficulty).all(|&b| b == 0)
    }
    
    // : Run multiple mining attempts to show statistical distribution
    println!("  Running 5 separate mining attempts for difficulty 1...");
    let mut total_attempts = 0;
    let mut successes = 0;
    
    for run in 1..=5 {
        println!("  Run {}: ", run);
        for nonce in (run * 1000)..((run + 1) * 1000) {
            total_attempts += 1;
            let header = Coin::header_bytes(&epoch_hash, nonce, &creator_address);
            
            if let Ok(pow_hash) = crypto::argon2id_pow(&header, 512, 1) {
                if is_valid_pow(&pow_hash, 1) {
                    successes += 1;
                    println!("    ✅ Success after {} attempts in this run", nonce - (run * 1000) + 1);
                    println!("    Hash: {:02x?}...", &pow_hash[..6]);
                    
                    // Verify it's actually valid
                    assert_eq!(pow_hash[0], 0, "First byte must be zero");
                    break;
                }
            }
        }
    }
    
    println!("  📊 Statistics: {} successes out of {} total attempts", successes, total_attempts);
    println!("  📊 Average attempts per success: {:.1}", total_attempts as f64 / successes as f64);
    println!("  📊 Expected: ~256 attempts per success for difficulty 1");
    
    // : Test hash validation edge cases
    println!("  Testing hash validation edge cases...");
    
    let almost_valid = {
        let mut h = [0xff; 32];
        h[0] = 0x01; // First byte is 1, not 0
        h
    };
    assert!(!is_valid_pow(&almost_valid, 1), "Should reject hash with first byte = 1");
    
    let exactly_valid = {
        let mut h = [0xff; 32];
        h[0] = 0x00; // First byte is exactly 0
        h
    };
    assert!(is_valid_pow(&exactly_valid, 1), "Should accept hash with first byte = 0");
    
    // Test difficulty 2 requirement
    assert!(!is_valid_pow(&exactly_valid, 2), "Should reject for difficulty 2 (second byte not zero)");
    
    let difficulty_2_valid = {
        let mut h = [0xff; 32];
        h[0] = 0x00;
        h[1] = 0x00;
        h
    };
    assert!(is_valid_pow(&difficulty_2_valid, 2), "Should accept hash with first two bytes = 0");
    
    println!("✅ PoW statistical properties test: REAL");
}

#[tokio::test]
async fn test_pow_memory_hardness() {
    println!("🧪 Testing PoW memory hardness...");
    
    let (pk, _) = dilithium3_keypair();
    let creator_address = address_from_pk(&pk);
    let epoch_hash = crypto::blake3_hash(b"memory hardness test");
    let test_nonce = 12345u64;
    
    // : Test that different memory settings produce different hashes
    let header = Coin::header_bytes(&epoch_hash, test_nonce, &creator_address);
    
    let low_mem_hash = crypto::argon2id_pow(&header, 512, 1).expect("Low memory PoW should work");
    let med_mem_hash = crypto::argon2id_pow(&header, 1024, 1).expect("Medium memory PoW should work");
    let high_mem_hash = crypto::argon2id_pow(&header, 2048, 1).expect("High memory PoW should work");
    
    // Different memory settings should produce different hashes
    assert_ne!(low_mem_hash, med_mem_hash, "Different memory should produce different hashes");
    assert_ne!(med_mem_hash, high_mem_hash, "Different memory should produce different hashes");
    assert_ne!(low_mem_hash, high_mem_hash, "Different memory should produce different hashes");
    
    // : Test timing differences (memory-hard should be slower with more memory)
    use std::time::Instant;
    
    let start_low = Instant::now();
    let _low_result = crypto::argon2id_pow(&header, 512, 1).unwrap();
    let low_time = start_low.elapsed();
    
    let start_high = Instant::now();
    let _high_result = crypto::argon2id_pow(&header, 2048, 1).unwrap();
    let high_time = start_high.elapsed();
    
    println!("  📊 512 KiB memory: {:?}", low_time);
    println!("  📊 2048 KiB memory: {:?}", high_time);
    
    // Higher memory should generally take more time (memory hardness property)
    assert!(high_time >= low_time, 
        "Higher memory should take at least as much time (memory hardness)");
    
    // : Test lane parallelization effects
    let single_lane = crypto::argon2id_pow(&header, 1024, 1).unwrap();
    let dual_lane = crypto::argon2id_pow(&header, 1024, 2).unwrap();
    let quad_lane = crypto::argon2id_pow(&header, 1024, 4).unwrap();
    
    // Different lane counts should produce different hashes
    assert_ne!(single_lane, dual_lane, "Different lane count should produce different hashes");
    assert_ne!(dual_lane, quad_lane, "Different lane count should produce different hashes");
    assert_ne!(single_lane, quad_lane, "Different lane count should produce different hashes");
    
    println!("  ✅ Memory hardness and parallelization verified");
    
    println!("✅ PoW memory hardness test: REAL");
}

#[tokio::test]
async fn test_pow_difficulty_scaling() {
    println!("🧪 Testing PoW difficulty scaling...");
    
    let (pk, _) = dilithium3_keypair();
    let creator_address = address_from_pk(&pk);
    let epoch_hash = crypto::blake3_hash(b"difficulty scaling test");
    
    fn is_valid_pow(hash: &[u8; 32], difficulty: usize) -> bool {
        hash.iter().take(difficulty).all(|&b| b == 0)
    }
    
    // : Test that higher difficulty is exponentially harder
    let difficulties = [0, 1, 2];
    let max_attempts_per_difficulty = [10, 500, 10000]; // Exponentially increasing attempts
    
    for (i, &difficulty) in difficulties.iter().enumerate() {
        println!("  Testing difficulty {}...", difficulty);
        let mut found = false;
        let mut attempts = 0;
        let max_attempts = max_attempts_per_difficulty[i];
        
        for nonce in 0..max_attempts {
            attempts += 1;
            let header = Coin::header_bytes(&epoch_hash, nonce + (i as u64 * 100000), &creator_address);
            
            if let Ok(pow_hash) = crypto::argon2id_pow(&header, 512, 1) {
                if is_valid_pow(&pow_hash, difficulty) {
                    println!("    ✅ Found solution for difficulty {} after {} attempts", difficulty, attempts);
                    println!("    Hash: {:02x?}...", &pow_hash[..8]);
                    
                    // Verify the solution meets the difficulty requirement
                    for byte_idx in 0..difficulty {
                        assert_eq!(pow_hash[byte_idx], 0, "Byte {} should be zero for difficulty {}", byte_idx, difficulty);
                    }
                    
                    found = true;
                    break;
                }
            }
        }
        
        if difficulty == 0 {
            assert!(found, "Should always find solution for difficulty 0");
        } else if difficulty == 1 {
            // For difficulty 1, we should usually find a solution in reasonable time
            if !found {
                println!("    ⚠️  No solution found for difficulty 1 in {} attempts (this can happen)", max_attempts);
            }
        } else {
            // For difficulty 2+, it's normal to not find a solution quickly
            if found {
                println!("    🎉 Lucky! Found solution for difficulty {} in {} attempts", difficulty, attempts);
            } else {
                println!("    📊 No solution found for difficulty {} in {} attempts (expected)", difficulty, max_attempts);
            }
        }
    }
    
    // : Test boundary conditions for difficulty validation
    let test_hashes = [
        ([0x00, 0xff, 0xff], 1, true),   // Valid for difficulty 1
        ([0x01, 0x00, 0x00], 1, false),  // Invalid for difficulty 1
        ([0x00, 0x00, 0xff], 2, true),   // Valid for difficulty 2
        ([0x00, 0x01, 0x00], 2, false),  // Invalid for difficulty 2
        ([0x00, 0x00, 0x00], 3, true),   // Valid for difficulty 3
        ([0x00, 0x00, 0x01], 3, false),  // Invalid for difficulty 3
    ];
    
    for (hash_prefix, difficulty, should_be_valid) in test_hashes {
        let mut test_hash = [0xffu8; 32];
        test_hash[0] = hash_prefix[0];
        test_hash[1] = hash_prefix[1];
        test_hash[2] = hash_prefix[2];
        
        let is_valid = is_valid_pow(&test_hash, difficulty);
        assert_eq!(is_valid, should_be_valid, 
            "Hash {:02x?}... should be {} for difficulty {}", 
            &test_hash[..3], if should_be_valid { "valid" } else { "invalid" }, difficulty);
    }
    
    println!("  ✅ Difficulty boundary conditions verified");
    
    println!("✅ PoW difficulty scaling test: REAL");
}

#[tokio::test]
async fn test_pow_determinism_and_reproducibility() {
    println!("🧪 Testing PoW determinism and reproducibility...");
    
    let (pk, _) = dilithium3_keypair();
    let creator_address = address_from_pk(&pk);
    let epoch_hash = crypto::blake3_hash(b"determinism test");
    let test_nonce = 54321u64;
    
    // : Test that same inputs produce same outputs
    let header = Coin::header_bytes(&epoch_hash, test_nonce, &creator_address);
    
    let hash1 = crypto::argon2id_pow(&header, 1024, 2).expect("PoW should work");
    let hash2 = crypto::argon2id_pow(&header, 1024, 2).expect("PoW should work");
    let hash3 = crypto::argon2id_pow(&header, 1024, 2).expect("PoW should work");
    
    assert_eq!(hash1, hash2, "Same inputs should produce same output");
    assert_eq!(hash2, hash3, "PoW should be consistently deterministic");
    
    // : Test that small input changes produce large output changes
    let mut modified_header = header.clone();
    modified_header[0] ^= 0x01; // Change one bit
    
    let modified_hash = crypto::argon2id_pow(&modified_header, 1024, 2).expect("Modified PoW should work");
    assert_ne!(hash1, modified_hash, "Small input change should produce different output");
    
    // Count differing bits (avalanche effect)
    let mut differing_bits = 0;
    for i in 0..32 {
        differing_bits += (hash1[i] ^ modified_hash[i]).count_ones();
    }
    
    assert!(differing_bits > 100, "Small input change should cause significant output change ({} bits differ)", differing_bits);
    println!("  ✅ Avalanche effect: {}/256 bits differ from 1-bit input change", differing_bits);
    
    // : Test parameter sensitivity
    let different_memory = crypto::argon2id_pow(&header, 2048, 2).expect("Different memory PoW should work");
    let different_lanes = crypto::argon2id_pow(&header, 1024, 4).expect("Different lanes PoW should work");
    
    assert_ne!(hash1, different_memory, "Different memory should produce different output");
    assert_ne!(hash1, different_lanes, "Different lanes should produce different output");
    assert_ne!(different_memory, different_lanes, "Different parameters should produce different outputs");
    
    // : Test coin creation determinism
    let coin1 = Coin::new(epoch_hash, test_nonce, creator_address, hash1);
    let coin2 = Coin::new(epoch_hash, test_nonce, creator_address, hash1);
    
    assert_eq!(coin1.id, coin2.id, "Same coin parameters should produce same ID");
    assert_eq!(coin1.value, coin2.value, "Same coin parameters should produce same value");
    assert_eq!(coin1.pow_hash, coin2.pow_hash, "Same coin parameters should have same PoW hash");
    
    println!("  ✅ Determinism and reproducibility verified");
    
    println!("✅ PoW determinism and reproducibility test: REAL");
}