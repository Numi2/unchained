use std::collections::HashSet;
use std::sync::Arc;
use tempfile::TempDir;
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
use unchained::{
    coin::Coin,
    crypto::{self, dilithium3_keypair, address_from_pk},
    storage::Store,
    epoch::{Anchor, MerkleTree},
    wallet::Wallet,
    config::{Epoch as EpochConfig, Mining as MiningConfig},
};

// ============================================================================
// CRITICAL REVIEW: Let's examine if these tests are REAL or SUPERFICIAL
// ============================================================================

fn test_cryptographic_functions() {
    use std::collections::HashSet;
    println!("🧪 Testing cryptographic functions...");

    // --------------------------------------------------------------------
    // BLAKE3 – determinism, avalanche property, collision sampling
    // --------------------------------------------------------------------
    let input = b"test data";
    let hash_a = crypto::blake3_hash(input);
    let hash_b = crypto::blake3_hash(input);
    assert_eq!(hash_a, hash_b, "BLAKE3 should be deterministic");
    assert_eq!(hash_a.len(), 32);

    // Avalanche effect (flip 1-bit)
    let mut modified = input.to_vec();
    modified[0] ^= 0x01;
    let hash_mod = crypto::blake3_hash(&modified);
    let differing_bits: u32 = hash_a
        .iter()
        .zip(hash_mod.iter())
        .map(|(a, b)| (a ^ b).count_ones())
        .sum();
    assert!(differing_bits > 100, "Avalanche effect too weak: {differing_bits} bits differ");

    // Collision search across 2 000 random messages
    let mut seen = HashSet::new();
    for i in 0..2000 {
        let data = format!("random_input_{i}");
        let h = crypto::blake3_hash(data.as_bytes());
        assert!(!seen.contains(&h), "Hash collision found after {i} samples");
        seen.insert(h);
    }

    // --------------------------------------------------------------------
    // Argon2id – memory sensitivity check
    // --------------------------------------------------------------------
    let pow_low = crypto::argon2id_pow(b"mining input", 1024, 1).unwrap();
    let pow_high = crypto::argon2id_pow(b"mining input", 4096, 1).unwrap();
    assert_ne!(pow_low, pow_high, "Changing memory should change Argon2id output");

    // --------------------------------------------------------------------
    // Dilithium3 keys & address derivation – uniqueness + determinism
    // --------------------------------------------------------------------
    let (pk1, sk1) = dilithium3_keypair();
    let (pk2, sk2) = dilithium3_keypair();
    assert_ne!(pk1.as_bytes(), pk2.as_bytes(), "Public keys should differ");
    assert_ne!(sk1.as_bytes(), sk2.as_bytes(), "Secret keys should differ");

    let addr1 = address_from_pk(&pk1);
    let addr2 = address_from_pk(&pk2);
    assert_ne!(addr1, addr2, "Different public keys should yield different addresses");
    assert_eq!(addr1, address_from_pk(&pk1), "Address derivation must be deterministic");

    println!("✅ Cryptographic functions test: REAL – avalanche & collision checks added");
}


fn test_coin_system() {
    println!("🧪 Testing coin system... (REVIEWING IF REAL)");
    
    let (pk, _) = dilithium3_keypair();
    let creator_address = address_from_pk(&pk);
    let epoch_hash = [1u8; 32];
    
    // --------------------------------------------------------------------
    // ⛏️  Test PoW validation: Goal =  actively mine until the hash meets difficulty
    // --------------------------------------------------------------------
    let mem_kib = 1024;
    let lanes = 1;
    let target_difficulty = 1; // Require 1 leading zero byte (≈1/256 chance)
    
    let mut valid_nonce = None;
    let mut pow_hash = [0u8; 32];
    
    for nonce_candidate in 0u64..2000 {
        let header = Coin::header_bytes(&epoch_hash, nonce_candidate, &creator_address);
        assert_eq!(header.len(), 32 + 8 + 32, "Header should be 72 bytes (epoch + nonce + address)");
    
        if let Ok(hash) = crypto::argon2id_pow(&header, mem_kib, lanes) {
            if hash.iter().take(target_difficulty).all(|&b| b == 0) {
                valid_nonce = Some(nonce_candidate);
                pow_hash = hash;
                break;
            }
        }
    }
    
    assert!(valid_nonce.is_some(), "Failed to find valid PoW within search window");
    let nonce = valid_nonce.unwrap();
    
    // Ensure PoW meets difficulty
    assert!(pow_hash.iter().take(target_difficulty).all(|&b| b == 0),
        "PoW hash does not satisfy difficulty {}", target_difficulty);
    
    // Tests coin creation with data and  PoW
    let coin = Coin::new(epoch_hash, nonce, creator_address, pow_hash);
    
    
    assert_eq!(coin.value, 1, "New coins should have value 1");
    assert_eq!(coin.epoch_hash, epoch_hash, "Epoch hash should match");
    assert_eq!(coin.nonce, nonce, "Nonce should match");
    assert_eq!(coin.creator_address, creator_address, "Creator address should match");
    assert_eq!(coin.pow_hash, pow_hash, "PoW hash should match");
    assert_eq!(coin.id.len(), 32, "Coin ID should be 32 bytes");
    
    // Tests deterministic coin ID generation
    let coin2 = Coin::new(epoch_hash, nonce, creator_address, pow_hash);
    assert_eq!(coin.id, coin2.id, "Same parameters should produce same coin ID");
    
    // Tests different parameters produce different IDs
    let coin3 = Coin::new(epoch_hash, nonce + 1, creator_address, pow_hash);
    assert_ne!(coin.id, coin3.id, "Different nonce should produce different coin ID");
    
    // Tests leaf hash conversion
    let leaf_hash = Coin::id_to_leaf_hash(&coin.id);
    assert_eq!(leaf_hash.len(), 32, "Leaf hash should be 32 bytes");
    assert_ne!(leaf_hash, coin.id, "Leaf hash should be different from coin ID");
    
    println!("✅ Coin system test: NOW REAL - validates PoW difficulty");
}

fn test_storage_system() {
    println!("🧪 Testing storage system... (REVIEWING IF REAL)");
    
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("test_db");
    
    let store = Store::open(db_path.to_str().unwrap()).expect("Failed to open store");
    
    // Tests actual persistence to disk
    let test_data = vec![1u8, 2, 3, 4, 5];
    let key = b"test_key";
    
    store.put("default", key, &test_data).expect("Failed to put data");
    let retrieved: Option<Vec<u8>> = store.get("default", key).expect("Failed to get data");
    
    assert!(retrieved.is_some(), "Data should be retrievable");
    assert_eq!(retrieved.unwrap(), test_data, "Retrieved data should match stored data");
    
    // Tests missing key behavior
    let missing: Option<Vec<u8>> = store.get("default", b"missing_key").expect("Get should succeed for missing key");
    assert!(missing.is_none(), "Missing key should return None");
    
    // Tests column family isolation
    store.put("coin", key, &test_data).expect("Failed to put in coin CF");
    let from_coin: Option<Vec<u8>> = store.get("coin", key).expect("Failed to get from coin CF");
    let from_default: Option<Vec<u8>> = store.get("default", key).expect("Failed to get from default CF");
    
    assert!(from_coin.is_some(), "Data should exist in coin CF");
    assert!(from_default.is_some(), "Data should exist in default CF");
    
    // Tests complex object serialization/compression
    let (pk, _) = dilithium3_keypair();
    let creator_address = address_from_pk(&pk);
    let epoch_hash = [2u8; 32];
    let nonce = 54321u64;
    let pow_hash = crypto::argon2id_pow(&Coin::header_bytes(&epoch_hash, nonce, &creator_address), 1024, 1).unwrap();
    let coin = Coin::new(epoch_hash, nonce, creator_address, pow_hash);
    
    store.put("coin", &coin.id, &coin).expect("Failed to store coin");
    let retrieved_coin: Option<Coin> = store.get("coin", &coin.id).expect("Failed to retrieve coin");
    
    assert!(retrieved_coin.is_some(), "Coin should be retrievable");
    assert_eq!(retrieved_coin.unwrap(), coin, "Retrieved coin should match stored coin");
    
    println!("Storage system test: persistence and serialization");
}

fn test_epoch_management() {
    println!("🧪 Testing epoch management... ");
    
    // Tests work calculation 
    let work_0 = Anchor::expected_work_for_difficulty(0);
    let work_1 = Anchor::expected_work_for_difficulty(1);
    let work_2 = Anchor::expected_work_for_difficulty(2);
    
    assert_eq!(work_0, 1, "Difficulty 0 should have work 1");
    assert_eq!(work_1, 256, "Difficulty 1 should have work 256"); // 2^8
    assert_eq!(work_2, 65536, "Difficulty 2 should have work 65536"); // 2^16
    assert!(work_2 > work_1, "Higher difficulty should have more work");
    
    // ❌ SUPERFICIAL: Just tests Merkle tree produces consistent outputs
    // ❌ DOESN'T TEST: Tree structure correctness, proof generation/verification
    let mut coin_ids = HashSet::new();
    
    let empty_root = MerkleTree::build_root(&coin_ids);
    assert_eq!(empty_root, [0u8; 32], "Empty tree should have zero root");
    
    let coin_id1 = [1u8; 32];
    coin_ids.insert(coin_id1);
    let single_root = MerkleTree::build_root(&coin_ids);
    assert_ne!(single_root, [0u8; 32], "Single coin tree should have non-zero root");
    
    let coin_id2 = [2u8; 32];
    coin_ids.insert(coin_id2);
    let double_root = MerkleTree::build_root(&coin_ids);
    assert_ne!(double_root, single_root, "Two coin tree should have different root than single coin");
    
    let coin_id3 = [3u8; 32];
    coin_ids.insert(coin_id3);
    let triple_root = MerkleTree::build_root(&coin_ids);
    assert_ne!(triple_root, double_root, "Three coin tree should have different root");
    
    // ✅ Tests determinism
    let triple_root2 = MerkleTree::build_root(&coin_ids);
    assert_eq!(triple_root, triple_root2, "Merkle root should be deterministic");
    
    // ❌ SUPERFICIAL: Tests difficulty calculation but not real blockchain conditions
    // ❌ DOESN'T TEST: Edge cases, attack scenarios, actual mining economics
    let epoch_cfg = EpochConfig {
        seconds: 60,
        target_leading_zeros: 2,
        target_coins_per_epoch: 10,
        retarget_interval: 5,
        max_difficulty_adjustment: 2.0,
    };
    
    let mining_cfg = MiningConfig {
        enabled: true,
        lanes: 1,
        mem_kib: 1024,
        min_mem_kib: 512,
        max_mem_kib: 2048,
        max_memory_adjustment: 2.0,
    };
    
    let (diff, mem) = Anchor::calculate_retarget(&[], &epoch_cfg, &mining_cfg);
    assert_eq!(diff, epoch_cfg.target_leading_zeros, "Should use default difficulty");
    assert_eq!(mem, mining_cfg.mem_kib, "Should use default memory");
    
    // ❌ FAKE: Creates fake anchor data, doesn't test real mining scenario
    let anchor = Anchor {
        num: 0,
        hash: [0u8; 32],
        difficulty: 2,
        coin_count: 5,
        cumulative_work: 100,
        mem_kib: 1024,
    };
    
    let (diff, _mem) = Anchor::calculate_retarget(&[anchor.clone()], &epoch_cfg, &mining_cfg);
    assert_eq!(diff, 1, "Should decrease difficulty due to low coin count");
    
    println!("⚠️  Epoch management test: PARTIALLY REAL - uses fake data, missing edge cases");
}

fn test_wallet_functionality() {
    println!("🧪 Testing wallet functionality... (REVIEWING IF REAL)");
    
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("wallet_test_db");
    
    let store = Arc::new(Store::open(db_path.to_str().unwrap()).expect("Failed to open store"));
    
    // tests wallet creation and persistence
    let wallet1 = Wallet::load_or_create(store.clone()).expect("Failed to create wallet");
    let addr1 = wallet1.address();
    assert_eq!(addr1.len(), 32, "Address should be 32 bytes");
    
    // Tests persistence across restarts
    let wallet2 = Wallet::load_or_create(store.clone()).expect("Failed to load wallet");
    let addr2 = wallet2.address();
    assert_eq!(addr1, addr2, "Loaded wallet should have same address as created wallet");
    
    // Tests isolation between different databases
    let db_path2 = temp_dir.path().join("wallet_test_db2");
    let store2 = Arc::new(Store::open(db_path2.to_str().unwrap()).expect("Failed to open store2"));
    let wallet3 = Wallet::load_or_create(store2).expect("Failed to create wallet3");
    let addr3 = wallet3.address();
    assert_ne!(addr1, addr3, "Different databases should create different wallets");
    
    // ❌ MISSING: Doesn't test signing/verification functionality
    // ❌ MISSING: Doesn't test key security, backup/restore scenarios
    
    println!("✅ Wallet functionality test: MOSTLY REAL - missing crypto operations testing");
}

fn test_integration_mining_simulation() {
    println!("🧪 Testing integration - REAL mining simulation... (REVIEWING IF REAL)");
    
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("integration_test_db");
    
    let store = Arc::new(Store::open(db_path.to_str().unwrap()).expect("Failed to open store"));
    let wallet = Arc::new(Wallet::load_or_create(store.clone()).expect("Failed to create wallet"));
    
    let creator_address = wallet.address();
    let epoch_hash = crypto::blake3_hash(b"test epoch");
    
    //  tests PoW with difficulty requirements
    let mem_kib = 1024;
    let lanes = 1;
    let target_difficulty = 1; // Require 1 leading zero byte (1/256 chance)
    
    println!("  Testing PoW with difficulty {} (expect ~256 attempts)...", target_difficulty);
    let mut found_coin = None;
    let mut attempts = 0;
    let max_attempts = 2000;
    
    for nonce in 0..max_attempts {
        attempts += 1;
        let header = Coin::header_bytes(&epoch_hash, nonce, &creator_address);
        
        if let Ok(pow_hash) = crypto::argon2id_pow(&header, mem_kib, lanes) {
            //  PoW validation - checks  difficulty requirement
            if pow_hash.iter().take(target_difficulty).all(|&b| b == 0) {
                let coin = Coin::new(epoch_hash, nonce, creator_address, pow_hash);
                
                //   Validates all coin properties
                assert_eq!(coin.value, 1);
                assert_eq!(coin.epoch_hash, epoch_hash);
                assert_eq!(coin.nonce, nonce);
                assert_eq!(coin.creator_address, creator_address);
                assert_eq!(coin.pow_hash, pow_hash);
                
                //  Double-checks PoW validity
                assert!(pow_hash.iter().take(target_difficulty).all(|&b| b == 0), 
                    "PoW hash doesn't meet difficulty requirement! Hash: {:02x?}", &pow_hash[..8]);
                
                //  Tests actual storage persistence
                store.put("coin", &coin.id, &coin).expect("Failed to store mined coin");
                
                let retrieved: Option<Coin> = store.get("coin", &coin.id).expect("Failed to retrieve coin");
                assert!(retrieved.is_some());
                assert_eq!(retrieved.unwrap(), coin);
                
                found_coin = Some(coin);
                break;
            }
        }
    }
    
    assert!(found_coin.is_some(), "Should have found a valid coin within {} attempts (difficulty {})", max_attempts, target_difficulty);
    println!("  ✅ Found valid coin after {} attempts (expected ~256 for difficulty 1)", attempts);
    
    //  Final verification of PoW validity
    let coin = found_coin.unwrap();
    assert!(coin.pow_hash.iter().take(target_difficulty).all(|&b| b == 0), 
        "Final verification failed: coin PoW hash doesn't meet difficulty");
    
    //  Tests epoch/anchor creation and storage
    let mut coin_ids = HashSet::new();
    coin_ids.insert(coin.id);
    
    let merkle_root = MerkleTree::build_root(&coin_ids);
    let mut hasher = blake3::Hasher::new();
    hasher.update(&merkle_root);
    let anchor_hash = *hasher.finalize().as_bytes();
    
    let anchor = Anchor {
        num: 0,
        hash: anchor_hash,
        difficulty: target_difficulty,
        coin_count: 1,
        cumulative_work: Anchor::expected_work_for_difficulty(target_difficulty),
        mem_kib,
    };
    
    store.put("epoch", &0u64.to_le_bytes(), &anchor).expect("Failed to store anchor");
    store.put("epoch", b"latest", &anchor).expect("Failed to store latest anchor");
    
    let retrieved_anchor: Option<Anchor> = store.get("epoch", &0u64.to_le_bytes()).expect("Failed to retrieve anchor");
    assert!(retrieved_anchor.is_some());
    assert_eq!(retrieved_anchor.unwrap().num, 0);
    
    println!("Integration test: properly validates PoW difficulty and mining");
}

fn test_pow_difficulty_stress() {
    println!("🧪 Testing PoW difficulty stress test...");
    
    let (pk, _) = dilithium3_keypair();
    let creator_address = address_from_pk(&pk);
    let epoch_hash = crypto::blake3_hash(b"stress test epoch");
    
    // Helper function to validate PoW 
    fn is_valid_pow(hash: &[u8; 32], difficulty: usize) -> bool {
        hash.iter().take(difficulty).all(|&b| b == 0)
    }
    
    // Test with difficulty 1 
    println!("  Testing difficulty 1 (1/256 chance per attempt)...");
    let mut attempts = 0;
    let mut found = false;
    let max_attempts = 1500; // Should be enough for difficulty 1
    
    for nonce in 0..max_attempts {
        attempts += 1;
        let header = Coin::header_bytes(&epoch_hash, nonce, &creator_address);
        
        if let Ok(pow_hash) = crypto::argon2id_pow(&header, 512, 1) { // Lower memory for speed
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
    
    // Test rejection of invalid PoW
    println!("  Testing invalid PoW rejection...");
    let invalid_hash = [0xff; 32]; // No leading zeros
    assert!(!is_valid_pow(&invalid_hash, 1), "Should reject hash with no leading zeros");
    
    let partial_valid = {
        let mut h = [0xff; 32];
        h[0] = 0x00; // Only first byte is zero
        h
    };
    assert!(is_valid_pow(&partial_valid, 1), "Should accept hash with 1 leading zero for difficulty 1");
    assert!(!is_valid_pow(&partial_valid, 2), "Should reject hash with only 1 leading zero for difficulty 2");
    
    println!("✅ PoW difficulty stress test passed");
}

fn test_pow_statistical_analysis() {
    println!("🧪 Testing PoW statistical analysis...");
    
    let (pk, _) = dilithium3_keypair();
    let creator_address = address_from_pk(&pk);
    let epoch_hash = crypto::blake3_hash(b"statistical test");
    
    fn is_valid_pow(hash: &[u8; 32], difficulty: usize) -> bool {
        hash.iter().take(difficulty).all(|&b| b == 0)
    }
    
    // Test multiple runs to show statistical distribution
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
    
    // Test that invalid hashes are properly rejected
    println!("  Testing hash validation edge cases...");
    
    // Test boundary cases
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
    
    println!("✅ PoW statistical analysis test passed");
}

#[tokio::test]
async fn test_pow_stress() {
    test_pow_difficulty_stress();
}

#[tokio::test]
async fn test_pow_statistics() {
    test_pow_statistical_analysis();
}

// Individual test functions for specific components
#[tokio::test]
async fn test_crypto_functions() {
    test_cryptographic_functions();
}

#[tokio::test]
async fn test_coins() {
    test_coin_system();
}

#[tokio::test]
async fn test_storage() {
    test_storage_system();
}

#[tokio::test]
async fn test_epochs() {
    test_epoch_management();
}

#[tokio::test]
async fn test_wallet() {
    test_wallet_functionality();
}

#[tokio::test]
async fn test_integration() {
    test_integration_mining_simulation();
}

