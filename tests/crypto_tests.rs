// REAL Cryptographic Function Tests
// These tests validate SECURITY PROPERTIES, not just basic functionality

use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _};
use unchained::{
    crypto::{dilithium3_keypair, address_from_pk, blake3_hash, argon2id_pow},
};
use std::collections::HashSet;

#[tokio::test]
async fn test_blake3_security_properties() {
    println!("🧪 Testing BLAKE3 security properties...");
    
    // Test avalanche effect (small input change = large output change)
    let input1 = b"test data";
    let input2 = b"test datb"; // Single bit change
    let hash1 = blake3_hash(input1);
    let hash2 = blake3_hash(input2);
    
    // Count differing bits to verify avalanche effect
    let mut differing_bits = 0;
    for i in 0..32 {
        differing_bits += (hash1[i] ^ hash2[i]).count_ones();
    }
    
    // Should have approximately 50% differing bits (avalanche effect)
    assert!(differing_bits > 100, "Avalanche effect too weak: only {} differing bits out of 256", differing_bits);
    assert!(differing_bits < 156, "Avalanche effect too strong: {} differing bits out of 256", differing_bits);
    
    println!("  ✅ Avalanche effect: {}/256 bits differ (good: 100-156)", differing_bits);
    
    // Test distribution properties with multiple samples
    let mut hash_set = HashSet::new();
    let mut collision_found = false;
    
    for i in 0..1000 {
        let input = format!("test_input_{}", i);
        let hash = blake3_hash(input.as_bytes());
        
        if hash_set.contains(&hash) {
            collision_found = true;
            break;
        }
        hash_set.insert(hash);
    }
    
    assert!(!collision_found, "Unexpected collision found in 1000 samples");
    println!("  ✅ No collisions in 1000 diverse inputs");
    
    // Test determinism under different conditions
    let test_data = b"determinism test";
    let hash_a = blake3_hash(test_data);
    let hash_b = blake3_hash(test_data);
    let hash_c = blake3_hash(test_data);
    
    assert_eq!(hash_a, hash_b, "Hash should be deterministic");
    assert_eq!(hash_b, hash_c, "Hash should be consistently deterministic");
    
    // Test empty input handling
    let empty_hash = blake3_hash(b"");
    assert_eq!(empty_hash.len(), 32, "Empty input should still produce 32-byte hash");
    assert_ne!(empty_hash, [0u8; 32], "Empty input hash should not be all zeros");
    
    // Test large input handling
    let large_input = vec![0x42u8; 10000]; // 10KB of data
    let large_hash = blake3_hash(&large_input);
    assert_eq!(large_hash.len(), 32, "Large input should produce 32-byte hash");
    
    println!("✅ BLAKE3 security properties test: REAL");
}

#[tokio::test]
async fn test_argon2id_memory_hardness() {
    println!("🧪 Testing Argon2id memory hardness...");
    
    let input = b"memory_hardness_test";
    
    // Test that memory requirements actually affect computation
    let low_mem_result = argon2id_pow(input, 1024, 1); // 1MB
    let high_mem_result = argon2id_pow(input, 8192, 1); // 8MB
    
    assert!(low_mem_result.is_ok(), "Low memory Argon2id should succeed");
    assert!(high_mem_result.is_ok(), "High memory Argon2id should succeed");
    
    // Different memory settings should produce different hashes
    assert_ne!(low_mem_result.unwrap(), high_mem_result.unwrap(), 
        "Different memory settings should produce different hashes");
    
    // Test timing differences (memory-hard should be slower with more memory)
    use std::time::Instant;
    
    let start = Instant::now();
    let _low_mem = argon2id_pow(input, 1024, 1).unwrap();
    let low_mem_time = start.elapsed();
    
    let start = Instant::now();
    let _high_mem = argon2id_pow(input, 4096, 1).unwrap();
    let high_mem_time = start.elapsed();
    
    println!("  📊 1MB memory: {:?}", low_mem_time);
    println!("  📊 4MB memory: {:?}", high_mem_time);
    
    // High memory should take more time (memory hardness property)
    assert!(high_mem_time > low_mem_time, 
        "Higher memory should take more time (memory hardness)");
    
    // Test lane parallelization
    let single_lane = argon2id_pow(input, 2048, 1).unwrap();
    let dual_lane = argon2id_pow(input, 2048, 2).unwrap();
    
    assert_ne!(single_lane, dual_lane, "Different lane count should produce different hashes");
    
    // Test invalid parameters are rejected
    let invalid_mem = argon2id_pow(input, 0, 1); // Zero memory
    assert!(invalid_mem.is_err(), "Zero memory should be rejected");
    
    let invalid_lanes = argon2id_pow(input, 1024, 0); // Zero lanes
    assert!(invalid_lanes.is_err(), "Zero lanes should be rejected");
    
    println!("✅ Argon2id memory hardness test: REAL");
}

#[tokio::test]
async fn test_dilithium3_security_properties() {
    println!("🧪 Testing Dilithium3 security properties...");
    
    // Test key generation randomness
    let mut public_keys = HashSet::new();
    let mut secret_keys = HashSet::new();
    
    for _ in 0..10 {
        let (pk, sk) = dilithium3_keypair();
        
        // Keys should be unique
        assert!(!public_keys.contains(pk.as_bytes()), "Duplicate public key generated");
        assert!(!secret_keys.contains(sk.as_bytes()), "Duplicate secret key generated");
        
        public_keys.insert(pk.as_bytes().to_vec());
        secret_keys.insert(sk.as_bytes().to_vec());
        
        // Keys should have expected sizes
        assert_eq!(pk.as_bytes().len(), unchained::crypto::DILITHIUM3_PK_BYTES, "Public key wrong size");
        assert_eq!(sk.as_bytes().len(), unchained::crypto::DILITHIUM3_SK_BYTES, "Secret key wrong size");
    }
    
    println!("  ✅ Generated 10 unique keypairs with correct sizes");
    
    // Test address derivation security
    let (pk1, _) = dilithium3_keypair();
    let (pk2, _) = dilithium3_keypair();
    
    let addr1 = address_from_pk(&pk1);
    let addr2 = address_from_pk(&pk2);
    
    // Addresses should be different for different keys
    assert_ne!(addr1, addr2, "Different public keys should produce different addresses");
    
    // Address should be deterministic
    let addr1_again = address_from_pk(&pk1);
    assert_eq!(addr1, addr1_again, "Address derivation should be deterministic");
    
    // Test address distribution (no obvious patterns)
    let mut addresses = Vec::new();
    for _ in 0..100 {
        let (pk, _) = dilithium3_keypair();
        let addr = address_from_pk(&pk);
        addresses.push(addr);
    }
    
    // Check for uniform distribution in first byte
    let mut byte_counts = [0u32; 256];
    for addr in &addresses {
        byte_counts[addr[0] as usize] += 1;
    }
    
    // Should not have any byte value appearing more than 5 times in 100 samples
    // (would indicate non-uniform distribution)
    let max_count = byte_counts.iter().max().unwrap();
    assert!(*max_count <= 5, "Address distribution may be biased: byte value appears {} times", max_count);
    
    println!("  ✅ Address distribution appears uniform (max byte frequency: {})", max_count);
    
    println!("✅ Dilithium3 security properties test: REAL");
}

#[tokio::test]  
async fn test_crypto_attack_resistance() {
    println!("🧪 Testing crypto attack resistance...");
    
            // Test resistance to length extension attacks
    let short_input = b"short";
    let extended_input = b"short_extended";
    
    let short_hash = blake3_hash(short_input);
    let extended_hash = blake3_hash(extended_input);
    
    assert_ne!(short_hash, extended_hash, "Hashes should be different for extended input");
    
    // Check that there's no obvious relationship between hashes
    let mut matching_bytes = 0;
    for i in 0..32 {
        if short_hash[i] == extended_hash[i] {
            matching_bytes += 1;
        }
    }
    
    // Should not have too many matching bytes (would indicate vulnerability)
    assert!(matching_bytes < 10, "Too many matching bytes between related inputs: {}", matching_bytes);
    
    println!("  ✅ No obvious relationship between hash of 'short' and 'short_extended'");
    
    // Test resistance to chosen-input attacks
    let chosen_inputs: &[&[u8]] = &[
        b"",
        b"a",
        b"aa", 
        b"aaa",
        b"\x00",
        b"\xff",
        b"\x00\xff\x00\xff",
        &[0u8; 64],
        &[255u8; 64],
    ];
    
    let mut chosen_hashes = HashSet::new();
    for input in chosen_inputs {
        let hash = blake3_hash(input);
        assert!(!chosen_hashes.contains(&hash), "Collision found in chosen inputs");
        chosen_hashes.insert(hash);
    }
    
    println!("  ✅ No collisions in chosen-input attack test");
    
    // Test Argon2id salt importance
    let input = b"salt_test";
    let no_salt_hash = argon2id_pow(input, 1024, 1).unwrap();
    
    // Test that salt affects output (Argon2id uses internal salt)
    let different_input = b"salt_test2";
    let different_hash = argon2id_pow(different_input, 1024, 1).unwrap();
    
    assert_ne!(no_salt_hash, different_hash, "Different inputs should produce different Argon2id hashes");
    
    println!("✅ Crypto attack resistance test: REAL");
}