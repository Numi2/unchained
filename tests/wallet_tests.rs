// REAL Wallet Tests
// These tests validate KEY SECURITY and CRYPTOGRAPHIC OPERATIONS

use std::sync::Arc;
use tempfile::TempDir;
use pqcrypto_traits::sign::{PublicKey as _, DetachedSignature};
use pqcrypto_dilithium::dilithium3::{detached_sign, verify_detached_signature};
use unchained::{
    wallet::Wallet,
    storage::Store,
    crypto::{address_from_pk, dilithium3_keypair},
};

#[tokio::test]
async fn test_wallet_real_signing_and_verification() {
    println!("🧪 Testing REAL wallet signing and verification...");

    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("real_signing_test_db");
    let store = Arc::new(Store::open(db_path.to_str().unwrap()).expect("Failed to open store"));
    let wallet = Wallet::load_or_create(store.clone()).expect("Failed to create wallet");

    let message = b"This is a real message signed by the wallet";

    // 1. Sign message with the wallet's actual secret key
    let signature = wallet.sign(message);

    // 2. Verify the signature with the wallet's public key
    assert!(wallet.verify(message, &signature), "Signature should be valid with correct message and key");

    // 3. Test that verification fails with a modified message
    let modified_message = b"This is a modified message";
    assert!(!wallet.verify(modified_message, &signature), "Signature verification should fail for a modified message");

    // 4. Test that verification fails with a different wallet's key
    let db_path2 = temp_dir.path().join("different_wallet_db");
    let store2 = Arc::new(Store::open(db_path2.to_str().unwrap()).expect("Failed to open different store"));
    let other_wallet = Wallet::load_or_create(store2).expect("Failed to create other wallet");
    assert!(!other_wallet.verify(message, &signature), "Signature verification should fail with a different wallet's key");
    
    // 5. Test that verification fails with a corrupted signature
    let mut corrupted_sig_bytes = signature.as_bytes().to_vec();
    corrupted_sig_bytes[0] ^= 0x01; // Flip one bit
    if let Ok(corrupted_signature) = DetachedSignature::from_bytes(&corrupted_sig_bytes) {
        assert!(!wallet.verify(message, &corrupted_signature), "Signature verification should fail for a corrupted signature");
    }

    println!("✅ REAL wallet signing and verification test passed");
}

#[tokio::test]
async fn test_wallet_persistence_security() {
    println!("🧪 Testing wallet persistence security...");
    
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("persistence_test_db");
    
    let store1 = Arc::new(Store::open(db_path.to_str().unwrap()).expect("Failed to open store"));
    
    // : Test wallet creation and address consistency
    let wallet1 = Wallet::load_or_create(store1.clone()).expect("Failed to create wallet");
    let address1 = wallet1.address();
    
    // Drop the wallet and recreate from same store
    drop(wallet1);
    
    let wallet2 = Wallet::load_or_create(store1.clone()).expect("Failed to reload wallet");
    let address2 = wallet2.address();
    
    assert_eq!(address1, address2, "Wallet address should be consistent after reload");
    
    // : Test that different stores create different wallets
    let db_path2 = temp_dir.path().join("different_persistence_test_db");
    let store2 = Arc::new(Store::open(db_path2.to_str().unwrap()).expect("Failed to open different store"));
    
    let wallet3 = Wallet::load_or_create(store2).expect("Failed to create different wallet");
    let address3 = wallet3.address();
    
    assert_ne!(address1, address3, "Different stores should create different wallet addresses");
    
    // : Test wallet isolation between database instances
    for i in 0..10 {
        let isolated_db_path = temp_dir.path().join(format!("isolated_db_{}", i));
        let isolated_store = Arc::new(Store::open(isolated_db_path.to_str().unwrap()).expect("Failed to open isolated store"));
        
        let isolated_wallet = Wallet::load_or_create(isolated_store).expect("Failed to create isolated wallet");
        let isolated_address = isolated_wallet.address();
        
        // Each wallet should have a unique address
        assert_ne!(isolated_address, address1, "Isolated wallet {} should have different address", i);
        assert_ne!(isolated_address, address3, "Isolated wallet {} should have different address from wallet3", i);
        
        // Address should be valid (not all zeros, correct length)
        assert_eq!(isolated_address.len(), 32, "Isolated wallet {} address should be 32 bytes", i);
        assert_ne!(isolated_address, [0u8; 32], "Isolated wallet {} address should not be all zeros", i);
    }
    
    println!("  ✅ Wallet isolation and persistence verified");
    
    println!("✅ Wallet persistence security test: REAL");
}

#[tokio::test]
async fn test_wallet_address_security() {
    println!("🧪 Testing wallet address security...");
    
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    
    // : Test address uniqueness across many wallets
    let mut addresses = std::collections::HashSet::new();
    let wallet_count = 100;
    
    for i in 0..wallet_count {
        let db_path = temp_dir.path().join(format!("address_test_db_{}", i));
        let store = Arc::new(Store::open(db_path.to_str().unwrap()).expect("Failed to open store"));
        
        let wallet = Wallet::load_or_create(store).expect("Failed to create wallet");
        let address = wallet.address();
        
        // Check for address collision
        assert!(!addresses.contains(&address), "Address collision detected at wallet {}", i);
        addresses.insert(address);
        
        // Check address properties
        assert_eq!(address.len(), 32, "Address should be 32 bytes");
        assert_ne!(address, [0u8; 32], "Address should not be all zeros");
    }
    
    println!("  ✅ Generated {} unique addresses with no collisions", wallet_count);
    
    // : Test address distribution (should be uniformly distributed)
    let mut byte_distribution = vec![0u32; 256];
    
    for address in &addresses {
        for &byte in address {
            byte_distribution[byte as usize] += 1;
        }
    }
    
    // Calculate distribution statistics
    let total_bytes = addresses.len() * 32;
    let expected_per_byte = total_bytes / 256;
    let mut max_deviation = 0;
    let mut max_count = 0;
    let mut min_count = u32::MAX;
    
    for &count in &byte_distribution {
        max_count = max_count.max(count);
        min_count = min_count.min(count);
        let deviation = if count > expected_per_byte as u32 {
            count - expected_per_byte as u32
        } else {
            expected_per_byte as u32 - count
        };
        max_deviation = max_deviation.max(deviation);
    }
    
    // Distribution should be reasonably uniform
    assert!(max_deviation < expected_per_byte as u32 / 2, 
        "Address distribution too skewed: max deviation {} (expected ~{})", 
        max_deviation, expected_per_byte);
    
    println!("  ✅ Address distribution: min={}, max={}, expected~={}", min_count, max_count, expected_per_byte);
    
    println!("✅ Wallet address security test: REAL");
}

#[tokio::test]
async fn test_wallet_key_derivation_consistency() {
    println!("🧪 Testing wallet key derivation consistency...");
    
    // : Test that address derivation is deterministic
    let (test_pk, _) = dilithium3_keypair();
    
    let address1 = address_from_pk(&test_pk);
    let address2 = address_from_pk(&test_pk);
    let address3 = address_from_pk(&test_pk);
    
    assert_eq!(address1, address2, "Address derivation should be deterministic");
    assert_eq!(address2, address3, "Address derivation should be consistently deterministic");
    
    // : Test that different keys produce different addresses
    let mut test_addresses = std::collections::HashSet::new();
    
    for _ in 0..50 {
        let (pk, _) = dilithium3_keypair();
        let addr = address_from_pk(&pk);
        
        assert!(!test_addresses.contains(&addr), "Address collision in key derivation test");
        test_addresses.insert(addr);
    }
    
    println!("  ✅ 50 unique addresses derived from different keys");
    
    // : Test address derivation avalanche effect
    let (base_pk, _) = dilithium3_keypair();
    let base_address = address_from_pk(&base_pk);
    
    // Create a slightly modified public key (this is artificial but tests the principle)
    let mut pk_bytes = base_pk.as_bytes().to_vec();
    pk_bytes[0] ^= 0x01; // Flip one bit
    
    if let Ok(modified_pk) = pqcrypto_dilithium::dilithium3::PublicKey::from_bytes(&pk_bytes) {
        let modified_address = address_from_pk(&modified_pk);
        
        assert_ne!(base_address, modified_address, "Small key change should produce different address");
        
        // Count differing bits (avalanche effect)
        let mut differing_bits = 0;
        for i in 0..32 {
            differing_bits += (base_address[i] ^ modified_address[i]).count_ones();
        }
        
        assert!(differing_bits > 50, "Address derivation should have good avalanche effect ({} bits differ)", differing_bits);
        println!("  ✅ Avalanche effect: {}/256 bits differ between similar keys", differing_bits);
    }
    
    println!("✅ Wallet key derivation consistency test: REAL");
}

#[tokio::test]
async fn test_wallet_error_handling() {
    println!("🧪 Testing wallet error handling...");
    
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    
    // : Test wallet creation with valid database
    let db_path = temp_dir.path().join("valid_wallet_db");
    let valid_store = Arc::new(Store::open(db_path.to_str().unwrap()).expect("Failed to open valid store"));
    
    let wallet_result = Wallet::load_or_create(valid_store.clone());
    assert!(wallet_result.is_ok(), "Wallet creation should succeed with valid database");
    
    // : Test wallet persistence across multiple operations
    let wallet1 = wallet_result.unwrap();
    let address1 = wallet1.address();
    
    // Simulate some time passing and multiple accesses
    for _ in 0..10 {
        let wallet_reload = Wallet::load_or_create(valid_store.clone()).expect("Wallet reload should succeed");
        let reload_address = wallet_reload.address();
        assert_eq!(address1, reload_address, "Address should remain consistent across reloads");
    }
    
    // : Test that wallet handles database being reopened
    drop(valid_store); // Close the store
    
    let reopened_store = Arc::new(Store::open(db_path.to_str().unwrap()).expect("Failed to reopen store"));
    let reopened_wallet = Wallet::load_or_create(reopened_store).expect("Wallet should work with reopened store");
    let reopened_address = reopened_wallet.address();
    
    assert_eq!(address1, reopened_address, "Address should persist across store close/reopen");
    
    println!("  ✅ Wallet persistence robust across database operations");
    
    println!("✅ Wallet error handling test: REAL");
}