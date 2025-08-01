// ADVERSARIAL Integration Tests
// These tests validate the blockchain's ability to defend against malicious actors.

use std::collections::HashSet;
use std::sync::Arc;
use tempfile::TempDir;
use unchainedcoin::{
    coin::Coin,
    crypto::{self, dilithium3_keypair, address_from_pk},
    storage::Store,
    epoch::{Anchor, MerkleTree},
    wallet::Wallet,
    // We will assume a Chain struct exists for managing the blockchain state
    // and a Block struct for representing a block.
    // chain::Chain,
    // block::Block,
};

// Mock structures - these will need to be replaced with actual implementations
// for the tests to compile and run.
struct Block {
    anchor: Anchor,
    coins: HashSet<Coin>,
}

struct Chain {
    store: Arc<Store>,
    // A real implementation would have more state, like the current chain tip.
}

impl Chain {
    fn new(store: Arc<Store>) -> Self {
        Self { store }
    }

    // This is a placeholder for the real block validation logic.
    // A real implementation would be much more complex.
    fn add_block(&self, block: Block) -> Result<(), &'static str> {
        // 1. Verify Merkle Root BEFORE any expensive PoW checks
        let coin_ids: HashSet<[u8; 32]> = block.coins.iter().map(|c| c.id).collect();
        let merkle_root = MerkleTree::build_root(&coin_ids);
        if merkle_root != block.anchor.hash {
            return Err("Merkle root does not match coin data");
        }

        // 2. Verify PoW for each coin in the block
        for coin in &block.coins {
            let header = Coin::header_bytes(&coin.epoch_hash, coin.nonce, &coin.creator_address);
            let Ok(calculated_pow) = crypto::argon2id_pow(&header, block.anchor.mem_kib, 1) else {
                return Err("PoW calculation failed");
            };

            // Hash must match the stored pow_hash and satisfy difficulty
            if calculated_pow != coin.pow_hash {
                return Err("Invalid PoW");
            }
            if !calculated_pow.iter().take(block.anchor.difficulty).all(|&b| b == 0) {
                return Err("Invalid PoW");
            }
        }

        // 3. Check for double-spends (simplified)
        for coin in &block.coins {
            if self.store.get::<Coin>("coin", &coin.id).unwrap().is_some() {
                return Err("Double-spend detected");
            }
        }

        // 4. Persist anchor and coins atomically
        self.store.put("anchor", &block.anchor.num.to_le_bytes(), &block.anchor).unwrap();
        for coin in &block.coins {
            self.store.put("coin", &coin.id, coin).unwrap();
        }

        Ok(())
    }
}


#[tokio::test]
async fn test_invalid_block_submission() {
    println!("🧪 Testing invalid block submission...");

    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("invalid_block_test_db");
    let store = Arc::new(Store::open(db_path.to_str().unwrap()).unwrap());
    let chain = Chain::new(store.clone());
    let wallet = Wallet::load_or_create(store.clone()).unwrap();
    let creator_address = wallet.address();

    // Create a valid coin
    let epoch_hash = crypto::blake3_hash(b"test_epoch");
    let (nonce, pow_hash) = mine_valid_pow(&epoch_hash, &creator_address, 1);
    let valid_coin = Coin::new(epoch_hash, nonce, creator_address, pow_hash);
    let mut coins = HashSet::new();
    coins.insert(valid_coin.clone());

    // --- Attack 1: Submit a block with a bad Merkle root ---
    let valid_merkle_root = MerkleTree::build_root(&coins.iter().map(|c| c.id).collect());
    let mut bad_merkle_root = valid_merkle_root.clone();
    bad_merkle_root[0] ^= 0x01; // Corrupt the root

    let bad_anchor = Anchor {
        num: 1,
        hash: bad_merkle_root,
        difficulty: 1,
        coin_count: 1,
        cumulative_work: 256,
        mem_kib: 1024,
    };
    let bad_block = Block { anchor: bad_anchor, coins: coins.clone() };

    assert_eq!(
        chain.add_block(bad_block).unwrap_err(),
        "Merkle root does not match coin data",
        "Chain should reject block with a bad Merkle root"
    );
    println!("  ✅ Chain correctly rejected block with bad Merkle root");

    // --- Attack 2: Submit a block with an invalid PoW ---
    let invalid_pow_hash = [0xff; 32]; // Does not meet difficulty
    let invalid_coin = Coin::new(epoch_hash, 123, creator_address, invalid_pow_hash);
    let mut invalid_coins = HashSet::new();
    invalid_coins.insert(invalid_coin);
    let invalid_merkle_root = MerkleTree::build_root(&invalid_coins.iter().map(|c| c.id).collect());

    let invalid_anchor = Anchor {
        num: 2,
        hash: invalid_merkle_root,
        difficulty: 1, // Requires 1 leading zero
        coin_count: 1,
        cumulative_work: 512,
        mem_kib: 1024,
    };
    let invalid_block = Block { anchor: invalid_anchor, coins: invalid_coins };

    assert_eq!(
        chain.add_block(invalid_block).unwrap_err(),
        "Invalid PoW",
        "Chain should reject block with an invalid PoW"
    );
    println!("  ✅ Chain correctly rejected block with invalid PoW");
}

#[tokio::test]
async fn test_double_spend_attack() {
    println!("🧪 Testing double-spend attack...");

    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("double_spend_test_db");
    let store = Arc::new(Store::open(db_path.to_str().unwrap()).unwrap());
    let chain = Chain::new(store.clone());
    let wallet = Wallet::load_or_create(store.clone()).unwrap();
    let creator_address = wallet.address();

    // 1. Mine a valid coin and include it in a valid block
    let epoch_hash = crypto::blake3_hash(b"double_spend_epoch");
    let (nonce, pow_hash) = mine_valid_pow(&epoch_hash, &creator_address, 1);
    let original_coin = Coin::new(epoch_hash, nonce, creator_address, pow_hash);
    
    let mut block1_coins = HashSet::new();
    block1_coins.insert(original_coin.clone());
    let block1_merkle_root = MerkleTree::build_root(&block1_coins.iter().map(|c| c.id).collect());
    let block1_anchor = Anchor {
        num: 1,
        hash: block1_merkle_root,
        difficulty: 1,
        coin_count: 1,
        cumulative_work: 256,
        mem_kib: 1024,
    };
    let block1 = Block { anchor: block1_anchor, coins: block1_coins };

    // Add the first block to the chain
    assert!(chain.add_block(block1).is_ok(), "First block should be valid");
    println!("  ✅ Block 1 with original coin added to the chain");

    // 2. Attempt to include the *same coin* in a new block
    let mut block2_coins = HashSet::new();
    block2_coins.insert(original_coin.clone()); // The double-spend attempt
    let block2_merkle_root = MerkleTree::build_root(&block2_coins.iter().map(|c| c.id).collect());
    let block2_anchor = Anchor {
        num: 2,
        hash: block2_merkle_root,
        difficulty: 1,
        coin_count: 1,
        cumulative_work: 512,
        mem_kib: 1024,
    };
    let block2 = Block { anchor: block2_anchor, coins: block2_coins };

    // This should fail because the coin is already in the store
    assert_eq!(
        chain.add_block(block2).unwrap_err(),
        "Double-spend detected",
        "Chain should reject block containing a coin that has already been spent"
    );
    println!("  ✅ Chain correctly rejected block with double-spent coin");
}

// Helper function to mine a valid PoW for testing
fn mine_valid_pow(epoch_hash: &[u8; 32], creator_address: &[u8; 32], difficulty: usize) -> (u64, [u8; 32]) {
    let mut nonce = 0;
    loop {
        let header = Coin::header_bytes(epoch_hash, nonce, creator_address);
        if let Ok(pow_hash) = crypto::argon2id_pow(&header, 1024, 1) {
            if pow_hash.iter().take(difficulty).all(|&b| b == 0) {
                return (nonce, pow_hash);
            }
        }
        nonce += 1;
    }
}
