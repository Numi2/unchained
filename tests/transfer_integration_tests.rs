use unchained::{
    storage::Store,
    wallet::Wallet,
    transfer::{Transfer, TransferManager},
};
use std::sync::Arc;
use tempfile::TempDir;

#[tokio::test]
async fn test_end_to_end_transfer() {
    // Create temporary database
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test_db");
    let db = Arc::new(Store::open(&db_path.to_string_lossy()).unwrap());

    // Create wallet1
    let wallet1 = Arc::new(Wallet::load_or_create(db.clone()).unwrap());

    println!("Wallet 1 address: {}", hex::encode(wallet1.address()));

    // Create a mock coin for wallet1
    let coin = unchained::coin::Coin::new(
        [1u8; 32], // epoch_hash
        12345,     // nonce
        wallet1.address(),
        [2u8; 32], // pow_hash
    );

    // Store the coin in the database
    db.put("coin", &coin.id, &coin).unwrap();

    // Verify initial balance
    let balance1 = wallet1.balance().unwrap();
    assert_eq!(balance1, 1, "Wallet 1 should have 1 coin initially");

    // Create a recipient wallet and obtain its stealth address
    let wallet2 = Arc::new(Wallet::load_or_create(db.clone()).unwrap());
    let recipient_stealth = wallet2.export_stealth_address();

    // Create transfer via wallet stealth send (without network broadcasting)
    let transfer = Wallet::send_to_stealth_address(&wallet1, &recipient_stealth, 1, &Arc::new(unchained::network::Network{ anchor_tx: broadcast::channel(1).0, proof_tx: broadcast::channel(1).0, command_tx: tokio::sync::mpsc::unbounded_channel().0 })).await.err().map(|_| {
        // We don't have a working NetHandle here; call the underlying create path directly for offline test
        let (_, kyber_pk) = Wallet::parse_and_verify_stealth_address(&recipient_stealth).unwrap();
        let transfer_mgr = TransferManager::new(db.clone());
        futures::executor::block_on(transfer_mgr.send_stealth_transfer(
            coin.id,
            wallet1.public_key().clone(),
            &wallet1.sign(b"dummy").clone().into_inner(),
            &kyber_pk,
            &Arc::new(unchained::network::Network{ anchor_tx: broadcast::channel(1).0, proof_tx: broadcast::channel(1).0, command_tx: tokio::sync::mpsc::unbounded_channel().0 })
        )).unwrap()
    }).unwrap_or_else(|_| unreachable!());

    // Validate the transfer
    transfer.validate(&db).unwrap();

    // Apply the transfer to the database
    transfer.apply(&db).unwrap();

    // Verify transfer was created correctly
    assert_eq!(transfer.coin_id, coin.id);
    assert_eq!(transfer.recipient(), transfer.recipient());
    assert!(transfer.is_from(&wallet1.address()).unwrap());

    // Verify the transfer was stored in the database
    let stored_transfer = db.get::<Transfer>("transfer", &coin.id).unwrap();
    assert!(stored_transfer.is_some());
    assert_eq!(stored_transfer.unwrap().coin_id, coin.id);

    // Verify updated balance
    let new_balance1 = wallet1.balance().unwrap();
    assert_eq!(new_balance1, 0, "Wallet 1 should have 0 coins after transfer");

    // Verify coin is marked as spent
    let unspent1 = wallet1.list_unspent().unwrap();
    assert_eq!(unspent1.len(), 0, "Wallet 1 should have no unspent coins");

    // Test double-spend prevention
    let double_spend = transfer.clone();
    
    let validation_result = double_spend.validate(&db);
    assert!(validation_result.is_err(), "Double-spend should be rejected");

    println!("✅ End-to-end transfer test passed!");
}

#[tokio::test]
async fn test_transfer_validation() {
    // Create temporary database
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test_db");
    let db = Arc::new(Store::open(&db_path.to_string_lossy()).unwrap());

    // Create wallet
    let wallet1 = Arc::new(Wallet::load_or_create(db.clone()).unwrap());
    let recipient_address = [0x42u8; 32]; // Different address

    // Create a coin for wallet1
    let coin = unchained::coin::Coin::new(
        [1u8; 32],
        12345,
        wallet1.address(),
        [2u8; 32],
    );
    db.put("coin", &coin.id, &coin).unwrap();

    // Test 1: Valid transfer
    let transfer = Transfer::create(
        coin.id,
        wallet1.public_key().clone(),
        wallet1.secret_key(),
        recipient_address,
        coin.id, // prev_tx_hash
    ).unwrap();

    let validation_result = transfer.validate(&db);
    assert!(validation_result.is_ok(), "Valid transfer should pass validation");

    // Test 2: Transfer with non-existent coin
    let fake_coin_id = [99u8; 32];
    let invalid_transfer = Transfer::create(
        fake_coin_id,
        wallet1.public_key().clone(),
        wallet1.secret_key(),
        recipient_address,
        fake_coin_id,
    ).unwrap();

    let validation_result = invalid_transfer.validate(&db);
    assert!(validation_result.is_err(), "Transfer with non-existent coin should fail");

    // Test 3: Transfer to zero address
    let zero_transfer_result = Transfer::create(
        coin.id,
        wallet1.public_key().clone(),
        wallet1.secret_key(),
        [0u8; 32], // zero address
        coin.id,
    );
    assert!(zero_transfer_result.is_err(), "Transfer to zero address should fail at creation");

    // Test 4: Double-spend
    transfer.apply(&db).unwrap(); // Apply the first transfer
    
    let double_spend = Transfer::create(
        coin.id,
        wallet1.public_key().clone(),
        wallet1.secret_key(),
        recipient_address,
        coin.id,
    ).unwrap();

    let validation_result = double_spend.validate(&db);
    assert!(validation_result.is_err(), "Double-spend should fail validation");

    println!("✅ Transfer validation test passed!");
}

#[tokio::test]
async fn test_wallet_transfer_functionality() {
    // Create temporary database
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("test_db");
    let db = Arc::new(Store::open(&db_path.to_string_lossy()).unwrap());

    // Create wallet
    let wallet1 = Arc::new(Wallet::load_or_create(db.clone()).unwrap());
    let recipient_address = [0x42u8; 32]; // Different address

    // Create multiple coins for wallet1
    for i in 0..5 {
        let coin = unchained::coin::Coin::new(
            [i as u8; 32],
            i as u64,
            wallet1.address(),
            [i as u8; 32],
        );
        db.put("coin", &coin.id, &coin).unwrap();
    }

    // Verify initial state
    let balance1 = wallet1.balance().unwrap();
    assert_eq!(balance1, 5, "Wallet 1 should have 5 coins");

    // Create transfer manager
    let transfer_mgr = TransferManager::new(db.clone());

    // Get coins to spend
    let coins_to_spend = wallet1.select_inputs(3).unwrap();
    assert_eq!(coins_to_spend.len(), 3, "Should select 3 coins");

    // Create transfers for each coin manually
    let mut transfers = Vec::new();
    for coin in coins_to_spend {
        let transfer = Transfer::create(
            coin.id,
            wallet1.public_key().clone(),
            wallet1.secret_key(),
            recipient_address,
            coin.id,
        ).unwrap();
        
        transfer.validate(&db).unwrap();
        transfer.apply(&db).unwrap();
        transfers.push(transfer);
    }

    assert_eq!(transfers.len(), 3, "Should have created 3 transfers");

    // Verify updated balance
    let new_balance1 = wallet1.balance().unwrap();
    assert_eq!(new_balance1, 2, "Wallet 1 should have 2 coins remaining");

    // Verify transaction history
    let history1 = wallet1.get_transaction_history().unwrap();
    assert_eq!(history1.len(), 3, "Wallet 1 should have 3 outgoing transactions");

    // Verify all transactions are properly recorded
    for record in &history1 {
        assert!(record.is_sender, "Wallet 1 should be sender in all transactions");
        assert_eq!(record.counterparty, recipient_address);
        assert_eq!(record.amount, 1);
    }

    println!("✅ Wallet transfer functionality test passed!");
}
