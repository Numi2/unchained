use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tauri::State;
use tokio::sync::{broadcast, mpsc};
use std::collections::HashMap;
use rocksdb;
use bincode;

// Import unchained modules
use unchained::{coin::Coin, 
    config::{self},
    storage::{self, Store},
    wallet::Wallet,
    epoch::Anchor,
    network::NetHandle,
    miner, sync, epoch, metrics,
};

// Standard library imports
use std::path::{Path, PathBuf};

// Application state with proper task management
#[derive(Default)]
pub struct AppState {
    pub config: Option<unchained::config::Config>,
    pub db: Option<Arc<Store>>,
    pub wallet: Option<Arc<Wallet>>,
    pub network: Option<NetHandle>,
    pub mining_enabled: bool,
    pub node_running: bool,
    // Task management
    pub shutdown_tx: Option<broadcast::Sender<()>>,
    pub coin_tx: Option<mpsc::UnboundedSender<[u8; 32]>>,
    pub background_tasks: HashMap<String, tokio::task::JoinHandle<()>>,
    // Mining-specific shutdown
    pub mining_shutdown_tx: Option<broadcast::Sender<()>>,
}

// Response types for the frontend
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct WalletInfo {
    pub address: String,
    pub balance: u64,
    pub unlocked: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NodeStatus {
    pub running: bool,
    pub mining: bool,
    pub peers: u32,
    pub current_epoch: Option<u64>,
    pub difficulty: Option<usize>,
    pub coins_mined: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EpochInfo {
    pub num: u64,
    pub hash: String,
    pub difficulty: usize,
    pub coin_count: u32,
    pub cumulative_work: String, // u128 as string for JSON compatibility
    pub mem_kib: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BlockInfo {
    pub id: String,
    pub created_at_epoch: u64,
    pub created_at_height: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TransferRequest {
    pub to_address: String,
    pub coin_id: String,
    pub passphrase: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NetworkPeer {
    pub id: String,
    pub address: String,
    pub connected: bool,
}

// Tauri commands

/// Attempt to locate the configuration file.
///
/// 1. If `path` is absolute and exists, use it.
/// 2. If `path` is relative and exists relative to the current working directory, use it.
/// 3. Otherwise, walk up parent directories of the current working directory looking for
///    the *file name* part (e.g. `config.toml`). This makes paths like `../config.toml`
///    work regardless of where the binary is executed from (e.g. `target/debug`).
fn resolve_config_path<P: AsRef<Path>>(path: P) -> Option<PathBuf> {
    let p = path.as_ref();

    // 1. Absolute path
    if p.is_absolute() && p.is_file() {
        return Some(p.to_path_buf());
    }

    // 2. Relative path from CWD
    if p.is_file() {
        return Some(std::env::current_dir().ok()?.join(p));
    }

    // 3. Walk up ancestors looking for the file name
    if let Some(file_name) = p.file_name() {
        let mut dir = std::env::current_dir().ok()?;
        loop {
            let candidate = dir.join(file_name);
            if candidate.is_file() {
                return Some(candidate);
            }
            if !dir.pop() {
                break;
            }
        }
    }

    None
}

#[tauri::command]
fn load_config(config_path: String) -> Result<String, String> {
    let cfg_path = resolve_config_path(&config_path)
        .ok_or_else(|| format!("Config file not found: {}", config_path))?;

    match config::load(&cfg_path) {
        Ok(_) => Ok(format!("Config loaded successfully from: {}", cfg_path.display())),
        Err(e) => Err(e.to_string())
    }
}

#[tauri::command]
async fn get_wallet_info(state: State<'_, Mutex<AppState>>) -> Result<Option<WalletInfo>, String> {
    let (db, wallet) = {
        let app_state = state.lock().unwrap();
        (app_state.db.clone(), app_state.wallet.clone())
    };
    
    match (db, wallet) {
        (Some(db), Some(wallet)) => {
            // Get wallet balance by scanning owned coins
            let balance = calculate_wallet_balance(&db, &wallet).await.map_err(|e| e.to_string())?;
            
            Ok(Some(WalletInfo {
                address: hex::encode(wallet.address()),
                balance,
                unlocked: true,
            }))
        }
        _ => Ok(None),
    }
}

#[tauri::command]
async fn unlock_wallet(
    passphrase: String, 
    state: State<'_, Mutex<AppState>>
) -> Result<WalletInfo, String> {
    let db = {
        let app_state = state.lock().unwrap();
        app_state.db.clone()
    };
    
    // Enforce a non-empty passphrase.  An empty string would effectively leave
    // the wallet unprotected which is undesirable from a security point of
    // view.
    if passphrase.trim().is_empty() {
        return Err("Passphrase must not be empty".to_string());
    }

    if let Some(db) = db {
        // Set environment variable for wallet passphrase
        std::env::set_var("WALLET_PASSPHRASE", &passphrase);
        
        let wallet = Arc::new(Wallet::load_or_create(db.clone()).map_err(|e| e.to_string())?);
        let balance = calculate_wallet_balance(&db, &wallet).await.map_err(|e| e.to_string())?;
        
        let wallet_info = WalletInfo {
            address: hex::encode(wallet.address()),
            balance,
            unlocked: true,
        };
        
        // Update state
        {
            let mut app_state = state.lock().unwrap();
            app_state.wallet = Some(wallet);
        }
        
        Ok(wallet_info)
    } else {
        Err("Database not initialized".to_string())
    }
}

#[tauri::command]
async fn get_node_status(state: State<'_, Mutex<AppState>>) -> Result<NodeStatus, String> {
    let (node_running, mining_enabled, db, _network) = {
        let app_state = state.lock().unwrap();
        (app_state.node_running, app_state.mining_enabled, app_state.db.clone(), app_state.network.clone())
    };
    
    let mut status = NodeStatus {
        running: node_running,
        mining: mining_enabled,
        peers: 0,
        current_epoch: None,
        difficulty: None,
        coins_mined: 0,
    };
    
    if let Some(db) = db {
        // Get latest epoch info
        if let Ok(Some(latest_epoch)) = db.get::<Anchor>("epoch", b"latest") {
            status.current_epoch = Some(latest_epoch.num);
            status.difficulty = Some(latest_epoch.difficulty);
        }
        
        // Count total coins by scanning epochs
        status.coins_mined = count_total_coins(&db).await.map_err(|e| e.to_string())?;
    }
    
    // TODO: Implement peer count from network if needed
    // For now, set to 0 since get_peer_count method doesn't exist yet
    status.peers = 0;
    
    Ok(status)
}

#[tauri::command]
async fn get_recent_epochs(
    limit: usize,
    state: State<'_, Mutex<AppState>>
) -> Result<Vec<EpochInfo>, String> {
    let app_state = state.lock().unwrap();
    
    match &app_state.db {
        Some(db) => {
            let mut epochs = Vec::new();
            
            // Get latest epoch first
            if let Ok(Some(latest)) = db.get::<Anchor>("epoch", b"latest") {
                let start_epoch = latest.num.saturating_sub(limit as u64 - 1);
                
                for epoch_num in start_epoch..=latest.num {
                    if let Ok(Some(epoch)) = db.get::<Anchor>("epoch", &epoch_num.to_le_bytes()) {
                        epochs.push(EpochInfo {
                            num: epoch.num,
                            hash: hex::encode(epoch.hash),
                            difficulty: epoch.difficulty,
                            coin_count: epoch.coin_count,
                            cumulative_work: epoch.cumulative_work.to_string(),
                            mem_kib: epoch.mem_kib,
                        });
                    }
                }
            }
            
            epochs.reverse(); // Most recent first
            Ok(epochs)
        }
        None => Err("Database not initialized".to_string()),
    }
}

#[tauri::command]
async fn get_recent_blocks(
    limit: usize,
    state: State<'_, Mutex<AppState>>
) -> Result<Vec<BlockInfo>, String> {
    let app_state = state.lock().unwrap();
    match &app_state.db {
        Some(db) => {
            let mut blocks = Vec::new();
            let cf = db.db.cf_handle("coin").unwrap();
            let iter = db.db.iterator_cf(cf, rocksdb::IteratorMode::End);

            for item in iter.take(limit) {
                if let Ok((_key, value)) = item {
                    if let Ok(coin) = bincode::deserialize::<Coin>(&value) {
                        blocks.push(BlockInfo {
                            id: hex::encode(coin.id),
                            created_at_epoch: 0,
                            created_at_height: 0,
                        });
                    }
                }
            }
            Ok(blocks)
        }
        None => Err("Database not initialized".to_string()),
    }
}

#[tauri::command]
async fn start_node(
    config_path: String,
    state: State<'_, Mutex<AppState>>
) -> Result<String, String> {
    println!("🔄 Starting node initialization...");
    
    // Wrap everything in a result to catch any potential panics
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| async move {
        start_node_impl(config_path, state).await
    }));
    
    match result {
        Ok(future) => future.await,
        Err(_) => {
            println!("💥 Node startup panicked!");
            Err("Node startup failed due to an internal error".to_string())
        }
    }
}

async fn start_node_impl(
    config_path: String,
    state: State<'_, Mutex<AppState>>
) -> Result<String, String> {
    
    // Check if node is already running
    {
        let app_state = state.lock().unwrap();
        if app_state.node_running {
            return Err("Node is already running".to_string());
        }
    } // Lock dropped here
    
    // Locate and load configuration with multiple fallback paths
    println!("📝 Loading configuration from: {}", config_path);
    let cfg_path = resolve_config_path(&config_path)
        .or_else(|| resolve_config_path("../config.toml"))
        .or_else(|| resolve_config_path("../../config.toml"))
        .or_else(|| resolve_config_path("config.toml"))
        .ok_or_else(|| format!("Failed to locate config file: tried '{}', '../config.toml', '../../config.toml', 'config.toml'", config_path))?;

    let mut cfg = config::load(&cfg_path)
        .map_err(|e| format!("Failed to load config: {}", e))?;
    println!("✅ Configuration loaded successfully");

    // ------------------------------------------------------------------
    // Resolve storage path relative to the config file’s directory so that
    // the Tauri app (launched from a deeper folder) shares the **same** DB
    // location as the CLI.
    // ------------------------------------------------------------------
    if std::path::Path::new(&cfg.storage.path).is_relative() {
        if let Some(cfg_dir) = std::path::Path::new(&cfg_path).parent() {
            let abs = cfg_dir.join(&cfg.storage.path);
            cfg.storage.path = abs.to_string_lossy().into_owned();
        }
    }
    
    // Open or reuse database
    let db = {
        let existing = {
            let app_state = state.lock().unwrap();
            app_state.db.clone()
        };
        if let Some(db) = existing {
            println!("🔄 Reusing existing database connection");
            db
        } else {
            println!("🗄️  Opening database at: {}", cfg.storage.path);
            let db = storage::open(&cfg.storage);
            println!("✅ Database opened successfully");
            db
        }
    };
    
    // Create shutdown broadcast channel for coordinated shutdown
    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    
    // ------------------------------------------------------------------
    // Wallet handling
    // ------------------------------------------------------------------
    // The node can start without an unlocked wallet. Mining (and any wallet
    // related operations) will only be enabled once the user provides a
    // pass-phrase through the `unlock_wallet` command. If a pass-phrase is
    // supplied via the `WALLET_PASSPHRASE` environment variable we'll attempt
    // to load (or create) the wallet immediately, otherwise we postpone wallet
    // creation to the explicit unlock step.
    // ------------------------------------------------------------------

    let wallet: Option<Arc<Wallet>> = match std::env::var("WALLET_PASSPHRASE") {
        Ok(ref p) if !p.trim().is_empty() => {
            println!("👛 Loading/creating wallet with provided passphrase…");
            match Wallet::load_or_create(db.clone()) {
                Ok(w) => {
                    println!("✅ Wallet ready. Address: {}", hex::encode(w.address()));
                    Some(Arc::new(w))
                }
                Err(e) => {
                    println!("❌ Wallet loading failed: {}", e);
                    return Err(format!("Failed to load wallet: {}", e));
                }
            }
        }
        _ => {
            println!("🔑 No wallet passphrase provided – node will start without wallet. You can unlock or create one later.");
            None
        }
    };
    
    // Start network with better error handling
    println!("📡 Starting network on port {}...", cfg.net.listen_port);
    let net = match unchained::network::spawn(cfg.net.clone(), db.clone()).await {
        Ok(n) => {
            println!("✅ Network started successfully");
            n
        },
        Err(e) => {
            println!("❌ Network startup failed: {}", e);
            return Err(format!("Failed to start network: {}", e));
        }
    };
    
    // Create coin channel for miner -> epoch manager communication
    let (coin_tx, coin_rx) = mpsc::unbounded_channel();
    
    // Spawn epoch manager
    println!("⏰ Starting epoch manager...");
    let epoch_mgr = epoch::Manager::new(
        db.clone(),
        cfg.epoch.clone(),
        cfg.mining.clone(),
        net.clone(),
        coin_rx,
        shutdown_tx.subscribe(),
    );
    epoch_mgr.spawn();
    println!("✅ Epoch manager started");
    
    // Spawn sync
    println!("🔄 Starting sync service...");
    sync::spawn(db.clone(), net.clone(), shutdown_tx.subscribe());
    println!("✅ Sync service started");
    
    // Start metrics server with better error handling
    println!("📊 Starting metrics server on {}...", cfg.metrics.bind);
    if let Err(e) = metrics::serve(cfg.metrics.clone()) {
        println!("⚠️  Metrics server failed to start: {}", e);
        // Don't fail the entire node startup for metrics
    } else {
        println!("✅ Metrics server started");
    }
    
    // Now update app state
    {
        let mut app_state = state.lock().unwrap();
        app_state.config = Some(cfg.clone());
        app_state.db = Some(db.clone());
        app_state.wallet = wallet;
        app_state.network = Some(net);
        app_state.shutdown_tx = Some(shutdown_tx);
        app_state.coin_tx = Some(coin_tx);
        app_state.node_running = true;
        // Clear previous mining flag so UI reflects fresh state
        app_state.mining_enabled = false;
    } // Lock dropped here
    
    println!("🚀 unchained node started successfully!");
    println!("   📡 P2P listening on port {}", cfg.net.listen_port);
    println!("   📊 Metrics available on http://{}", cfg.metrics.bind);
    
    Ok("Node started successfully".to_string())
}

#[tauri::command]
async fn stop_node(state: State<'_, Mutex<AppState>>) -> Result<String, String> {
    // Get shutdown handle and check node status
    let (shutdown_tx, db, background_tasks) = {
        let mut app_state = state.lock().unwrap();
        
        if !app_state.node_running {
            return Err("Node is not running".to_string());
        }
        
        println!("🛑 Shutdown signal received, cleaning up...");
        
        // Get components we need for shutdown
        let shutdown_tx = app_state.shutdown_tx.clone();
        let db = app_state.db.clone();
        let background_tasks = std::mem::take(&mut app_state.background_tasks);
        
        (shutdown_tx, db, background_tasks)
    }; // Lock dropped here
    
    // Signal all background tasks to shutdown
    if let Some(shutdown_tx) = shutdown_tx {
        println!("📡 Signaling background tasks to shutdown...");
        let _ = shutdown_tx.send(());
    }
    
    // Give tasks a reasonable time to shutdown gracefully
    println!("⏳ Waiting for tasks to shutdown gracefully...");
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    
    // Abort any remaining background tasks
    for (name, handle) in background_tasks {
        println!("🔄 Aborting background task: {}", name);
        handle.abort();
    }
    
    // Flush DB (keep open) so next start reuses the same handle
    if let Some(db) = db.as_ref() {
        if let Err(e) = db.flush() {
            eprintln!("Warning: Database flush failed: {}", e);
        }
        println!("✅ Database flushed");
    }
    
    // Reset runtime state but keep DB handle for quick restart
    {
        let mut app_state = state.lock().unwrap();
        app_state.node_running = false;
        app_state.mining_enabled = false;
        app_state.network = None;
        // Keep db and wallet so they can be reused on next start
        app_state.shutdown_tx = None;
        app_state.coin_tx = None;
        app_state.mining_shutdown_tx = None;
        // Don’t clear config so relative paths remain resolved

        // Clear wallet passphrase so the next session requires the user to re-enter it.
        std::env::remove_var("WALLET_PASSPHRASE");
    } // Lock dropped here
    
    println!("👋 unchained node stopped");
    Ok("Node stopped successfully".to_string())
}

#[tauri::command]
async fn toggle_mining(
    enabled: bool,
    state: State<'_, Mutex<AppState>>
) -> Result<String, String> {
    let mut app_state = state.lock().unwrap();
    
    if !app_state.node_running {
        return Err("Node must be running to control mining".to_string());
    }
    if enabled && app_state.wallet.is_none() {
        return Err("Unlock or create a wallet before starting mining".to_string());
    }
    
    // Get required components for mining
    let (config, db, network, wallet, coin_tx) = {
        let cfg = app_state.config.as_ref().ok_or("Configuration not loaded")?;
        let db = app_state.db.as_ref().ok_or("Database not initialized")?;
        let net = app_state.network.as_ref().ok_or("Network not running")?;
        let wallet = app_state.wallet.as_ref().ok_or("Wallet not loaded")?;
        let coin_tx = app_state.coin_tx.as_ref().ok_or("Coin channel not available")?;
        
        (cfg.clone(), db.clone(), net.clone(), wallet.clone(), coin_tx.clone())
    };
    
    if enabled && !app_state.mining_enabled {
        // Start mining
        println!("⛏️  Starting mining...");
        
        // Create a dedicated shutdown channel for mining
        let (mining_shutdown_tx, _) = broadcast::channel::<()>(1);
        
        // Spawn the miner using the existing miner::spawn function
        miner::spawn(
            config.mining.clone(),
            db,
            network,
            wallet,
            coin_tx,
            mining_shutdown_tx.subscribe(),
        );
        
        // Store the mining shutdown sender
        app_state.mining_shutdown_tx = Some(mining_shutdown_tx);
        app_state.mining_enabled = true;
        println!("✅ Mining started successfully");
        Ok("Mining started".to_string())
        
    } else if !enabled && app_state.mining_enabled {
        // Stop mining
        println!("🛑 Stopping mining...");
        
        // Send shutdown signal to mining task
        if let Some(mining_shutdown_tx) = &app_state.mining_shutdown_tx {
            let _ = mining_shutdown_tx.send(());
        }
        
        // Clear the mining shutdown sender
        app_state.mining_shutdown_tx = None;
        app_state.mining_enabled = false;
        
        println!("✅ Mining stopped");
        Ok("Mining stopped".to_string())
        
    } else if enabled && app_state.mining_enabled {
        Ok("Mining is already running".to_string())
    } else {
        Ok("Mining is already stopped".to_string())
    }
}

#[tauri::command]
async fn create_transfer(
    request: TransferRequest,
    state: State<'_, Mutex<AppState>>
) -> Result<String, String> {
    let app_state = state.lock().unwrap();
    
    match (&app_state.db, &app_state.wallet) {
        (Some(_db), Some(_wallet)) => {
            // In a real implementation, you would:
            // 1. Validate the transfer request
            // 2. Create and sign the transfer
            // 3. Broadcast it to the network
            
            // For now, just validate the inputs
            let _to_addr = hex::decode(&request.to_address)
                .map_err(|_| "Invalid destination address")?;
            
            if _to_addr.len() != 32 {
                return Err("Address must be 32 bytes".to_string());
            }
            
            let _coin_id = hex::decode(&request.coin_id)
                .map_err(|_| "Invalid coin ID")?;
            
            if _coin_id.len() != 32 {
                return Err("Coin ID must be 32 bytes".to_string());
            }
            
            Ok("Transfer created successfully (simulation)".to_string())
        }
        _ => Err("Wallet must be unlocked to create transfers".to_string()),
    }
}

#[tauri::command]
async fn get_owned_coins(
    state: State<'_, Mutex<AppState>>
) -> Result<Vec<String>, String> {
    let app_state = state.lock().unwrap();
    
    match (&app_state.db, &app_state.wallet) {
        (Some(_db), Some(_wallet)) => {
            // In a real implementation, you would scan the database for coins
            // owned by this wallet address
            // For now, return empty list
            Ok(vec![])
        }
        _ => Err("Wallet must be unlocked".to_string()),
    }
}

// Helper functions
async fn calculate_wallet_balance(_db: &Arc<Store>, wallet: &Arc<Wallet>) -> Result<u64> {
    // Use the wallet's built-in balance calculation method
    // Only log when balance changes significantly (for debugging)
    let balance = wallet.balance()?;
    if balance > 0 {
        // Only log once per balance value to reduce spam
        static mut LAST_BALANCE: u64 = 0;
        unsafe {
            if balance != LAST_BALANCE {
                println!("💰 Wallet balance: {} coins", balance);
                LAST_BALANCE = balance;
            }
        }
    }
    Ok(balance)
}

async fn count_total_coins(db: &Arc<Store>) -> Result<u64> {
    let mut total = 0u64;
    
    // Count coins from epoch metadata
    for epoch_num in 0u64..=100 { // Check first 100 epochs
        if let Ok(Some(epoch)) = db.get::<Anchor>("epoch", &epoch_num.to_le_bytes()) {
            total += epoch.coin_count as u64;
        } else {
            break; // No more epochs
        }
    }
    
    Ok(total)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(Mutex::new(AppState::default()))
        .invoke_handler(tauri::generate_handler![
            load_config,
            get_wallet_info,
            unlock_wallet,
            get_node_status,
            get_recent_epochs,
            get_recent_blocks,
            start_node,
            stop_node,
            toggle_mining,
            create_transfer,
            get_owned_coins
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}