use crate::{storage::Store, crypto, epoch::Anchor, coin::Coin, network::NetHandle, wallet::Wallet};
use rand::Rng;
use std::sync::Arc;
use tokio::{sync::{broadcast::Receiver, mpsc}, task};

pub fn spawn(
    cfg: crate::config::Mining,
    db: Arc<Store>,
    net: NetHandle,
    wallet: Arc<Wallet>, // The miner needs a persistent identity
    coin_tx: mpsc::UnboundedSender<[u8; 32]>,
) {
    let mut anchor_rx: Receiver<Anchor> = net.anchor_subscribe();
    task::spawn(async move {
        loop {
            if let Ok(anchor) = anchor_rx.recv().await {
                println!(
                    "⛏️  New epoch #{}: difficulty={}, mem_kib={}. Mining...",
                    anchor.num, anchor.difficulty, anchor.mem_kib
                );
                mine_epoch(anchor, cfg.lanes, &wallet, &db, &net, &coin_tx).await;
            } else {
                eprintln!("❌ Miner stopped: anchor channel closed or lagged.");
                break;
            }
        }
    });
}

async fn mine_epoch(
    anchor: Anchor,
    lanes: u32,
    wallet: &Wallet,
    db: &Arc<Store>,
    net: &NetHandle,
    coin_tx: &mpsc::UnboundedSender<[u8; 32]>,
) {
    let creator_address = wallet.address();
    let mem_kib = anchor.mem_kib;
    let difficulty = anchor.difficulty;

    loop {
        let nonce: u64 = rand::thread_rng().gen();
        let header = Coin::header_bytes(&anchor.hash, nonce, &creator_address);
        
        if let Ok(pow_hash) = crypto::argon2id_pow(&header, mem_kib, lanes) {
            if pow_hash.iter().take(difficulty).all(|&b| b == 0) {
                let coin = Coin::new(anchor.hash, nonce, creator_address, pow_hash);
                println!("✅ Found a new coin! ID: {}", hex::encode(&coin.id));

                if let Err(e) = db.put("coin", &coin.id, &coin) {
                    eprintln!("🔥 Failed to save coin to DB: {e}");
                }
                if coin_tx.send(coin.id).is_err() {
                    eprintln!("🔥 Failed to send coin ID to epoch manager");
                }
                net.gossip_coin(&coin).await;
                break;
            }
        }
    }
}