//! Sync logic: detects gaps, requests missing epochs, and streams data back
//! ------------------------------------------------------------------------
//! Assumes `network.rs` exposes:
//!   • fn anchor_subscribe(&self) -> broadcast::Receiver<epoch::Anchor>
//!   • async fn request_epoch(&self, num: u64)
//!   • async fn request_coin(&self, id: [u8; 32])
//!
//! And that `network.rs` gossips back the missing `Anchor / Coin / Transfer`
//! messages, which we store on arrival (handled inside `network.rs`).

use crate::{storage::Store, epoch::Anchor, network::NetHandle};
use std::sync::Arc;
use tokio::{sync::broadcast::Receiver, task};

/// Spawns the background sync worker
pub fn spawn(db: Arc<Store>, net: NetHandle) {
    // Subscribe to live anchors from the network
    let mut anchor_rx: Receiver<Anchor> = net.anchor_subscribe();

    task::spawn(async move {
        // Find the last epoch we already have (0 if fresh DB)
        let mut local_epoch: u64 =
            db.get::<Anchor>("epoch", b"latest").map_or(0, |a| a.num);

        loop {
            match anchor_rx.recv().await {
                Ok(anchor) => {
                    // If we’re behind, request missing epochs one by one
                    if anchor.num > local_epoch + 1 {
                        for missing in (local_epoch + 1)..anchor.num {
                            net.request_epoch(missing).await;
                        }
                    }
                    // Update our local highest epoch
                    local_epoch = anchor.num;
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    eprintln!("⚠️  Sync lagged {n} anchors behind; resetting cursor");
                    local_epoch =
                        db.get::<Anchor>("epoch", b"latest").map_or(0, |a| a.num);
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });
}