use crate::{storage::Store, epoch::Anchor, network::NetHandle};
use std::sync::Arc;
use tokio::{sync::broadcast::Receiver, task};

pub fn spawn(db: Arc<Store>, net: NetHandle) {
    let mut anchor_rx: Receiver<Anchor> = net.anchor_subscribe();

    task::spawn(async move {
        let mut local_epoch = db.get::<Anchor>("epoch", b"latest").unwrap_or_default().map_or(0, |a| a.num);

        loop {
            match anchor_rx.recv().await {
                Ok(anchor) => {
                    let current_best = db.get::<Anchor>("epoch", b"latest").unwrap_or_default();
                    
                    let should_accept = match current_best {
                        Some(best) => anchor.cumulative_work > best.cumulative_work ||
                                      (anchor.cumulative_work == best.cumulative_work && anchor.num > best.num),
                        None => true,
                    };

                    if should_accept {
                        if anchor.num > local_epoch + 1 {
                            println!("⛓️  Syncing: behind by {} epochs. Requesting missing ones.", anchor.num.saturating_sub(local_epoch + 1));
                            for missing in (local_epoch + 1)..anchor.num {
                                net.request_epoch(missing).await;
                            }
                        }
                        local_epoch = anchor.num;
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    eprintln!("⚠️  Sync lagged {n} anchors behind; re-checking latest from DB.");
                    local_epoch = db.get::<Anchor>("epoch", b"latest").unwrap_or_default().map_or(0, |a| a.num);
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });
}