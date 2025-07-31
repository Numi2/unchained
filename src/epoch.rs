//! Epoch manager: collects freshly-mined coin IDs, rolls a new anchor
//! every `cfg.seconds` and gossips it to the network.

use crate::{storage::Store, network::NetHandle};
use tokio::{sync::{broadcast, mpsc}, time};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, sync::Arc};

#[derive(Clone, Serialize, Deserialize)]
pub struct Anchor {
    pub num:          u64,
    pub hash:         [u8; 32],
    pub difficulty:   usize,
    pub coin_count:   u32,
}

pub struct Manager {
    db:   Arc<Store>,
    cfg:  crate::config::Epoch,
    net:  NetHandle,
    tx:   broadcast::Sender<Anchor>,
    coin_rx: mpsc::UnboundedReceiver<[u8; 32]>,
}
impl Manager {
    pub fn new(db: Arc<Store>,
               cfg: crate::config::Epoch,
               net: NetHandle,
               coin_rx: mpsc::UnboundedReceiver<[u8; 32]>) -> Self
    {
        let (tx, _) = broadcast::channel(32);
        Self { db, cfg, net, tx, coin_rx }
    }
    /// Start the async task
    pub fn spawn(mut self) {
        tokio::spawn(async move {
            let mut current_epoch = self
                .db.get::<Anchor>("epoch", b"latest")
                .map_or(0, |a| a.num + 1);

            let mut buffer: HashSet<[u8; 32]> = HashSet::new();
            let mut ticker = time::interval(time::Duration::from_secs(self.cfg.seconds));

            loop {
                tokio::select! {
                    Some(id) = self.coin_rx.recv() => {
                        buffer.insert(id);
                    }
                    _ = ticker.tick() => {
                        // roll anchor
                        let mut h = blake3::Hasher::new();
                        for id in &buffer { h.update(id); }
                        if let Some(prev) = self.db.get::<Anchor>("epoch", &current_epoch.to_le_bytes()) {
                            h.update(&prev.hash);
                        }
                        let hash = *h.finalize().as_bytes();
                        let anchor = Anchor {
                            num: current_epoch,
                            hash,
                            difficulty: self.cfg.target_leading_zeros,
                            coin_count: buffer.len() as u32,
                        };
                        // store
                        self.db.put("epoch", &current_epoch.to_le_bytes(), &anchor);
                        self.db.put("epoch", b"latest", &anchor);
                        // broadcast
                        self.net.gossip_anchor(&anchor).await;
                        let _ = self.tx.send(anchor.clone());
                        // prepare next epoch
                        buffer.clear();
                        current_epoch += 1;
                    }
                }
            }
        });
    }
    pub fn subscribe(&self) -> broadcast::Receiver<Anchor> { self.tx.subscribe() }
}