use crate::{storage::Store, crypto, epoch::Anchor, coin::Coin, network::NetHandle};
use rand::Rng;
use std::sync::Arc;
use tokio::{sync::broadcast::Receiver, task};
use pqcrypto_traits::sign::PublicKey as PublicKeyTrait;

pub fn spawn(cfg: crate::config::Mining,
             db: Arc<Store>, 
             net: NetHandle,
             coin_tx: tokio::sync::mpsc::UnboundedSender<[u8; 32]>)     // new
{
    let mut rx: Receiver<Anchor> = net.anchor_subscribe();   // get epoch anchors
    task::spawn(async move {
        let (pk, _sk) = crypto::dilithium3_keypair(); // random creator key
        let mem = cfg.mem_kib; let lanes = cfg.lanes;
        loop {
            let anchor = rx.recv().await.unwrap();        // current epoch
            mine_epoch(anchor, mem, lanes, &pk, &db, &net, &coin_tx).await;
        }
    });
}

async fn mine_epoch(anchor: Anchor, mem: u32, lanes: u32,
                    pk: &pqcrypto_dilithium::dilithium3::PublicKey, 
                    db: &Arc<Store>, 
                    net: &NetHandle,
                    coin_tx: &tokio::sync::mpsc::UnboundedSender<[u8; 32]>) {
    loop {
        let nonce: u64 = rand::thread_rng().gen();
        let pk_bytes: [u8; 32] = pk.as_bytes().try_into().unwrap();
        let header = Coin::header(anchor.hash, nonce, pk_bytes);
        let h = crypto::argon2id_pow(&header, mem, lanes);
        if h.iter().take_while(|&&b| b==0).count() >= anchor.difficulty {
            let coin = Coin::assemble(header, h);
            db.put("coin", &coin.id, &coin);
            coin_tx.send(coin.id).ok();      // push id to epoch roller
            net.gossip_coin(&coin).await;    // broadcast to peers
            break;
        }
    }
}