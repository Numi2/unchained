use crate::{storage::Store, epoch::Anchor, coin::Coin, transfer::Transfer};
use libp2p::{
    identity, quic, swarm::SwarmEvent, PeerId, Swarm, Transport, Multiaddr,
    futures::StreamExt, core::muxing::StreamMuxerBox,
};
use libp2p_gossipsub::{
    self as gossipsub, IdentTopic, MessageAuthenticity, IdentityTransform,
    AllowAllSubscriptionFilter, Behaviour as Gossipsub, Event as GossipsubEvent,
};
use serde_json;
use std::sync::Arc;
use tokio::sync::broadcast;

// unchanged constants …
const TOP_ANCHOR: &str = "anchor";
const TOP_COIN:   &str = "coin";
const TOP_TX:     &str = "tx";
const TOP_COIN_REQUEST: &str = "coin_request";

pub struct Network {
    anchor_tx: broadcast::Sender<Anchor>,
    // Commands to send to the network task
    _command_tx: tokio::sync::mpsc::UnboundedSender<NetworkCommand>,
}

enum NetworkCommand {
    GossipAnchor(Anchor),
    GossipCoin(Coin),
    RequestEpoch(u64),
    RequestCoin([u8; 32]),
}
pub type NetHandle = Arc<Network>;

pub async fn spawn(cfg: crate::config::Net,
                   db: Arc<Store>) -> anyhow::Result<NetHandle>
{
    // identity
    let id_keys   = identity::Keypair::generate_ed25519();
    let peer_id   = PeerId::from(id_keys.public());

    // transport (QUIC + tokio executor baked in)  
    let transport = quic::tokio::Transport::new(quic::Config::new(&id_keys))
        .map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer)))
        .boxed();

    // gossipsub behaviour
    let mut gs: Gossipsub<IdentityTransform, AllowAllSubscriptionFilter> = Gossipsub::new(
        MessageAuthenticity::Signed(id_keys.clone()),
        gossipsub::Config::default(),
    ).map_err(|e| anyhow::anyhow!("Failed to create Gossipsub: {}", e))?;
    for t in [TOP_ANCHOR, TOP_COIN, TOP_TX, TOP_COIN_REQUEST] {
        gs.subscribe(&IdentTopic::new(t))?;
    }

    // build swarm
    let swarm_config = libp2p::swarm::Config::with_tokio_executor();
    let mut swarm = Swarm::new(transport, gs, peer_id, swarm_config);

    swarm.listen_on(format!("/ip4/0.0.0.0/udp/{}/quic-v1", cfg.listen_port).parse::<Multiaddr>()?)?;
    for addr in &cfg.bootstrap {
        swarm.dial(addr.parse::<Multiaddr>()?)?;
    }

    let (anchor_tx, _) = broadcast::channel(32);
    let (command_tx, command_rx) = tokio::sync::mpsc::unbounded_channel();
    
    let net = Arc::new(Network{ 
        anchor_tx: anchor_tx.clone(), 
        _command_tx: command_tx.clone(),
    });

    // network event loop
    {
        let db = db.clone();
        tokio::spawn(async move {
            let mut swarm = swarm;
            let mut command_rx = command_rx;
            
            loop {
                tokio::select! {
                    event = swarm.select_next_some() => {
                        if let SwarmEvent::Behaviour(GossipsubEvent::Message { message, .. }) = event {
                            match message.topic.as_str() {
                                TOP_ANCHOR => {
                                    if let Ok(a) = serde_json::from_slice::<Anchor>(&message.data) {
                                        db.put("epoch", &a.num.to_le_bytes(), &a);
                                        db.put("epoch", b"latest", &a);
                                        let _ = anchor_tx.send(a);
                                    }
                                }
                                TOP_COIN => {
                                    if let Ok(c) = serde_json::from_slice::<Coin>(&message.data) {
                                        db.put("coin", &c.id, &c);
                                    }
                                }  
                                TOP_TX => {
                                    if let Ok(t) = serde_json::from_slice::<Transfer>(&message.data) {
                                        db.put("head", &t.coin_id, &t);
                                    }
                                }
                                TOP_COIN_REQUEST => {
                                    if let Ok(coin_id) = serde_json::from_slice::<[u8; 32]>(&message.data) {
                                        // Check if we have this coin and serve it
                                        if let Some(coin) = db.get::<Coin>("coin", &coin_id) {
                                            let bytes = serde_json::to_vec(&coin).unwrap();
                                            let _ = swarm.behaviour_mut().publish(IdentTopic::new(TOP_COIN), bytes);
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    Some(command) = command_rx.recv() => {
                        match command {
                            NetworkCommand::GossipAnchor(a) => {
                                let bytes = serde_json::to_vec(&a).unwrap();
                                let _ = swarm.behaviour_mut().publish(IdentTopic::new(TOP_ANCHOR), bytes);
                            }
                            NetworkCommand::GossipCoin(c) => {
                                let bytes = serde_json::to_vec(&c).unwrap();
                                let _ = swarm.behaviour_mut().publish(IdentTopic::new(TOP_COIN), bytes);
                            }
                            NetworkCommand::RequestEpoch(n) => {
                                let ctrl = serde_json::to_vec(&n).unwrap();
                                let _ = swarm.behaviour_mut().publish(IdentTopic::new(TOP_ANCHOR), ctrl);
                            }
                            NetworkCommand::RequestCoin(coin_id) => {
                                let bytes = serde_json::to_vec(&coin_id).unwrap();
                                let _ = swarm.behaviour_mut().publish(IdentTopic::new(TOP_COIN_REQUEST), bytes);
                            }
                        }
                    }
                }
            }
        });
    }
    Ok(net)
}

/// -------- helper methods used by miner / sync / epoch ----------
impl Network {
    pub async fn gossip_anchor(&self, a: &Anchor) {
        let _ = self._command_tx.send(NetworkCommand::GossipAnchor(a.clone()));
    }
    pub async fn gossip_coin(&self, c: &Coin) {
        let _ = self._command_tx.send(NetworkCommand::GossipCoin(c.clone()));
    }
    pub fn anchor_subscribe(&self) -> broadcast::Receiver<Anchor> {
        self.anchor_tx.subscribe()
    }
    pub async fn request_epoch(&self, n: u64) {
        let _ = self._command_tx.send(NetworkCommand::RequestEpoch(n));
    }
    pub async fn request_coin(&self, coin_id: [u8; 32]) {
        let _ = self._command_tx.send(NetworkCommand::RequestCoin(coin_id));
    }
}