use crate::{storage::Store, epoch::Anchor, coin::Coin, transfer::Transfer};
use libp2p::{
    gossipsub,
    identity, quic, swarm::SwarmEvent, PeerId, Swarm, Transport, Multiaddr,
    futures::StreamExt, core::muxing::StreamMuxerBox,
};
use libp2p::gossipsub::{
    IdentTopic, MessageAuthenticity, IdentityTransform,
    AllowAllSubscriptionFilter, Behaviour as Gossipsub, Event as GossipsubEvent,
};
use bincode;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};

// Topics are versioned for future protocol upgrades.
const TOP_ANCHOR: &str = "anchor/1";
const TOP_COIN:   &str = "coin/1";
const TOP_TX:     &str = "tx/1";
const TOP_EPOCH_REQUEST: &str = "epoch_request/1";
const TOP_COIN_REQUEST: &str = "coin_request/1";

#[derive(Clone)]
pub struct Network {
    anchor_tx: broadcast::Sender<Anchor>,
    command_tx: mpsc::UnboundedSender<NetworkCommand>,
}

#[derive(Debug)]
enum NetworkCommand {
    GossipAnchor(Anchor),
    GossipCoin(Coin),
    RequestEpoch(u64),
    RequestCoin([u8; 32]),
}
pub type NetHandle = Arc<Network>;

pub async fn spawn(cfg: crate::config::Net, db: Arc<Store>) -> anyhow::Result<NetHandle> {
    let id_keys = identity::Keypair::generate_ed25519();
    let peer_id = PeerId::from(id_keys.public());

    // NOTE: The libp2p transport here (QUIC) uses standard crypto and is NOT post-quantum safe.
    // For true PQ resistance, a PQ KEM like Kyber must be integrated into the handshake,
    // e.g., via the Noise protocol framework. This is a major undertaking.
    let transport = quic::tokio::Transport::new(quic::Config::new(&id_keys))
        .map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer)))
        .boxed();

    let mut gs: Gossipsub<IdentityTransform, AllowAllSubscriptionFilter> = Gossipsub::new(
        MessageAuthenticity::Signed(id_keys.clone()),
        gossipsub::Config::default(),
    ).map_err(|e| anyhow::anyhow!("Failed to create Gossipsub: {}", e))?;
    for t in [TOP_ANCHOR, TOP_COIN, TOP_TX, TOP_EPOCH_REQUEST, TOP_COIN_REQUEST] {
        gs.subscribe(&IdentTopic::new(t))?;
    }

    let mut swarm = Swarm::new(transport, gs, peer_id, libp2p::swarm::Config::with_tokio_executor());
    swarm.listen_on(format!("/ip4/0.0.0.0/udp/{}/quic-v1", cfg.listen_port).parse()?)?;
    for addr in &cfg.bootstrap {
        swarm.dial(addr.parse::<Multiaddr>()?)?;
    }

    let (anchor_tx, _) = broadcast::channel(32);
    let (command_tx, mut command_rx) = mpsc::unbounded_channel();
    
    let net = Arc::new(Network{ anchor_tx: anchor_tx.clone(), command_tx });

    tokio::spawn(async move {
        loop {
            tokio::select! {
                event = swarm.select_next_some() => {
                    if let SwarmEvent::Behaviour(GossipsubEvent::Message { message, .. }) = event {
                        match message.topic.as_str() {
                            TOP_ANCHOR => if let Ok(a) = bincode::deserialize::<Anchor>(&message.data) {
                                if db.put("epoch", &a.num.to_le_bytes(), &a).is_ok() {
                                    let _ = db.put("epoch", b"latest", &a);
                                    let _ = anchor_tx.send(a);
                                }
                            },
                            TOP_COIN => if let Ok(c) = bincode::deserialize::<Coin>(&message.data) {
                                // TODO: Full coin validation before storing!
                                let _ = db.put("coin", &c.id, &c);
                            },
                            TOP_TX => if let Ok(t) = bincode::deserialize::<Transfer>(&message.data) {
                                // TODO: Full transfer validation!
                                let _ = db.put("head", &t.coin_id, &t);
                            },
                            TOP_COIN_REQUEST => if let Ok(id) = bincode::deserialize::<[u8; 32]>(&message.data) {
                                if let Ok(Some(coin)) = db.get::<Coin>("coin", &id) {
                                    if let Ok(bytes) = bincode::serialize(&coin) {
                                        let _ = swarm.behaviour_mut().publish(IdentTopic::new(TOP_COIN), bytes);
                                    }
                                }
                            },
                            TOP_EPOCH_REQUEST => if let Ok(num) = bincode::deserialize::<u64>(&message.data) {
                                if let Ok(Some(anchor)) = db.get::<Anchor>("epoch", &num.to_le_bytes()) {
                                    if let Ok(bytes) = bincode::serialize(&anchor) {
                                        let _ = swarm.behaviour_mut().publish(IdentTopic::new(TOP_ANCHOR), bytes);
                                    }
                                }
                            },
                            _ => {}
                        }
                    }
                },
                Some(command) = command_rx.recv() => {
                    let (topic, data) = match command {
                        NetworkCommand::GossipAnchor(a) => (TOP_ANCHOR, bincode::serialize(&a).ok()),
                        NetworkCommand::GossipCoin(c) => (TOP_COIN, bincode::serialize(&c).ok()),
                        NetworkCommand::RequestEpoch(n) => (TOP_EPOCH_REQUEST, bincode::serialize(&n).ok()),
                        NetworkCommand::RequestCoin(id) => (TOP_COIN_REQUEST, bincode::serialize(&id).ok()),
                    };
                    if let Some(d) = data {
                        let _ = swarm.behaviour_mut().publish(IdentTopic::new(topic), d);
                    }
                }
            }
        }
    });
    Ok(net)
}

impl Network {
    pub async fn gossip_anchor(&self, a: &Anchor) { let _ = self.command_tx.send(NetworkCommand::GossipAnchor(a.clone())); }
    pub async fn gossip_coin(&self, c: &Coin) { let _ = self.command_tx.send(NetworkCommand::GossipCoin(c.clone())); }
    pub fn anchor_subscribe(&self) -> broadcast::Receiver<Anchor> { self.anchor_tx.subscribe() }
    pub async fn request_epoch(&self, n: u64) { let _ = self.command_tx.send(NetworkCommand::RequestEpoch(n)); }
    
}