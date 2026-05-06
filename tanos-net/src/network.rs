use anyhow::{Context, Result};
use futures::StreamExt;
use libp2p::{
    core::upgrade::Version,
    gossipsub, mdns, noise, swarm::NetworkBehaviour, swarm::SwarmEvent, tcp, yamux, PeerId, Swarm,
    Transport,
};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use tanos_core::identity::NodeIdentity;
use tanos_core::{GossipPacket, TanMessage};

#[derive(NetworkBehaviour)]
pub struct TanBehaviour {
    pub mdns: mdns::tokio::Behaviour,
    pub gossipsub: gossipsub::Behaviour,
}

pub struct NetworkEngine {
    swarm: Swarm<TanBehaviour>,
    msg_receiver: mpsc::Receiver<GossipPacket>,
    event_sender: mpsc::Sender<NetworkEvent>,
}

#[derive(Debug)]
pub enum NetworkEvent {
    PeerDiscovered(PeerId),
    PeerExpired(PeerId),
    PacketReceived(GossipPacket),
}

pub fn create_engine(
    identity: Arc<NodeIdentity>,
) -> Result<(NetworkEngine, mpsc::Sender<GossipPacket>, mpsc::Receiver<NetworkEvent>)> {
    // 1. Create a libp2p identity from our existing Ed25519 secret key
    let mut secret_key_bytes = identity.secret_key_bytes();
    let ed25519_secret = libp2p::identity::ed25519::SecretKey::try_from_bytes(&mut secret_key_bytes)
        .context("Failed to parse ed25519 secret key")?;
    let keypair = libp2p::identity::Keypair::from(libp2p::identity::ed25519::Keypair::from(ed25519_secret));
    
    let peer_id = PeerId::from(keypair.public());
    info!("Initializing libp2p engine. PeerId: {}", peer_id);

    let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair.clone())
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        ).map_err(|e| anyhow::anyhow!("tcp builder failed: {}", e))?
        .with_behaviour(|key| {
            let peer_id = PeerId::from(key.public());
            let mdns = mdns::tokio::Behaviour::new(
                mdns::Config::default(),
                peer_id,
            ).unwrap();

            let message_id_fn = |message: &gossipsub::Message| {
                let mut s = DefaultHasher::new();
                message.data.hash(&mut s);
                gossipsub::MessageId::from(s.finish().to_string())
            };

            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(1))
                .validation_mode(gossipsub::ValidationMode::Strict)
                .message_id_fn(message_id_fn)
                .build()
                .unwrap();

            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            ).unwrap();

            Ok(TanBehaviour { mdns, gossipsub })
        })
        .map_err(|e| anyhow::anyhow!("behaviour error: {:?}", e))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    let (msg_tx, msg_rx) = mpsc::channel(100);
    let (event_tx, event_rx) = mpsc::channel(100);

    let engine = NetworkEngine {
        swarm,
        msg_receiver: msg_rx,
        event_sender: event_tx,
    };

    Ok((engine, msg_tx, event_rx))
}

impl NetworkEngine {
    pub async fn run(mut self) -> Result<()> {
        // Listen on a random port to allow multiple nodes on one machine
        self.swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
        
        let topic = gossipsub::IdentTopic::new("tanos-mesh");
        self.swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

        info!("Network Engine running, subscribed to 'tanos-mesh'");

        loop {
            tokio::select! {
                // Outgoing messages from our node
                Some(packet) = self.msg_receiver.recv() => {
                    if let Ok(bytes) = serde_json::to_vec(&packet) {
                        match self.swarm.behaviour_mut().gossipsub.publish(topic.clone(), bytes) {
                            Ok(_) => {},
                            Err(libp2p::gossipsub::PublishError::NoPeersSubscribedToTopic) => {
                                // Ignore this - it just means we are the first one on the mesh
                            }
                            Err(e) => {
                                error!("Failed to publish packet: {:?}", e);
                            }
                        }
                    }
                }
                
                // Incoming libp2p swarm events
                event = self.swarm.select_next_some() => match event {
                    SwarmEvent::Behaviour(TanBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                        for (peer_id, multiaddr) in list {
                            debug!("mDNS discovered {} at {}", peer_id, multiaddr);
                            if let Err(e) = self.swarm.dial(multiaddr.clone()) {
                                debug!("Failed to dial {}: {:?}", peer_id, e);
                            }
                            self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                            let _ = self.event_sender.send(NetworkEvent::PeerDiscovered(peer_id)).await;
                        }
                    }
                    SwarmEvent::Behaviour(TanBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                        for (peer_id, _multiaddr) in list {
                            debug!("mDNS expired {}", peer_id);
                            self.swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                            let _ = self.event_sender.send(NetworkEvent::PeerExpired(peer_id)).await;
                        }
                    }
                    SwarmEvent::Behaviour(TanBehaviourEvent::Gossipsub(gossipsub::Event::Message { propagation_source: _, message_id: _, message })) => {
                        if let Ok(packet) = serde_json::from_slice::<GossipPacket>(&message.data) {
                            let _ = self.event_sender.send(NetworkEvent::PacketReceived(packet)).await;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}
