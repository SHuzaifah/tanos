//! UDP discovery: beacon broadcast and listener.
//!
//! Every 5 seconds the node broadcasts a signed `DiscoveryBeacon` on UDP port
//! 7700. Incoming beacons are verified, added to the peer table, and optionally
//! re-broadcast with an incremented hop count (up to 3 hops) so that nodes not
//! in direct radio/WiFi range can still discover each other.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tracing::{debug, info, warn};

use tanos_core::identity::NodeIdentity;
use tanos_core::DiscoveryBeacon;

use crate::peers::PeerTable;

/// Default UDP port for discovery beacons.
pub const DISCOVERY_PORT: u16 = 7700;

/// How often we broadcast our own beacon.
const BEACON_INTERVAL: Duration = Duration::from_secs(5);

/// Maximum number of hops a re-broadcast beacon may travel.
const MAX_HOP_COUNT: u8 = 3;

/// Maximum size of a single UDP datagram we'll accept.
const MAX_DATAGRAM: usize = 4096;

/// Run the discovery subsystem (broadcast + listener) until `shutdown` fires.
pub async fn run(
    identity: Arc<NodeIdentity>,
    peer_table: Arc<PeerTable>,
    tcp_port: u16,
    shutdown: Arc<Notify>,
) -> Result<()> {
    let socket = UdpSocket::bind(("0.0.0.0", DISCOVERY_PORT))
        .await
        .context("failed to bind UDP discovery socket")?;

    socket
        .set_broadcast(true)
        .context("failed to enable broadcast on discovery socket")?;

    info!(
        port = DISCOVERY_PORT,
        "discovery listener started on UDP port"
    );

    let send_socket = Arc::new(socket);
    let recv_socket = send_socket.clone();

    // Spawn broadcast loop
    let bc_identity = identity.clone();
    let bc_socket = send_socket.clone();
    let bc_shutdown = shutdown.clone();
    let bc_peer_table = peer_table.clone();
    let broadcast_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = bc_shutdown.notified() => {
                    debug!("discovery broadcaster shutting down");
                    return;
                }
                _ = tokio::time::sleep(BEACON_INTERVAL) => {
                    if let Err(e) = broadcast_beacon(&bc_identity, &bc_socket, tcp_port, &bc_peer_table).await {
                        warn!(error = %e, "failed to broadcast beacon");
                    }
                }
            }
        }
    });

    // Spawn listen loop
    let listen_identity = identity.clone();
    let listen_peer_table = peer_table.clone();
    let listen_socket = recv_socket;
    let listen_shutdown = shutdown.clone();
    let listen_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            tokio::select! {
                _ = listen_shutdown.notified() => {
                    debug!("discovery listener shutting down");
                    return;
                }
                result = listen_socket.recv_from(&mut buf) => {
                    match result {
                        Ok((len, src_addr)) => {
                            if let Err(e) = handle_beacon(
                                &buf[..len],
                                src_addr,
                                &listen_identity,
                                &listen_peer_table,
                                &listen_socket,
                            ).await {
                                debug!(error = %e, "ignoring invalid beacon");
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, "UDP recv error");
                        }
                    }
                }
            }
        }
    });

    // Wait for both loops
    let _ = tokio::join!(broadcast_handle, listen_handle);
    Ok(())
}

/// Broadcast our own signed beacon to 255.255.255.255 and unicast to known peers.
async fn broadcast_beacon(
    identity: &NodeIdentity,
    socket: &UdpSocket,
    tcp_port: u16,
    peer_table: &PeerTable,
) -> Result<()> {
    let beacon = DiscoveryBeacon::new_signed(identity, tcp_port);
    let payload = serde_json::to_vec(&beacon).context("failed to serialize beacon")?;

    // 1. Send global broadcast
    let dest: SocketAddr = ([255, 255, 255, 255], DISCOVERY_PORT).into();
    let _ = socket.send_to(&payload, dest).await;

    // 2. Unicast directly to all known peers (bypasses Android Wi-Fi broadcast drops)
    for peer in peer_table.snapshot_peers() {
        let mut peer_udp_addr = peer.addr;
        peer_udp_addr.set_port(DISCOVERY_PORT);
        let _ = socket.send_to(&payload, peer_udp_addr).await;
    }

    debug!(node_id = %beacon.node_id, "broadcast discovery beacon");
    Ok(())
}

/// Process an incoming beacon datagram.
async fn handle_beacon(
    data: &[u8],
    src_addr: SocketAddr,
    our_identity: &NodeIdentity,
    peer_table: &PeerTable,
    socket: &UdpSocket,
) -> Result<()> {
    let beacon: DiscoveryBeacon =
        serde_json::from_slice(data).context("malformed beacon JSON")?;

    // Ignore our own beacons
    if beacon.node_id == our_identity.node_id {
        return Ok(());
    }

    // Cryptographic verification
    beacon
        .verify_signature()
        .context("beacon signature invalid")?;

    // Build the peer address (use source IP but the beacon's listen_port for TCP)
    let peer_addr = SocketAddr::new(src_addr.ip(), beacon.listen_port);

    // Add/update peer table
    let is_new = peer_table.upsert(&beacon, peer_addr);
    if is_new {
        info!(
            node_id = %beacon.node_id,
            addr = %peer_addr,
            hop_count = beacon.hop_count,
            "peer discovered"
        );
    }

    // Re-broadcast with incremented hop count (flood fill for multi-hop)
    if beacon.hop_count < MAX_HOP_COUNT {
        let mut relayed = beacon.clone();
        relayed.hop_count += 1;
        // We keep the original signature — downstream nodes verify against
        // the original signer's public key embedded in the beacon itself.
        if let Ok(payload) = serde_json::to_vec(&relayed) {
            let dest: SocketAddr = ([255, 255, 255, 255], DISCOVERY_PORT).into();
            let _ = socket.send_to(&payload, dest).await;
            debug!(
                node_id = %relayed.node_id,
                new_hop = relayed.hop_count,
                "re-broadcast beacon"
            );
        }
    }

    Ok(())
}
