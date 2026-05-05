//! Peer table and routing table management.
//!
//! Maintains a map of known peers with their addresses, hop counts, public keys,
//! and last-seen timestamps. Provides routing decisions for multi-hop forwarding.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::Notify;
use tracing::debug;

use tanos_core::DiscoveryBeacon;

/// How long before a peer is considered stale and pruned.
const PEER_TIMEOUT: Duration = Duration::from_secs(30);

/// Interval between prune sweeps.
const PRUNE_INTERVAL: Duration = Duration::from_secs(10);

/// Information about a known peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub node_id: String,
    pub public_key: [u8; 32],
    pub encryption_pubkey: [u8; 32],
    pub addr: SocketAddr,
    pub hop_count: u8,
    pub last_seen: Instant,
}

/// Entry in the routing table — tells us where to forward messages for a given
/// destination node ID.
#[derive(Debug, Clone)]
pub struct RouteEntry {
    pub next_hop_id: String,
    pub next_hop_addr: SocketAddr,
    pub hop_count: u8,
    pub last_updated: Instant,
}

/// Thread-safe peer table with integrated routing.
pub struct PeerTable {
    peers: Mutex<HashMap<String, PeerInfo>>,
    routes: Mutex<HashMap<String, RouteEntry>>,
}

impl PeerTable {
    pub fn new() -> Self {
        Self {
            peers: Mutex::new(HashMap::new()),
            routes: Mutex::new(HashMap::new()),
        }
    }

    /// Insert or update a peer from a discovery beacon.
    /// Returns `true` if this is a newly discovered peer.
    pub fn upsert(&self, beacon: &DiscoveryBeacon, addr: SocketAddr) -> bool {
        let mut peers = self.peers.lock().unwrap();
        let mut routes = self.routes.lock().unwrap();

        let hop_count = beacon.hop_count + 1; // +1 because we received it one hop away
        let now = Instant::now();

        let is_new = !peers.contains_key(&beacon.node_id);

        // Update or insert peer info — prefer lower hop count
        let should_update = match peers.get(&beacon.node_id) {
            None => true,
            Some(existing) => hop_count < existing.hop_count,
        };

        if should_update || !is_new {
            peers.insert(
                beacon.node_id.clone(),
                PeerInfo {
                    node_id: beacon.node_id.clone(),
                    public_key: beacon.public_key,
                    encryption_pubkey: beacon.encryption_pubkey,
                    addr,
                    hop_count,
                    last_seen: now,
                },
            );
        }

        // Always refresh last_seen even if hop_count didn't improve
        if let Some(peer) = peers.get_mut(&beacon.node_id) {
            peer.last_seen = now;
        }

        // Update routing table — prefer shortest path
        let update_route = match routes.get(&beacon.node_id) {
            None => true,
            Some(existing) => hop_count < existing.hop_count,
        };

        if update_route {
            // For direct peers (hop_count == 1), next_hop is the peer itself
            // For relayed peers, next_hop is whoever gave us the beacon
            routes.insert(
                beacon.node_id.clone(),
                RouteEntry {
                    next_hop_id: beacon.node_id.clone(),
                    next_hop_addr: addr,
                    hop_count,
                    last_updated: now,
                },
            );
        }

        // Refresh route timestamp
        if let Some(route) = routes.get_mut(&beacon.node_id) {
            route.last_updated = now;
        }

        is_new
    }

    /// Look up routing info for a destination node.
    pub fn get_route(&self, dest_id: &str) -> Option<RouteEntry> {
        let routes = self.routes.lock().unwrap();
        routes.get(dest_id).cloned()
    }

    /// Look up peer info by node ID.
    pub fn get_peer(&self, node_id: &str) -> Option<PeerInfo> {
        let peers = self.peers.lock().unwrap();
        peers.get(node_id).cloned()
    }

    /// Get a snapshot of all known peers.
    pub fn snapshot_peers(&self) -> Vec<PeerInfo> {
        let peers = self.peers.lock().unwrap();
        peers.values().cloned().collect()
    }

    /// Get a snapshot of all routing entries.
    pub fn snapshot_routes(&self) -> Vec<(String, RouteEntry)> {
        let routes = self.routes.lock().unwrap();
        routes
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Get all peer node IDs (for sending auto-hello on new discovery).
    pub fn peer_ids(&self) -> Vec<String> {
        let peers = self.peers.lock().unwrap();
        peers.keys().cloned().collect()
    }

    /// Prune peers that haven't been seen within the timeout.
    pub fn prune_stale(&self) {
        let mut peers = self.peers.lock().unwrap();
        let mut routes = self.routes.lock().unwrap();
        let now = Instant::now();

        let stale_ids: Vec<String> = peers
            .iter()
            .filter(|(_, info)| now.duration_since(info.last_seen) > PEER_TIMEOUT)
            .map(|(id, _)| id.clone())
            .collect();

        for id in &stale_ids {
            peers.remove(id);
            routes.remove(id);
            debug!(node_id = %id, "pruned stale peer");
        }
    }
}

/// Run periodic prune sweeps until `shutdown` fires.
pub async fn run_pruner(peer_table: Arc<PeerTable>, shutdown: Arc<Notify>) {
    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                debug!("peer pruner shutting down");
                return;
            }
            _ = tokio::time::sleep(PRUNE_INTERVAL) => {
                // Run prune in a blocking context since we use blocking_lock
                let pt = peer_table.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    pt.prune_stale();
                }).await;
            }
        }
    }
}
