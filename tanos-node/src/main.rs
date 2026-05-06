//! TanOS Node — binary entry point.
//!
//! Wires together `tanos-core` (identity, crypto) and `tanos-net` (networking),
//! persists state to a local SQLite database, and serves a web dashboard.

mod cli;
mod db;
mod web;
mod setup;

use setup::run_setup_gui;
use std::sync::Arc;
use std::collections::HashMap;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{error, info, warn, debug};

use tanos_core::{identity, GossipPacket, DiscoveryBeacon, InnerMessage, TanMessage};
use tanos_net::{create_engine, NetworkEvent};
use tokio::sync::Mutex;

#[derive(Debug, Clone, PartialEq)]
pub enum PeerStatus {
    PendingUs,   // They want to connect — waiting for OUR approval
    PendingThem, // We want to connect — waiting for THEIR approval
    Approved,    // Both sides approved — encrypted tunnel active
}

impl PeerStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            PeerStatus::PendingUs => "pending_us",
            PeerStatus::PendingThem => "pending_them",
            PeerStatus::Approved => "approved",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "pending_us" => PeerStatus::PendingUs,
            "approved" => PeerStatus::Approved,
            _ => PeerStatus::PendingThem,
        }
    }
}

pub struct PeerInfo {
    pub status: PeerStatus,
    pub friendly_name: String,
    pub beacon: DiscoveryBeacon,
}

pub type PeerTable = Arc<Mutex<HashMap<String, PeerInfo>>>;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = cli::Cli::parse();
    let command = cli.command.unwrap_or(cli::Commands::Start);

    let (identity, just_setup) = if tanos_core::identity::identity_exists().unwrap_or(false) {
        (Arc::new(
            tokio::task::spawn_blocking(identity::load_identity)
                .await
                .context("identity task panicked")?
                .context("failed to load identity")?,
        ), false)
    } else {
        // Run setup GUI
        (run_setup_gui().await?, true)
    };

    match command {
        cli::Commands::Start => run_node(identity, just_setup).await,
        cli::Commands::Id => {
            println!("TanID:       {}", identity.tan_id);
            println!("Name:        {}", identity.friendly_name.lock().unwrap());
            println!("Public Key:  {}", hex::encode(identity.public_key_bytes()));
            Ok(())
        }
        cli::Commands::Peers => send_local_api("GET", "/api/peers", None).await,
        cli::Commands::Send { id, msg } => {
            let message = msg.join(" ");
            let body = serde_json::json!({ "tan_id": id, "message": message });
            send_local_api("POST", "/api/send", Some(body.to_string())).await
        }
        cli::Commands::Route => send_local_api("GET", "/api/peers", None).await,
        cli::Commands::Approve { id } => {
            let body = serde_json::json!({ "tan_id": id });
            send_local_api("POST", "/api/approve", Some(body.to_string())).await
        }
    }
}

async fn run_node(identity: Arc<identity::NodeIdentity>, just_setup: bool) -> Result<()> {
    let web_port: u16 = std::env::var("TANOS_PORT")
        .unwrap_or_else(|_| "7700".to_string())
        .parse()
        .unwrap_or(7700);

    // Open sovereign database
    let data_dir = identity::identity_dir()?;
    let database = db::open_db(&data_dir)?;
    info!(
        tan_id = %identity.tan_id,
        name = %identity.friendly_name.lock().unwrap(),
        db = ?data_dir.join("tanos.db"),
        "🌐 TanOS node starting"
    );

    let (engine, msg_tx, mut event_rx) = create_engine(identity.clone())?;

    // Restore peer table from DB (beacons will be re-populated from the mesh)
    let peer_table: PeerTable = Arc::new(Mutex::new(HashMap::new()));

    let shutdown = Arc::new(tokio::sync::Notify::new());
    let shutdown_signal = shutdown.clone();

    // Ctrl+C handler
    tokio::spawn(async move {
        if let Err(e) = tokio::signal::ctrl_c().await {
            error!(error = %e, "failed to listen for Ctrl+C");
        }
        info!("shutdown signal received, stopping node...");
        for _ in 0..10 { shutdown_signal.notify_one(); }
    });

    // Spawn libp2p engine
    let engine_task = tokio::spawn(async move {
        if let Err(e) = engine.run().await {
            error!("Network engine failed: {:?}", e);
        }
    });

    // Beacon broadcaster (every 5s)
    let beacon_tx = msg_tx.clone();
    let beacon_identity = identity.clone();
    let beacon_shutdown = shutdown.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = beacon_shutdown.notified() => break,
                _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                    let beacon = DiscoveryBeacon::new_signed(&beacon_identity, 7701);
                    let _ = beacon_tx.send(GossipPacket::Beacon { data: beacon }).await;
                }
            }
        }
    });

    // Web dashboard
    let web_state = web::AppState {
        identity: identity.clone(),
        peer_table: peer_table.clone(),
        database: database.clone(),
        msg_tx: msg_tx.clone(),
    };
    tokio::spawn(async move {
        // If we just ran setup, the browser is already open to localhost:7700
        // and waiting to be redirected to `/`, so we don't need to open another tab.
        web::start_web_server(web_state, web_port, !just_setup).await;
    });

    // ─── Main Event Loop ─────────────────────────────────────────────────
    loop {
        tokio::select! {
            _ = shutdown.notified() => break,
            Some(event) = event_rx.recv() => {
                match event {
                    NetworkEvent::PeerDiscovered(peer_id) => {
                        debug!("mDNS Peer discovered: {}", peer_id);
                    }
                    NetworkEvent::PeerExpired(peer_id) => {
                        debug!("mDNS Peer expired: {}", peer_id);
                    }
                    NetworkEvent::PacketReceived(packet) => {
                        match packet {
                            GossipPacket::Beacon { data: beacon } => {
                                if beacon.tan_id == identity.tan_id { continue; }
                                if beacon.verify_signature().is_err() { continue; }

                                let mut pt = peer_table.lock().await;
                                if !pt.contains_key(&beacon.tan_id) {
                                    // New peer! Check if we already know them from DB
                                    let db = database.lock().await;
                                    let db_peer = db.get_peer(&beacon.tan_id).ok().flatten();
                                    let db_status = db_peer.as_ref()
                                        .map(|p| PeerStatus::from_str(&p.status))
                                        .unwrap_or(PeerStatus::PendingThem);
                                    let mut db_name = db_peer.map(|p| p.friendly_name).unwrap_or_default();
                                    if db_name.is_empty() {
                                        db_name = beacon.friendly_name.clone();
                                    }
                                    drop(db);

                                    info!("🔍 Discovered peer: {} (name: {}, status: {:?})", beacon.tan_id, db_name, db_status);

                                    pt.insert(beacon.tan_id.clone(), PeerInfo {
                                        status: db_status.clone(),
                                        friendly_name: db_name,
                                        beacon: beacon.clone(),
                                    });

                                    // Always send a friend request so they know we exist
                                    let req = InnerMessage::FriendRequest {
                                        friendly_name: identity.friendly_name.lock().unwrap().clone(),
                                    };
                                    let _ = send_inner_message(&identity, &beacon, req, &msg_tx).await;

                                    // If we were already approved (from DB), also send approval
                                    if db_status == PeerStatus::Approved {
                                        let approval = InnerMessage::FriendApproval {
                                            friendly_name: identity.friendly_name.lock().unwrap().clone(),
                                        };
                                        let _ = send_inner_message(&identity, &beacon, approval, &msg_tx).await;
                                    }
                                } else {
                                    // Update beacon (keeps keys fresh) and name
                                    if let Some(p) = pt.get_mut(&beacon.tan_id) {
                                        p.beacon = beacon.clone();
                                        if !beacon.friendly_name.is_empty() {
                                            p.friendly_name = beacon.friendly_name.clone();
                                        }
                                    }
                                }
                            }
                            GossipPacket::Message { data: tan_msg } => {
                                if tan_msg.to_id != identity.tan_id { continue; }

                                let secret = identity.secret_key_bytes();
                                let plaintext = match tanos_core::crypto::decrypt(
                                    &secret,
                                    &tan_msg.ephemeral_pubkey,
                                    &tan_msg.nonce,
                                    &tan_msg.payload,
                                ) {
                                    Ok(p) => p,
                                    Err(_) => continue,
                                };

                                let inner = match serde_json::from_slice::<InnerMessage>(&plaintext) {
                                    Ok(i) => i,
                                    Err(_) => continue,
                                };

                                let mut pt = peer_table.lock().await;
                                match inner {
                                    InnerMessage::FriendRequest { friendly_name } => {
                                        if let Some(p) = pt.get_mut(&tan_msg.from_id) {
                                            p.friendly_name = friendly_name.clone();
                                            
                                            // STRICT MUTUAL APPROVAL:
                                            // If WE already approved them (from UI), auto-complete the handshake.
                                            // Otherwise, mark as "pending_us" — user must click Approve.
                                            if p.status == PeerStatus::Approved {
                                                info!("🤝 {} ({}) reconnected — tunnel re-established.", friendly_name, tan_msg.from_id);
                                                let approval = InnerMessage::FriendApproval {
                                                    friendly_name: identity.friendly_name.lock().unwrap().clone(),
                                                };
                                                let _ = send_inner_message(&identity, &p.beacon.clone(), approval, &msg_tx).await;
                                            } else if p.status != PeerStatus::PendingUs {
                                                info!("📨 Friend Request from {} ({}) — approve in dashboard.", friendly_name, tan_msg.from_id);
                                                p.status = PeerStatus::PendingUs;
                                                let db = database.lock().await;
                                                let _ = db.upsert_peer(&tan_msg.from_id, &friendly_name, "pending_us");
                                            }
                                        }
                                    }
                                    InnerMessage::FriendApproval { friendly_name } => {
                                        info!("✅ {} approved your request! Tunnel established.", friendly_name);
                                        if let Some(p) = pt.get_mut(&tan_msg.from_id) {
                                            p.status = PeerStatus::Approved;
                                            p.friendly_name = friendly_name.clone();
                                            let db = database.lock().await;
                                            let _ = db.upsert_peer(&tan_msg.from_id, &friendly_name, "approved");
                                        }
                                    }
                                    InnerMessage::Text(t) => {
                                        if let Some(p) = pt.get(&tan_msg.from_id) {
                                            if p.status == PeerStatus::Approved {
                                                info!("💬 {}: {}", tan_msg.from_id, t);
                                                let db = database.lock().await;
                                                let _ = db.save_message(&tan_msg.from_id, &t, "received");
                                            } else {
                                                warn!("Blocked message from unapproved peer {}", tan_msg.from_id);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    engine_task.abort();
    info!("TanOS node shut down cleanly");
    Ok(())
}

// ─── Shared Helper ───────────────────────────────────────────────────────

pub async fn send_inner_message(
    identity: &identity::NodeIdentity,
    recipient: &DiscoveryBeacon,
    inner: InnerMessage,
    msg_tx: &tokio::sync::mpsc::Sender<GossipPacket>,
) -> Result<()> {
    let payload = serde_json::to_vec(&inner)?;
    let encrypted = tanos_core::crypto::encrypt(&recipient.encryption_pubkey, &payload)?;
    let sig = tanos_core::crypto::sign(&identity.signing_key, &encrypted.ciphertext);

    let tan_msg = TanMessage {
        id: uuid::Uuid::new_v4().to_string(),
        from_id: identity.tan_id.clone(),
        to_id: recipient.tan_id.clone(),
        payload: encrypted.ciphertext,
        ephemeral_pubkey: encrypted.ephemeral_pubkey,
        nonce: encrypted.nonce,
        ttl: 5,
        signature: sig,
    };

    msg_tx.send(GossipPacket::Message { data: tan_msg }).await?;
    Ok(())
}

// ─── CLI Helper ──────────────────────────────────────────────────────────

async fn send_local_api(method: &str, path: &str, body: Option<String>) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let port = std::env::var("TANOS_PORT").unwrap_or_else(|_| "7700".to_string());
    let addr = format!("127.0.0.1:{}", port);
    let mut stream = tokio::net::TcpStream::connect(&addr).await
        .context(format!("Failed to connect on port {}. Is `tanos-node start` running?", port))?;
    let content = body.unwrap_or_default();
    let request = format!(
        "{} {} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        method, path, content.len(), content
    );
    stream.write_all(request.as_bytes()).await?;
    let mut resp = String::new();
    stream.read_to_string(&mut resp).await?;
    if let Some(body_start) = resp.find("\r\n\r\n") {
        println!("{}", &resp[body_start + 4..]);
    } else {
        println!("{}", resp);
    }
    Ok(())
}
