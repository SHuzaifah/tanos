//! TanOS Node — binary entry point.
//!
//! Wires together `tanos-core` (identity, crypto) and `tanos-net` (networking)
//! without containing any business logic itself.

mod cli;

use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{error, info};

use tanos_core::identity;
use tanos_net::{discovery, peers, transport};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = cli::Cli::parse();
    let command = cli.command.unwrap_or(cli::Commands::Start);

    // Load identity (blocking crypto + FS, done before async runtime is busy)
    let identity = Arc::new(
        tokio::task::spawn_blocking(identity::load_or_create_identity)
            .await
            .context("identity task panicked")?
            .context("failed to load or create identity")?,
    );

    match command {
        cli::Commands::Start => run_node(identity).await,
        cli::Commands::Id => {
            println!("Node ID:     {}", identity.node_id);
            println!("Public Key:  {}", hex::encode(identity.public_key_bytes()));
            Ok(())
        }
        cli::Commands::Peers => {
            send_local_command("PEERS\n").await
        }
        cli::Commands::Send { id, msg } => {
            let message = msg.join(" ");
            send_local_command(&format!("SEND {} {}\n", id, message)).await
        }
        cli::Commands::Route => {
            send_local_command("ROUTE\n").await
        }
    }
}

/// Main node execution: start all subsystems and run until interrupted.
async fn run_node(identity: Arc<identity::NodeIdentity>) -> Result<()> {
    info!(
        node_id = %identity.node_id,
        pubkey = %hex::encode(identity.public_key_bytes()),
        "🌐 TanOS node starting"
    );

    let peer_table = Arc::new(peers::PeerTable::new());
    let seen_messages = Arc::new(transport::SeenMessages::new());
    let shutdown = Arc::new(tokio::sync::Notify::new());

    // Set up Ctrl+C handler
    let shutdown_signal = shutdown.clone();
    tokio::spawn(async move {
        if let Err(e) = tokio::signal::ctrl_c().await {
            error!(error = %e, "failed to listen for Ctrl+C");
        }
        info!("shutdown signal received, stopping node...");
        // Notify all tasks multiple times since Notify wakes one waiter at a time
        for _ in 0..10 {
            shutdown_signal.notify_one();
        }
    });

    let tcp_port = transport::MESSAGE_PORT;

    // Clone references for each subsystem
    let disc_identity = identity.clone();
    let disc_peers = peer_table.clone();
    let disc_shutdown = shutdown.clone();

    let tcp_identity = identity.clone();
    let tcp_peers = peer_table.clone();
    let tcp_seen = seen_messages.clone();
    let tcp_shutdown = shutdown.clone();

    let prune_peers = peer_table.clone();
    let prune_shutdown = shutdown.clone();

    let hello_identity = identity.clone();
    let hello_peers = peer_table.clone();
    let hello_shutdown = shutdown.clone();

    // Launch all subsystems concurrently
    let (_disc_result, _tcp_result, _, _, _) = tokio::join!(
        // UDP discovery
        async move {
            if let Err(e) = discovery::run(disc_identity, disc_peers, tcp_port, disc_shutdown).await
            {
                error!(error = %e, "discovery subsystem failed");
            }
        },
        // TCP message listener
        async move {
            if let Err(e) = transport::listen(tcp_identity, tcp_peers, tcp_seen, tcp_shutdown).await
            {
                error!(error = %e, "TCP listener failed");
            }
        },
        // Peer pruner
        peers::run_pruner(prune_peers, prune_shutdown),
        // Auto-hello on new peer discovery
        run_auto_hello(hello_identity, hello_peers, hello_shutdown),
        // Local API server for CLI
        local_api_server(identity.clone(), peer_table.clone(), shutdown.clone()),
    );

    info!("TanOS node shut down cleanly");
    Ok(())
}

/// Periodically check for newly discovered peers and send them a hello message.
///
/// We keep our own set of peers we've already greeted. When a new peer appears
/// in the peer table that we haven't greeted yet, we send the auto-hello.
async fn run_auto_hello(
    identity: Arc<identity::NodeIdentity>,
    peer_table: Arc<peers::PeerTable>,
    shutdown: Arc<tokio::sync::Notify>,
) {
    use std::collections::HashSet;
    let mut greeted: HashSet<String> = HashSet::new();

    loop {
        tokio::select! {
            _ = shutdown.notified() => {
                return;
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {
                // Snapshot current peer IDs in a blocking context
                let pt = peer_table.clone();
                let current_peers = match tokio::task::spawn_blocking(move || pt.peer_ids()).await {
                    Ok(ids) => ids,
                    Err(_) => continue,
                };

                for peer_id in current_peers {
                    if greeted.contains(&peer_id) {
                        continue;
                    }
                    greeted.insert(peer_id.clone());

                    let hello_msg = format!(
                        "hello from {}, TanOS mesh node online",
                        identity.node_id
                    );

                    // Send in a blocking-aware context
                    let id = identity.clone();
                    let pt = peer_table.clone();
                    let pid = peer_id.clone();
                    let msg = hello_msg.clone();

                    tokio::spawn(async move {
                        // Small delay to let routing stabilize
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

                        // Get route in blocking context
                        let pt_clone = pt.clone();
                        let pid_clone = pid.clone();
                        let route = tokio::task::spawn_blocking(move || {
                            pt_clone.get_route(&pid_clone)
                        }).await;

                        let route = match route {
                            Ok(Some(r)) => r,
                            _ => {
                                tracing::debug!(peer = %pid, "no route yet for auto-hello, skipping");
                                return;
                            }
                        };

                        let pt_clone2 = pt.clone();
                        let pid_clone2 = pid.clone();
                        let peer_info = tokio::task::spawn_blocking(move || {
                            pt_clone2.get_peer(&pid_clone2)
                        }).await;

                        let peer_info = match peer_info {
                            Ok(Some(p)) => p,
                            _ => return,
                        };

                        // Encrypt and send
                        let recipient_x25519 = tanos_core::crypto::x25519_pubkey_from_secret(&peer_info.public_key);
                        match tanos_core::crypto::encrypt(&recipient_x25519, msg.as_bytes()) {
                            Ok(encrypted) => {
                                let sig = tanos_core::crypto::sign(&id.signing_key, &encrypted.ciphertext);
                                let tan_msg = tanos_core::TanMessage {
                                    id: uuid::Uuid::new_v4().to_string(),
                                    from_id: id.node_id.clone(),
                                    to_id: pid.clone(),
                                    payload: encrypted.ciphertext,
                                    ephemeral_pubkey: encrypted.ephemeral_pubkey,
                                    nonce: encrypted.nonce,
                                    ttl: 5,
                                    signature: sig,
                                };
                                if let Err(e) = transport::send_raw(&tan_msg, route.next_hop_addr).await {
                                    tracing::warn!(peer = %pid, error = %e, "failed to send auto-hello");
                                } else {
                                    info!(peer = %pid, "👋 sent auto-hello");
                                }
                            }
                            Err(e) => {
                                tracing::warn!(peer = %pid, error = %e, "failed to encrypt auto-hello");
                            }
                        }
                    });
                }
            }
        }
    }
}

async fn send_local_command(cmd: &str) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect("127.0.0.1:7702").await
        .context("Failed to connect to local node on port 7702. Is `tanos-node start` running?")?;
    stream.write_all(cmd.as_bytes()).await.context("Failed to send command")?;
    let mut resp = String::new();
    stream.read_to_string(&mut resp).await.context("Failed to read response")?;
    print!("{}", resp);
    Ok(())
}

async fn local_api_server(
    identity: Arc<identity::NodeIdentity>,
    peer_table: Arc<peers::PeerTable>,
    shutdown: Arc<tokio::sync::Notify>,
) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    let listener = match TcpListener::bind("127.0.0.1:7702").await {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to bind local API server on port 7702");
            return;
        }
    };

    loop {
        tokio::select! {
            _ = shutdown.notified() => return,
            result = listener.accept() => {
                if let Ok((mut socket, _)) = result {
                    let identity = identity.clone();
                    let peer_table = peer_table.clone();
                    tokio::spawn(async move {
                        let (reader, mut writer) = socket.split();
                        let mut reader = BufReader::new(reader);
                        let mut line = String::new();
                        if let Ok(n) = reader.read_line(&mut line).await {
                            if n == 0 { return; }
                            let line = line.trim();
                            if line == "PEERS" {
                                let peers = peer_table.snapshot_peers();
                                let mut out = String::new();
                                for p in peers {
                                    out.push_str(&format!("{} at {} (hop {})\n", p.node_id, p.addr, p.hop_count));
                                }
                                if out.is_empty() {
                                    out.push_str("No peers found.\n");
                                }
                                let _ = writer.write_all(out.as_bytes()).await;
                            } else if line == "ROUTE" {
                                let routes = peer_table.snapshot_routes();
                                let mut out = String::new();
                                for (dest, r) in routes {
                                    out.push_str(&format!("{} -> {} (hop {})\n", dest, r.next_hop_id, r.hop_count));
                                }
                                if out.is_empty() {
                                    out.push_str("No routes found.\n");
                                }
                                let _ = writer.write_all(out.as_bytes()).await;
                            } else if line.starts_with("SEND ") {
                                let rest = &line[5..];
                                if let Some((id, msg)) = rest.split_once(' ') {
                                    if let Err(e) = transport::send_message(&identity, &peer_table, id, msg.as_bytes()).await {
                                        let _ = writer.write_all(format!("Error: {}\n", e).as_bytes()).await;
                                    } else {
                                        let _ = writer.write_all(b"Message sent successfully.\n").await;
                                    }
                                } else {
                                    let _ = writer.write_all(b"Invalid SEND format.\n").await;
                                }
                            } else {
                                let _ = writer.write_all(b"Unknown command.\n").await;
                            }
                        }
                    });
                }
            }
        }
    }
}
