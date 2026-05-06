//! CLI definition using `clap`.

use clap::{Parser, Subcommand};

/// TanOS — Decentralized Peer-to-Peer Mesh Networking Node
#[derive(Parser, Debug)]
#[command(
    name = "tanos-node",
    version,
    about = "A self-healing mesh network node that works without any ISP, router, or central server."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Start the TanOS mesh node (default)
    Start,
    /// Print own node ID and public key
    Id,
    /// Print current peer table with hop counts
    Peers,
    /// Send an encrypted message to a node
    Send {
        /// Target node ID (hex string)
        id: String,
        /// Message to send
        #[arg(trailing_var_arg = true, num_args = 1..)]
        msg: Vec<String>,
    },
    /// Print the full routing table
    Route,
    /// Approve a pending Friend Request
    Approve {
        /// Target node ID to approve
        id: String,
    },
}
