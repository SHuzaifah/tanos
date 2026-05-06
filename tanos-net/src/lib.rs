//! # tanos-net
//!
//! Networking layer for TanOS: UDP discovery, TCP transport, and peer management.
//! Now powered by libp2p.

pub mod network;

pub use network::{create_engine, NetworkEngine, NetworkEvent};
