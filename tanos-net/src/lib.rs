//! # tanos-net
//!
//! Networking layer for TanOS: UDP discovery, TCP transport, and peer management.
//!
//! All async I/O and network code lives here. Crypto primitives are delegated
//! to `tanos-core`.

pub mod discovery;
pub mod peers;
pub mod transport;
