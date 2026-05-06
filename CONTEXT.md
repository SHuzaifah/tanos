# TanOS — Decentralized Peer-to-Peer Mesh Networking

> Every device running TanOS becomes a node in a self-healing mesh network
> that works without any ISP, router, or central server.

## Architecture

```
┌─────────────────────────────────────────────────┐
│                   tanos-node                     │
│          Binary entry point + CLI (clap)         │
│     Wires everything together, no biz logic      │
├────────────────────┬────────────────────────────┤
│     tanos-core     │         tanos-net           │
│  Identity (Ed25519)│  Discovery (UDP 7700)       │
│  Crypto (X25519 +  │  Transport (TCP 7701)       │
│   ChaCha20-Poly)   │  Peer Table + Routing       │
│  Wire Formats      │  Auto-Hello on Discovery    │
└────────────────────┴────────────────────────────┘
```

## Quick Start

### Local (single node)
```bash
cargo run -p tanos-node -- start
```

### CLI Commands
```bash
tanos-node start          # Start the mesh node
tanos-TanID             # Print node ID and public key
tanos-node peers          # Print current peer table
tanos-node send <id> msg  # Send encrypted message
tanos-node route          # Print routing table
```

## Wire Formats

### DiscoveryBeacon (UDP)
Broadcast every 5s. Fields: `tan_id`, `public_key`, `listen_port`,
`hop_count`, `timestamp`, `signature`.

### TanMessage (TCP)
Encrypted E2E. Fields: `id`, `from_id`, `to_id`, `payload`,
`ephemeral_pubkey`, `nonce`, `ttl`, `signature`.

## Security Model
- **Identity**: Ed25519 keypair persisted at `~/.tanos/identity.key`
- **Signing**: All beacons and messages are Ed25519-signed
- **Encryption**: X25519 ECDH + ChaCha20-Poly1305 AEAD per message
- **Ephemeral keys**: Fresh X25519 keypair per message (forward secrecy)

## Code Quality
- No `unwrap()` — all errors use `anyhow::Result<T>`
- No blocking in async — `tokio::fs` or `spawn_blocking` where needed
- All crypto in `tanos-core`, all I/O in `tanos-net`
- Comprehensive unit tests for all crypto functions
