# TanOS PRD

## Product Overview
TanOS is a decentralized peer-to-peer mesh networking platform where every device running TanOS becomes a node in a self-healing mesh network that works without any ISP, router, or central server.

## Features
- Decentralized P2P mesh network
- Discovery over UDP on port 7700
- Transport over TCP on port 7701
- Peer Table and Routing
- Identity generation using Ed25519 keypairs
- End-to-end encryption using X25519 ECDH + ChaCha20-Poly1305 AEAD
- CLI interface to manage node (start, view peers, send messages, view routes)
- Docker support for testing a 5-node mesh

## Architecture
- **tanos-node**: Binary entry point and CLI, wires everything together.
- **tanos-core**: Handles Identity (Ed25519), Crypto (X25519 + ChaCha20-Poly), and Wire Formats.
- **tanos-net**: Handles Discovery, Transport, Peer Table, Routing, and Auto-Hello.

## Use Cases
1. Start the mesh node locally or in Docker.
2. View Node ID and public key.
3. Print current peer table.
4. Send encrypted messages to other peers.
5. Print routing table.
