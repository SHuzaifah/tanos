//! # tanos-core
//!
//! Identity, cryptography, and wire format primitives for the TanOS
//! decentralized mesh network.
//!
//! This crate is intentionally **synchronous** and contains zero async code.
//! All I/O (network, advanced filesystem) belongs in `tanos-net`.

pub mod crypto;
pub mod identity;

use serde::{Deserialize, Serialize};

// ─── Serde helpers for fixed-size byte arrays ────────────────────────────
// serde only supports arrays up to [T; 32] natively. For [u8; 64] we use
// a custom module that hex-encodes/decodes the bytes in JSON.

mod serde_bytes_64 {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "expected 64 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

// ─── Wire Formats ────────────────────────────────────────────────────────

/// Broadcast over UDP every 5 seconds to announce presence on the mesh.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryBeacon {
    /// Short node identifier: hex of first 8 bytes of the Ed25519 public key.
    pub node_id: String,
    /// Full 32-byte Ed25519 public key.
    pub public_key: [u8; 32],
    /// TCP port the node is listening on for messages (default 7701).
    pub listen_port: u16,
    /// Number of hops this beacon has travelled (starts at 0).
    pub hop_count: u8,
    /// Unix timestamp in milliseconds when the beacon was created.
    pub timestamp: u64,
    /// Ed25519 signature over all fields above.
    #[serde(with = "serde_bytes_64")]
    pub signature: [u8; 64],
}

/// Sent over TCP for encrypted node-to-node communication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TanMessage {
    /// UUID v4 identifier for deduplication.
    pub id: String,
    /// Sender's short node ID.
    pub from_id: String,
    /// Destination node's short node ID.
    pub to_id: String,
    /// Encrypted payload (ChaCha20-Poly1305 ciphertext).
    pub payload: Vec<u8>,
    /// X25519 ephemeral public key used for this message's ECDH.
    pub ephemeral_pubkey: [u8; 32],
    /// 12-byte nonce used for ChaCha20-Poly1305.
    pub nonce: [u8; 12],
    /// Time-to-live: max 5, decremented each hop. Dropped at 0.
    pub ttl: u8,
    /// Ed25519 signature over the encrypted payload.
    #[serde(with = "serde_bytes_64")]
    pub signature: [u8; 64],
}

// ─── Beacon Construction & Verification ──────────────────────────────────

impl DiscoveryBeacon {
    /// Build the canonical byte representation used for signing / verification.
    /// Covers every field except `signature` itself.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.node_id.as_bytes());
        buf.extend_from_slice(&self.public_key);
        buf.extend_from_slice(&self.listen_port.to_le_bytes());
        buf.push(self.hop_count);
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf
    }

    /// Create a signed beacon from the node's identity.
    pub fn new_signed(identity: &identity::NodeIdentity, listen_port: u16) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let mut beacon = Self {
            node_id: identity.node_id.clone(),
            public_key: identity.public_key_bytes(),
            listen_port,
            hop_count: 0,
            timestamp,
            signature: [0u8; 64],
        };

        beacon.signature = crypto::sign(&identity.signing_key, &beacon.signable_bytes());
        beacon
    }

    /// Verify the beacon's Ed25519 signature.
    pub fn verify_signature(&self) -> anyhow::Result<()> {
        let vk = crypto::verifying_key_from_bytes(&self.public_key)?;
        crypto::verify(&vk, &self.signable_bytes(), &self.signature)
    }
}

impl TanMessage {
    /// Build the canonical byte representation used for signing / verification.
    /// Signs over the encrypted payload (not plaintext).
    pub fn signable_bytes(&self) -> Vec<u8> {
        self.payload.clone()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beacon_sign_and_verify() {
        let id = identity::NodeIdentity::generate();
        let beacon = DiscoveryBeacon::new_signed(&id, 7701);
        assert!(beacon.verify_signature().is_ok());
    }

    #[test]
    fn beacon_tampered_fails_verify() {
        let id = identity::NodeIdentity::generate();
        let mut beacon = DiscoveryBeacon::new_signed(&id, 7701);
        beacon.hop_count = 99; // tamper
        assert!(beacon.verify_signature().is_err());
    }

    #[test]
    fn beacon_serialization_roundtrip() {
        let id = identity::NodeIdentity::generate();
        let beacon = DiscoveryBeacon::new_signed(&id, 7701);
        let json = serde_json::to_string(&beacon).expect("serialize");
        let restored: DiscoveryBeacon = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(beacon.node_id, restored.node_id);
        assert_eq!(beacon.signature, restored.signature);
    }
}
