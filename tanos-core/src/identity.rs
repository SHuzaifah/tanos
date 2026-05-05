//! Identity management: Ed25519 keypair generation, persistence, and node ID derivation.
//!
//! On first boot, a new Ed25519 signing keypair is generated and persisted to
//! `~/.tanos/identity.key`. On subsequent boots the stored keypair is loaded.
//! The node_id is the hex encoding of the first 8 bytes of the public key.

use anyhow::{Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::path::{Path, PathBuf};

/// Number of leading public key bytes used to derive the short node ID.
const NODE_ID_BYTES: usize = 8;

/// Wraps an Ed25519 signing keypair together with the derived short node ID.
#[derive(Debug)]
pub struct NodeIdentity {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    pub node_id: String,
}

impl NodeIdentity {
    /// Create a brand-new random identity.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let node_id = derive_node_id(&verifying_key);
        Self {
            signing_key,
            verifying_key,
            node_id,
        }
    }

    /// Reconstruct an identity from a raw 32-byte secret key.
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        let verifying_key = signing_key.verifying_key();
        let node_id = derive_node_id(&verifying_key);
        Self {
            signing_key,
            verifying_key,
            node_id,
        }
    }

    /// Return the full 32-byte public key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Return the raw 32-byte secret key (for persistence only).
    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

/// Derive the short node ID (hex of first 8 bytes of the public key).
pub fn derive_node_id(verifying_key: &VerifyingKey) -> String {
    hex::encode(&verifying_key.to_bytes()[..NODE_ID_BYTES])
}

/// Resolve the storage directory for identity data.
///
/// On Android / Termux the `HOME` env var points to app-specific storage.
/// Everywhere else we fall back to `~/.tanos`.
pub fn identity_dir() -> Result<PathBuf> {
    // Check for Termux-style path first
    if let Ok(home) = std::env::var("HOME") {
        let p = Path::new(&home);
        if p.join(".termux").exists() || home.contains("com.termux") {
            let dir = p.join(".tanos");
            return Ok(dir);
        }
    }

    // Standard desktop / server path
    let base = directories::BaseDirs::new().context("cannot determine home directory")?;
    Ok(base.home_dir().join(".tanos"))
}

/// Full path to the identity key file.
pub fn identity_file() -> Result<PathBuf> {
    Ok(identity_dir()?.join("identity.key"))
}

/// Load an existing identity from disk, or generate and persist a new one.
///
/// This is intentionally **synchronous** because it is a pure
/// filesystem + crypto operation with no network I/O. The caller
/// (in tanos-node) should invoke it *before* entering the async
/// runtime, or inside `spawn_blocking`.
pub fn load_or_create_identity() -> Result<NodeIdentity> {
    let path = identity_file()?;

    if path.exists() {
        let raw = std::fs::read(&path).context("failed to read identity file")?;
        if raw.len() != 32 {
            anyhow::bail!(
                "identity file has unexpected size {} (expected 32 bytes)",
                raw.len()
            );
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&raw);
        Ok(NodeIdentity::from_secret_bytes(&bytes))
    } else {
        let identity = NodeIdentity::generate();
        let dir = path
            .parent()
            .context("identity file has no parent directory")?;
        std::fs::create_dir_all(dir).context("failed to create identity directory")?;
        std::fs::write(&path, identity.secret_key_bytes())
            .context("failed to write identity file")?;
        Ok(identity)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_identity_produces_valid_node_id() {
        let id = NodeIdentity::generate();
        // node_id is hex of 8 bytes → 16 hex chars
        assert_eq!(id.node_id.len(), 16);
        assert!(hex::decode(&id.node_id).is_ok());
    }

    #[test]
    fn roundtrip_secret_bytes() {
        let original = NodeIdentity::generate();
        let restored = NodeIdentity::from_secret_bytes(&original.secret_key_bytes());
        assert_eq!(original.node_id, restored.node_id);
        assert_eq!(
            original.public_key_bytes(),
            restored.public_key_bytes()
        );
    }

    #[test]
    fn persist_and_reload_identity() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let key_path = tmp.path().join("identity.key");

        // Generate and save
        let id1 = NodeIdentity::generate();
        std::fs::write(&key_path, id1.secret_key_bytes()).expect("write");

        // Reload
        let raw = std::fs::read(&key_path).expect("read");
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&raw);
        let id2 = NodeIdentity::from_secret_bytes(&bytes);

        assert_eq!(id1.node_id, id2.node_id);
    }
}
