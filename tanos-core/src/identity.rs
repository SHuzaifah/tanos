//! Identity management: Ed25519 keypair generation, persistence, and node ID derivation.
//!
//! On first boot, a new Ed25519 signing keypair is generated and persisted to
//! `~/.tanos/identity.key`. On subsequent boots the stored keypair is loaded.
//! The tan_id is the hex encoding of the first 8 bytes of the public key.

use anyhow::{Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use std::path::{Path, PathBuf};

use std::sync::Mutex;

/// Number of leading public key bytes used to derive the short node ID.
const TAN_ID_BYTES: usize = 8;

/// Wraps an Ed25519 signing keypair together with the derived short node ID.
#[derive(Debug)]
pub struct NodeIdentity {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    pub tan_id: String,
    pub friendly_name: Mutex<String>,
}

impl NodeIdentity {
    /// Create a brand-new random identity.
    pub fn generate(friendly_name: Option<String>) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let tan_id = derive_tan_id(&verifying_key);
        Self {
            signing_key,
            verifying_key,
            tan_id: tan_id.clone(),
            friendly_name: Mutex::new(friendly_name.unwrap_or(format!("tan-{}", &tan_id[..4]))),
        }
    }

    /// Reconstruct an identity from a raw 32-byte secret key.
    pub fn from_secret_bytes(bytes: &[u8; 32], friendly_name: String) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        let verifying_key = signing_key.verifying_key();
        let tan_id = derive_tan_id(&verifying_key);
        Self {
            signing_key,
            verifying_key,
            tan_id,
            friendly_name: Mutex::new(friendly_name),
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
pub fn derive_tan_id(verifying_key: &VerifyingKey) -> String {
    hex::encode(&verifying_key.to_bytes()[..TAN_ID_BYTES])
}

/// Resolve the storage directory for identity data.
///
/// On Android / Termux the `HOME` env var points to app-specific storage.
/// Everywhere else we fall back to `~/.tanos`.
pub fn identity_dir() -> Result<PathBuf> {
    // 1. Check for manual override via environment variable
    if let Ok(dir) = std::env::var("TANOS_DIR") {
        return Ok(PathBuf::from(dir));
    }

    // 2. Check for Termux-style path
    if let Ok(home) = std::env::var("HOME") {
        let p = Path::new(&home);
        if p.join(".termux").exists() || home.contains("com.termux") {
            let dir = p.join(".tanos");
            return Ok(dir);
        }
    }

    // 3. Standard desktop / server path
    let base = directories::BaseDirs::new().context("cannot determine home directory")?;
    Ok(base.home_dir().join(".tanos"))
}

/// Full path to the identity key file.
pub fn identity_file() -> Result<PathBuf> {
    Ok(identity_dir()?.join("identity.key"))
}

pub fn identity_exists() -> Result<bool> {
    Ok(identity_file()?.exists())
}

pub fn load_identity() -> Result<NodeIdentity> {
    let path = identity_file()?;
    let name_path = path.with_extension("name");

    if !path.exists() {
        anyhow::bail!("Identity file does not exist");
    }

    let raw = std::fs::read(&path).context("failed to read identity file")?;
    if raw.len() != 32 {
        anyhow::bail!(
            "identity file has unexpected size {} (expected 32 bytes)",
            raw.len()
        );
    }
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&raw);
    
    let name = std::fs::read_to_string(&name_path).unwrap_or_else(|_| "Unknown".to_string());
    
    Ok(NodeIdentity::from_secret_bytes(&bytes, name))
}

pub fn save_identity(identity: &NodeIdentity) -> Result<()> {
    let path = identity_file()?;
    let name_path = path.with_extension("name");
    
    let dir = path
        .parent()
        .context("identity file has no parent directory")?;
    std::fs::create_dir_all(dir).context("failed to create identity directory")?;
    
    std::fs::write(&path, identity.secret_key_bytes())
        .context("failed to write identity file")?;
    let name = identity.friendly_name.lock().unwrap();
    std::fs::write(&name_path, name.as_str())
        .context("failed to write identity name file")?;
    Ok(())
}

pub fn load_or_create_identity() -> Result<NodeIdentity> {
    if identity_exists()? {
        load_identity()
    } else {
        let identity = NodeIdentity::generate(None);
        save_identity(&identity)?;
        Ok(identity)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_identity_produces_valid_tan_id() {
        let id = NodeIdentity::generate(None);
        // tan_id is hex of 8 bytes → 16 hex chars
        assert_eq!(id.tan_id.len(), 16);
        assert!(hex::decode(&id.tan_id).is_ok());
    }

    #[test]
    fn roundtrip_secret_bytes() {
        let original = NodeIdentity::generate(Some("Alice".to_string()));
        let original_name = original.friendly_name.lock().unwrap().clone();
        let restored = NodeIdentity::from_secret_bytes(&original.secret_key_bytes(), original_name);
        assert_eq!(original.tan_id, restored.tan_id);
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
        let id1 = NodeIdentity::generate(None);
        std::fs::write(&key_path, id1.secret_key_bytes()).expect("write");

        // Reload
        let raw = std::fs::read(&key_path).expect("read");
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&raw);
        let id2 = NodeIdentity::from_secret_bytes(&bytes, "Unknown".to_string());

        assert_eq!(id1.tan_id, id2.tan_id);
    }
}
