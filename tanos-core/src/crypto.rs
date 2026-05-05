//! Cryptographic primitives for TanOS.
//!
//! - **Signing / verification** — Ed25519 via `ed25519-dalek`.
//! - **Key exchange** — X25519 Diffie-Hellman via `x25519-dalek`.
//! - **Authenticated encryption** — ChaCha20-Poly1305 via `chacha20poly1305`.
//!
//! All crypto lives exclusively in this crate; `tanos-net` and `tanos-node`
//! must never use raw crypto primitives directly.

use anyhow::{Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

/// Result of encrypting a plaintext payload for a specific recipient.
#[derive(Debug)]
pub struct EncryptedPayload {
    /// The encrypted ciphertext (plaintext + 16-byte Poly1305 tag).
    pub ciphertext: Vec<u8>,
    /// The X25519 ephemeral public key used for this message.
    pub ephemeral_pubkey: [u8; 32],
    /// The 12-byte nonce used for ChaCha20-Poly1305.
    pub nonce: [u8; 12],
}

// ─── Signing ─────────────────────────────────────────────────────────────

/// Sign arbitrary data with an Ed25519 signing key.
pub fn sign(signing_key: &SigningKey, data: &[u8]) -> [u8; 64] {
    let sig: Signature = signing_key.sign(data);
    sig.to_bytes()
}

/// Verify an Ed25519 signature over data.
pub fn verify(verifying_key: &VerifyingKey, data: &[u8], sig_bytes: &[u8; 64]) -> Result<()> {
    let sig = Signature::from_bytes(sig_bytes);
    verifying_key
        .verify(data, &sig)
        .context("Ed25519 signature verification failed")
}

/// Reconstruct a `VerifyingKey` from raw 32 bytes.
pub fn verifying_key_from_bytes(bytes: &[u8; 32]) -> Result<VerifyingKey> {
    VerifyingKey::from_bytes(bytes).context("invalid Ed25519 public key bytes")
}

// ─── Encryption ──────────────────────────────────────────────────────────

/// Encrypt `plaintext` for a recipient identified by their X25519 public key.
///
/// Internally performs:
///   1. Generate an ephemeral X25519 keypair.
///   2. Perform ECDH with the recipient's public key to derive a shared secret.
///   3. Use the shared secret as the ChaCha20-Poly1305 key.
///   4. Generate a random 12-byte nonce.
///   5. Encrypt and authenticate the plaintext.
pub fn encrypt(recipient_pubkey: &[u8; 32], plaintext: &[u8]) -> Result<EncryptedPayload> {
    // Step 1: ephemeral keypair
    let ephemeral_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

    // Step 2: ECDH
    let recipient_x25519 = X25519PublicKey::from(*recipient_pubkey);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_x25519);

    // Step 3: derive key (shared_secret is already 32 bytes)
    let cipher = ChaCha20Poly1305::new_from_slice(shared_secret.as_bytes())
        .context("failed to create ChaCha20 cipher from shared secret")?;

    // Step 4: random nonce
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Step 5: encrypt
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("ChaCha20-Poly1305 encryption failed: {}", e))?;

    Ok(EncryptedPayload {
        ciphertext,
        ephemeral_pubkey: ephemeral_public.to_bytes(),
        nonce: nonce_bytes,
    })
}

/// Decrypt a payload using our static X25519 secret key and the sender's
/// ephemeral public key.
///
/// The `static_secret_bytes` are the receiver's long-term X25519 private key
/// (derived from or equal to their Ed25519 secret key for simplicity, or a
/// separate X25519 key stored alongside the identity).
pub fn decrypt(
    static_secret_bytes: &[u8; 32],
    ephemeral_pubkey: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let static_secret = StaticSecret::from(*static_secret_bytes);
    let ephemeral_pub = X25519PublicKey::from(*ephemeral_pubkey);
    let shared_secret = static_secret.diffie_hellman(&ephemeral_pub);

    let cipher = ChaCha20Poly1305::new_from_slice(shared_secret.as_bytes())
        .context("failed to create ChaCha20 cipher from shared secret")?;

    let nonce = Nonce::from_slice(nonce);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("ChaCha20-Poly1305 decryption failed: {}", e))
}

/// Derive an X25519 public key from a 32-byte static secret.
///
/// Used to derive the encryption public key we advertise (stored in beacons
/// alongside the Ed25519 verifying key, or derived on the fly from the same
/// 32-byte seed).
pub fn x25519_pubkey_from_secret(secret_bytes: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*secret_bytes);
    let public = X25519PublicKey::from(&secret);
    public.to_bytes()
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();
        let data = b"hello tanos mesh";

        let sig = sign(&signing_key, data);
        assert!(verify(&verifying_key, data, &sig).is_ok());
    }

    #[test]
    fn verify_rejects_tampered_data() {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();
        let data = b"original message";
        let sig = sign(&signing_key, data);

        let tampered = b"tampered message";
        assert!(verify(&verifying_key, tampered, &sig).is_err());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let key_a = SigningKey::generate(&mut rand::rngs::OsRng);
        let key_b = SigningKey::generate(&mut rand::rngs::OsRng);
        let data = b"some data";
        let sig = sign(&key_a, data);

        assert!(verify(&key_b.verifying_key(), data, &sig).is_err());
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        // Simulate a recipient with a static X25519 keypair
        let recipient_secret_bytes: [u8; 32] = {
            let mut buf = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut buf);
            buf
        };
        let recipient_pubkey = x25519_pubkey_from_secret(&recipient_secret_bytes);

        let plaintext = b"secret mesh message";
        let encrypted =
            encrypt(&recipient_pubkey, plaintext).expect("encryption should succeed");

        let decrypted = decrypt(
            &recipient_secret_bytes,
            &encrypted.ephemeral_pubkey,
            &encrypted.nonce,
            &encrypted.ciphertext,
        )
        .expect("decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_with_wrong_key_fails() {
        let recipient_secret: [u8; 32] = {
            let mut buf = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut buf);
            buf
        };
        let recipient_pubkey = x25519_pubkey_from_secret(&recipient_secret);

        let encrypted =
            encrypt(&recipient_pubkey, b"payload").expect("encryption should succeed");

        // Try decrypting with a different secret key
        let wrong_secret: [u8; 32] = {
            let mut buf = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut buf);
            buf
        };
        assert!(decrypt(
            &wrong_secret,
            &encrypted.ephemeral_pubkey,
            &encrypted.nonce,
            &encrypted.ciphertext,
        )
        .is_err());
    }

    #[test]
    fn verifying_key_from_bytes_roundtrip() {
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let vk = sk.verifying_key();
        let bytes = vk.to_bytes();
        let restored = verifying_key_from_bytes(&bytes).expect("valid key bytes");
        assert_eq!(vk, restored);
    }

    #[test]
    fn x25519_pubkey_deterministic() {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let pk1 = x25519_pubkey_from_secret(&secret);
        let pk2 = x25519_pubkey_from_secret(&secret);
        assert_eq!(pk1, pk2);
    }
}
