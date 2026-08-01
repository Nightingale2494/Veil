// backend/src/domain/mod.rs

pub mod device;
pub mod messaging;
pub mod repositories;
pub mod session;
pub mod user;

use thiserror::Error;

#[derive(Error, Debug, serde::Serialize, serde::Deserialize)]
pub enum Error {
    #[error("Cryptographic error: {0}")]
    CryptoError(String),
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    #[error("Validation error: {0}")]
    ValidationError(String),
}

/// Abstract Cryptography interface. Keeping Domain and Application independent
/// of concrete algorithms (e.g. Ring vs RustCrypto).
pub trait CryptoProvider: Send + Sync {
    /// Hashes a password using Argon2id
    fn hash_password(&self, password: &[u8]) -> Result<String, Error>;

    /// Verifies a password against an Argon2id hash
    fn verify_password(&self, password: &[u8], hash: &str) -> Result<bool, Error>;

    /// Encrypts symmetric plaintext using ChaCha20-Poly1305
    fn encrypt_symmetric(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error>;

    /// Decrypts symmetric ciphertext using ChaCha20-Poly1305
    fn decrypt_symmetric(&self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error>;

    /// Generates an X25519 or Ed25519 keypair (returns (public, private))
    fn generate_keypair(&self, curve: KeyCurve) -> Result<(Vec<u8>, Vec<u8>), Error>;

    /// Generates cryptographically secure random bytes (CSPRNG)
    fn generate_secure_random(&self, len: usize) -> Result<Vec<u8>, Error>;

    /// Computes HMAC-SHA256 of the data using the provided key
    fn compute_hmac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error>;

    /// Computes SHA-256 hash of the data (used for opaque access tokens)
    fn hash_sha256(&self, data: &[u8]) -> Result<Vec<u8>, Error>;

    /// Verifies if two slices are equal in constant-time to prevent timing side-channel attacks
    fn verify_constant_time(&self, a: &[u8], b: &[u8]) -> bool;

    /// Computes X25519 Diffie-Hellman shared secret
    fn diffie_hellman(&self, private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, Error>;

    /// Computes Ed25519 signature over a message
    fn sign_ed25519(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, Error>;

    /// Verifies Ed25519 signature over a message
    fn verify_ed25519(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyCurve {
    X25519,
    Ed25519,
}
