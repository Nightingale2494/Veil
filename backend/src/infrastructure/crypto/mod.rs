// backend/src/infrastructure/crypto/mod.rs

use crate::domain::{CryptoProvider, Error, KeyCurve};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Params,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::SigningKey;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::PublicKey;

type HmacSha256 = Hmac<Sha256>;

pub struct RustCryptoProvider;

impl CryptoProvider for RustCryptoProvider {
    fn hash_password(&self, password: &[u8]) -> Result<String, Error> {
        // Enforce RFC 9106 recommended default profile:
        // Memory = 64 MiB (65536 KB), Iterations = 3, Parallelism = 4
        let params = Params::new(65536, 3, 4, None)
            .map_err(|e| Error::CryptoError(format!("Argon2 configuration error: {}", e)))?;

        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        let salt = SaltString::generate(&mut OsRng);

        let hash = argon2
            .hash_password(password, &salt)
            .map_err(|e| Error::CryptoError(format!("Argon2 hashing failed: {}", e)))?
            .to_string();

        Ok(hash)
    }

    fn verify_password(&self, password: &[u8], hash: &str) -> Result<bool, Error> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| Error::CryptoError(format!("Invalid password hash format: {}", e)))?;

        // Verifies against parameters encoded in the stored hash
        let argon2 = Argon2::default();
        let matches = argon2.verify_password(password, &parsed_hash).is_ok();

        Ok(matches)
    }

    fn encrypt_symmetric(&self, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| Error::CryptoError(format!("Invalid symmetric key size: {}", e)))?;

        // CSPRNG Nonce generation
        let mut nonce_bytes = [0u8; 12];
        rand::Rng::fill(&mut rand::thread_rng(), &mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let mut ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| Error::CryptoError(format!("Encryption failed: {}", e)))?;

        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.append(&mut ciphertext);
        Ok(result)
    }

    fn decrypt_symmetric(&self, key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        if ciphertext.len() < 12 {
            return Err(Error::CryptoError(
                "Ciphertext too short (missing nonce)".into(),
            ));
        }
        let (nonce_bytes, payload) = ciphertext.split_at(12);
        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| Error::CryptoError(format!("Invalid symmetric key size: {}", e)))?;
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, payload)
            .map_err(|e| Error::CryptoError(format!("Decryption failed: {}", e)))?;
        Ok(plaintext)
    }

    fn generate_keypair(&self, curve: KeyCurve) -> Result<(Vec<u8>, Vec<u8>), Error> {
        match curve {
            KeyCurve::X25519 => {
                let mut rng = rand::thread_rng();
                let secret = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
                let public = PublicKey::from(&secret);
                Ok((public.as_bytes().to_vec(), secret.to_bytes().to_vec()))
            }
            KeyCurve::Ed25519 => {
                let mut rng = rand::thread_rng();
                let signing_key = SigningKey::generate(&mut rng);
                let public_key = signing_key.verifying_key();
                Ok((
                    public_key.as_bytes().to_vec(),
                    signing_key.to_bytes().to_vec(),
                ))
            }
        }
    }

    fn generate_secure_random(&self, len: usize) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0u8; len];
        // rand::thread_rng() uses OsRng internally to seed itself, satisfying CSPRNG requirements
        rand::Rng::fill(&mut rand::thread_rng(), &mut buf[..]);
        Ok(buf)
    }

    fn compute_hmac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(key)
            .map_err(|e| Error::CryptoError(format!("HMAC key size error: {}", e)))?;
        mac.update(data);
        let result = mac.finalize();
        Ok(result.into_bytes().to_vec())
    }

    fn hash_sha256(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        Ok(hasher.finalize().to_vec())
    }

    fn verify_constant_time(&self, a: &[u8], b: &[u8]) -> bool {
        a.ct_eq(b).unwrap_u8() == 1
    }

    fn diffie_hellman(&self, private_key: &[u8], public_key: &[u8]) -> Result<Vec<u8>, Error> {
        use x25519_dalek::{PublicKey, StaticSecret};
        if private_key.len() != 32 || public_key.len() != 32 {
            return Err(Error::CryptoError(
                "Invalid key length for X25519 DH".to_string(),
            ));
        }
        let mut priv_bytes = [0u8; 32];
        priv_bytes.copy_from_slice(private_key);
        let secret = StaticSecret::from(priv_bytes);

        let mut pub_bytes = [0u8; 32];
        pub_bytes.copy_from_slice(public_key);
        let public = PublicKey::from(pub_bytes);

        let shared = secret.diffie_hellman(&public);
        Ok(shared.to_bytes().to_vec())
    }

    fn sign_ed25519(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, Error> {
        use ed25519_dalek::{Signer, SigningKey};
        if private_key.len() != 32 {
            return Err(Error::CryptoError(
                "Invalid key length for Ed25519 signing".to_string(),
            ));
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(private_key);
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let signature = signing_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }

    fn verify_ed25519(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, Error> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        if public_key.len() != 32 {
            return Err(Error::CryptoError(
                "Invalid public key length for Ed25519".to_string(),
            ));
        }
        if signature.len() != 64 {
            return Err(Error::CryptoError(
                "Invalid signature length for Ed25519".to_string(),
            ));
        }
        let mut pub_bytes = [0u8; 32];
        pub_bytes.copy_from_slice(public_key);
        let verifying_key = VerifyingKey::from_bytes(&pub_bytes)
            .map_err(|e| Error::CryptoError(format!("Invalid Ed25519 public key bytes: {}", e)))?;

        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);
        let signature_obj = Signature::from_bytes(&sig_bytes);

        let result = verifying_key.verify(message, &signature_obj).is_ok();
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hashing() {
        let provider = RustCryptoProvider;
        let pwd = b"supersecretpassword";
        let hash = provider.hash_password(pwd).unwrap();

        // Assert Argon2id parameters are embedded correctly
        assert!(hash.contains("m=65536,t=3,p=4"));
        assert!(provider.verify_password(pwd, &hash).unwrap());
        assert!(!provider.verify_password(b"wrongpassword", &hash).unwrap());
    }

    #[test]
    fn test_symmetric_encryption() {
        let provider = RustCryptoProvider;
        let key = [0u8; 32];
        let plaintext = b"Hello, Veil E2E encryption!";
        let ciphertext = provider.encrypt_symmetric(&key, plaintext).unwrap();
        let decrypted = provider.decrypt_symmetric(&key, &ciphertext).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_keypair_generation() {
        let provider = RustCryptoProvider;
        let (x_pub, x_priv) = provider.generate_keypair(KeyCurve::X25519).unwrap();
        assert_eq!(x_pub.len(), 32);
        assert_eq!(x_priv.len(), 32);

        let (ed_pub, ed_priv) = provider.generate_keypair(KeyCurve::Ed25519).unwrap();
        assert_eq!(ed_pub.len(), 32);
        assert_eq!(ed_priv.len(), 32);
    }

    #[test]
    fn test_secure_random() {
        let provider = RustCryptoProvider;
        let rand1 = provider.generate_secure_random(32).unwrap();
        let rand2 = provider.generate_secure_random(32).unwrap();
        assert_eq!(rand1.len(), 32);
        assert_eq!(rand2.len(), 32);
        assert_ne!(rand1, rand2);
    }

    #[test]
    fn test_hmac_and_sha256() {
        let provider = RustCryptoProvider;
        let key = b"my_secret_server_hmac_key";
        let data = b"some_sensitive_refresh_token_payload";
        let hmac_val1 = provider.compute_hmac(key, data).unwrap();
        let hmac_val2 = provider.compute_hmac(key, data).unwrap();
        assert_eq!(hmac_val1, hmac_val2);

        let hash_val = provider.hash_sha256(data).unwrap();
        assert_eq!(hash_val.len(), 32);
    }

    #[test]
    fn test_constant_time() {
        let provider = RustCryptoProvider;
        let a = b"secret123";
        let b = b"secret123";
        let c = b"secret456";
        assert!(provider.verify_constant_time(a, b));
        assert!(!provider.verify_constant_time(a, c));
    }

    #[test]
    fn test_diffie_hellman_and_signatures() {
        let provider = RustCryptoProvider;

        // Test X25519 DH Shared Secret Exchange
        let (pub1, priv1) = provider.generate_keypair(KeyCurve::X25519).unwrap();
        let (pub2, priv2) = provider.generate_keypair(KeyCurve::X25519).unwrap();
        let shared1 = provider.diffie_hellman(&priv1, &pub2).unwrap();
        let shared2 = provider.diffie_hellman(&priv2, &pub1).unwrap();
        assert_eq!(shared1, shared2);

        // Test Ed25519 Signatures
        let (ed_pub, ed_priv) = provider.generate_keypair(KeyCurve::Ed25519).unwrap();
        let msg = b"Secure payload to sign";
        let sig = provider.sign_ed25519(&ed_priv, msg).unwrap();
        assert_eq!(sig.len(), 64);
        assert!(provider.verify_ed25519(&ed_pub, msg, &sig).unwrap());
        assert!(!provider
            .verify_ed25519(&ed_pub, b"mutated payload", &sig)
            .unwrap());
    }
}
