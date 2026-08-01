# SECURITY.md - Veil Security & Cryptographic Specifications

This document outlines the security architecture, threat model, cryptographic specifications, and operational policies for **Veil**.

---

## 1. Cryptographic Primitives

Veil relies strictly on mature, audited libraries (such as the `RustCrypto` and `dalek` ecosystems) for all cryptographic operations. Custom cryptography is not permitted.

| Primitive / Algorithm | Purpose | Specification |
| :--- | :--- | :--- |
| **Argon2id** | Server-side password & recovery key hashing | RFC 9106 default profile:<br>- Memory: 65,536 KB (64 MiB)<br>- Iterations (m_cost): 3<br>- Parallelism (p_cost): 4 |
| **X25519** | Diffie-Hellman Key Exchange | Curve25519-based ECDH (32-byte keys) |
| **Ed25519** | Digital Signatures | Ed25519 (EdDSA) signing & verification (32-byte keys, 64-byte signatures) |
| **ChaCha20-Poly1305** | Symmetric Encryption | Authenticated Encryption with Associated Data (AEAD), random 12-byte nonces |
| **HKDF-SHA256** | Key Derivation | Key-based HKDF extract & expand for ratchet key updates |
| **HMAC-SHA256** | Token hashing & integrity verification | Keyed-hash message authentication code |
| **BIP-39 Mnemonic** | Account Recovery Key | 24-word mnemonic phrase (256-bit entropy) generated client-side |

---

## 2. Secure Randomness

All cryptographic keys, salts, database IDs, session identifiers, nonces, and tokens must be generated using a Cryptographically Secure Pseudo-Random Number Generator (CSPRNG) seeded by the host Operating System's entropy source.
- In Rust: Using `rand::rngs::OsRng` or `rand::thread_rng()`.
- In Dart/Flutter: Using `crypto` secure random generators or platform-native cryptographically secure random APIs.

---

## 3. Session & Token Lifecycle

### Token Specifications
- **Access Tokens**: Opaque 256-bit cryptographically random strings (represented as Hex or Base64). 
  - Expiry: 15 minutes.
  - Storage: In the database, only the SHA-256 hash of the access token is stored (`sessions.access_token_hash`).
- **Refresh Tokens**: Opaque 256-bit cryptographically random strings.
  - Expiry: 30 days.
  - Storage: Stored hashed using `HMAC-SHA256` with a server-held secret key.
  - Rotation: A refresh token is strictly single-use. Every request to rotate a token results in the old token being revoked and a new refresh token issued.

### CSRF Protections
Authentication uses Bearer tokens transmitted via the `Authorization` header (`Authorization: Bearer <token>`) rather than ambient browser cookies. Therefore, standard Cross-Site Request Forgery (CSRF) protection is not required for the API endpoints as the browser does not attach Bearer tokens automatically.

---

## 4. Threat Model & Security Controls

### Brute-Force & Credential Stuffing Prevention
- Login attempts are logged in the `login_attempts` table, tracking `username`, `ip_hash`, `user_agent`, and `success/failure` state.
- **Rate-Limiting**: Max 5 failed login attempts in 10 minutes per username/IP. If exceeded, a 15-minute cooldown lock is applied.
- **Recovery Rate-Limiting**: Recovery key submission is locked for 1 hour after 3 failed attempts to protect against brute-forcing the BIP-39 recovery phrase.

### Threat Assumptions
1. **Compromised Server Database**: In the event of a full database disclosure:
   - Passwords and recovery keys remain protected by salted Argon2id hashes.
   - Active session refresh tokens are protected by HMAC-SHA256 under a separate server configuration secret key, preventing attackers from hijacking active user sessions.
   - Message payloads are E2E encrypted and cannot be decrypted by the server or an attacker.
2. **Device Loss / Compromise**:
   - Each device maintains its own key pair and identity.
   - A compromised device can be selectively revoked from any other active verified device, restricting access without rotating master keys.
   - Account recovery via the 24-word mnemonic rotates all keys, revokes all sessions/devices, and forces re-approval.
