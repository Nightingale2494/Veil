// backend/src/application/messaging.rs

use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

use crate::domain::{
    messaging::{DoubleRatchetState, Envelope, MessagePayload, MessageType, PreKeyBundle},
    repositories::{DeviceSessionRepository, PreKeyRepository, ReplayCacheRepository},
    CryptoProvider, Error,
};

// HKDF-SHA256 Helper conforming to RFC 5869
pub fn hkdf_sha256(
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    length: usize,
    crypto: &dyn CryptoProvider,
) -> Result<Vec<u8>, Error> {
    // HKDF-Extract(salt, ikm) -> PRK (Pseudo-Random Key)
    let prk = crypto.compute_hmac(salt, ikm)?;

    // HKDF-Expand(PRK, info) -> OKM (Output Keying Material)
    let mut okm = Vec::new();
    let mut t = Vec::new();
    let mut i = 1u8;
    while okm.len() < length {
        let mut input = Vec::new();
        input.extend_from_slice(&t);
        input.extend_from_slice(info);
        input.push(i);
        t = crypto.compute_hmac(&prk, &input)?;
        okm.extend_from_slice(&t);
        i += 1;
    }
    okm.truncate(length);
    Ok(okm)
}

// Double Ratchet Symmetric Chain Key update: advances chain and returns (next_chain_key, message_key)
fn kdf_ck(ck: &[u8], crypto: &dyn CryptoProvider) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let next_ck = crypto.compute_hmac(ck, &[0x02])?;
    let msg_key = crypto.compute_hmac(ck, &[0x01])?;
    Ok((next_ck, msg_key))
}

// Double Ratchet DH Root Key update: advances root key and returns (next_root_key, chain_key)
fn kdf_rk(
    rk: &[u8],
    dh_out: &[u8],
    crypto: &dyn CryptoProvider,
) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let okm = hkdf_sha256(rk, dh_out, b"VeilRatchetRootKeyDerivationInfo", 64, crypto)?;
    let next_rk = okm[0..32].to_vec();
    let ck = okm[32..64].to_vec();
    Ok((next_rk, ck))
}

// X3DH Session Agreement UseCase
pub struct EstablishSessionUseCase<'a> {
    pub session_repo: &'a dyn DeviceSessionRepository,
    pub prekey_repo: &'a dyn PreKeyRepository,
    pub crypto: &'a dyn CryptoProvider,
    pub server_state_key: Vec<u8>, // Used for encrypting ratchet state at rest
}

impl<'a> EstablishSessionUseCase<'a> {
    // Executes the X3DH handshake as an initiator and sets up the active Double Ratchet session state
    pub async fn execute(
        &self,
        initiator_device_id: Uuid,
        recipient_device_id: Uuid,
        initiator_identity_dh_private: &[u8], // X25519 identity private key (no conversions)
    ) -> Result<DoubleRatchetState, Error> {
        // 1. Fetch prekey bundle of target recipient device
        let bundle = self
            .prekey_repo
            .get_prekey_bundle(&recipient_device_id)
            .await?
            .ok_or_else(|| {
                Error::NotFound("Prekey bundle not found for recipient device".to_string())
            })?;

        // Verify prekey bundle signatures
        // A. Verify Bob's identity DH key signature
        let id_sig_ok = self.crypto.verify_ed25519(
            &bundle.identity_signing_key,
            &bundle.identity_dh_key,
            &bundle.identity_dh_signature,
        )?;
        if !id_sig_ok {
            return Err(Error::Unauthorized(
                "Invalid identity DH signature in prekey bundle".to_string(),
            ));
        }

        // B. Verify Bob's signed prekey signature
        let sig_ok = self.crypto.verify_ed25519(
            &bundle.identity_signing_key,
            &bundle.signed_prekey,
            &bundle.prekey_signature,
        )?;
        if !sig_ok {
            return Err(Error::Unauthorized(
                "Invalid signed prekey signature in prekey bundle".to_string(),
            ));
        }

        // 2. Generate ephemeral key pair (EK) for initiator
        let (ek_pub, ek_priv) = self
            .crypto
            .generate_keypair(crate::domain::KeyCurve::X25519)?;

        // 3. Compute Diffie-Hellman handshakes (DH1, DH2, DH3, DH4) directly on X25519 keys
        let dh1 = self
            .crypto
            .diffie_hellman(initiator_identity_dh_private, &bundle.signed_prekey)?;
        let dh2 = self
            .crypto
            .diffie_hellman(&ek_priv, &bundle.identity_dh_key)?;
        let dh3 = self
            .crypto
            .diffie_hellman(&ek_priv, &bundle.signed_prekey)?;

        let mut ikm = Vec::new();
        ikm.extend_from_slice(&dh1);
        ikm.extend_from_slice(&dh2);
        ikm.extend_from_slice(&dh3);

        // DH4 = DH(initiator_ephemeral_private, recipient_one_time_key) (if present)
        if let Some(ref otk) = bundle.one_time_key {
            let dh4 = self.crypto.diffie_hellman(&ek_priv, otk)?;
            ikm.extend_from_slice(&dh4);
            // Consume the one time prekey from repository
            let _ = self
                .prekey_repo
                .consume_one_time_key(&recipient_device_id)
                .await?;
        }

        // 4. Derive Root Key and Chain Key from HKDF
        let shared_secret = hkdf_sha256(
            &[0u8; 32],
            &ikm,
            b"VeilX3DHSessionSetupInfo",
            64,
            self.crypto,
        )?;
        let rk = shared_secret[0..32].to_vec();
        let cks = shared_secret[32..64].to_vec();

        // 5. Initialize the Double Ratchet state (Reuse handshake ephemeral keys as initial DH keys)
        let dhs_pub = ek_pub;
        let dhs_priv = ek_priv;

        let state = DoubleRatchetState {
            dhs_priv,
            dhs_pub,
            dhr_pub: Some(bundle.signed_prekey.clone()),
            rk,
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: HashMap::new(),
        };

        // 6. Serialize & Encrypt state at rest
        let serialized = ciborium_serialize(&state)?;
        let encrypted = self
            .crypto
            .encrypt_symmetric(&self.server_state_key, &serialized)?;

        // 7. Save session state to repository
        self.session_repo
            .save_session(
                &Uuid::new_v4(),
                &initiator_device_id,
                &recipient_device_id,
                "1.0",
                &encrypted,
                0,
            )
            .await?;

        Ok(state)
    }
}

// Double Ratchet UseCase
pub struct DoubleRatchetUseCase<'a> {
    pub session_repo: &'a dyn DeviceSessionRepository,
    pub replay_repo: &'a dyn ReplayCacheRepository,
    pub crypto: &'a dyn CryptoProvider,
    pub server_state_key: Vec<u8>,
}

impl<'a> DoubleRatchetUseCase<'a> {
    // Encrypts a message payload using the Double Ratchet sending chain key
    pub async fn encrypt_message(
        &self,
        sender_device_id: Uuid,
        recipient_device_id: Uuid,
        conversation_id: Uuid,
        sender_identity_private: &[u8], // Used to sign the envelope
        payload: &MessagePayload,
    ) -> Result<Envelope, Error> {
        // 1. Fetch existing device session
        let (session_id, version, encrypted_state, _) = self
            .session_repo
            .get_session(&sender_device_id, &recipient_device_id)
            .await?
            .ok_or_else(|| Error::NotFound("Ratchet session not found for devices".to_string()))?;

        // 2. Decrypt ratchet state at rest
        let decrypted_state = self
            .crypto
            .decrypt_symmetric(&self.server_state_key, &encrypted_state)?;
        let mut state: DoubleRatchetState = ciborium_deserialize(&decrypted_state)?;

        // 3. Advance sending chain
        let cks = state
            .cks
            .clone()
            .ok_or_else(|| Error::CryptoError("Sending chain key not initialized".to_string()))?;
        let (next_cks, msg_key) = kdf_ck(&cks, self.crypto)?;
        state.cks = Some(next_cks);

        let msg_num = state.ns;
        state.ns += 1;

        // 4. Encrypt message payload with message key
        let payload_bytes = ciborium_serialize(payload)?;
        let ciphertext = self.crypto.encrypt_symmetric(&msg_key, &payload_bytes)?;

        // 5. Re-serialize and encrypt state at rest
        let new_state_bytes = ciborium_serialize(&state)?;
        let new_encrypted_state = self
            .crypto
            .encrypt_symmetric(&self.server_state_key, &new_state_bytes)?;

        self.session_repo
            .save_session(
                &session_id,
                &sender_device_id,
                &recipient_device_id,
                &version,
                &new_encrypted_state,
                msg_num as i32,
            )
            .await?;

        // 6. Build the envelope fields (with empty signature for signing)
        let mut envelope = Envelope {
            message_id: Uuid::new_v4(),
            conversation_id,
            sender_device_id,
            recipient_device_id,
            timestamp: Utc::now().timestamp_millis(),
            dh_pub: state.dhs_pub.clone(),
            ciphertext,
            signature: Vec::new(),
            major_version: 1,
            minor_version: 0,
            message_number: msg_num,
        };

        // 7. Calculate envelope signature over Canonical CBOR of the unsigned envelope
        let envelope_bytes = ciborium_serialize(&envelope)?;
        let signature = self
            .crypto
            .sign_ed25519(sender_identity_private, &envelope_bytes)?;

        envelope.signature = signature;
        Ok(envelope)
    }

    // Decrypts an incoming message envelope, managing out-of-order skipped keys and DH ratchets
    pub async fn decrypt_message(
        &self,
        recipient_device_id: Uuid,
        sender_device_id: Uuid,
        envelope: &Envelope,
        sender_identity_public: &[u8], // Used to verify signature before decryption
        recipient_identity_private: &[u8], // For DH exchange calculations
    ) -> Result<MessagePayload, Error> {
        // 1. Verify Replay Attack prevention (deduplication)
        let unique = self.replay_repo.add_to_cache(&envelope.message_id).await?;
        if !unique {
            return Err(Error::ValidationError(
                "Duplicate message ID detected (replay attack protection)".to_string(),
            ));
        }

        // 2. Verify digital envelope signature over Canonical CBOR
        let mut envelope_unsigned = envelope.clone();
        envelope_unsigned.signature = Vec::new();
        let verify_data = ciborium_serialize(&envelope_unsigned)?;

        let sig_ok = self.crypto.verify_ed25519(
            sender_identity_public,
            &verify_data,
            &envelope.signature,
        )?;
        if !sig_ok {
            return Err(Error::Unauthorized(
                "Invalid envelope signature: authentication failed".to_string(),
            ));
        }

        // 3. Fetch device session
        let (session_id, version, encrypted_state, _) = self
            .session_repo
            .get_session(&recipient_device_id, &sender_device_id)
            .await?
            .ok_or_else(|| Error::NotFound("Ratchet session not found for devices".to_string()))?;

        // 4. Decrypt ratchet state at rest
        let decrypted_state = self
            .crypto
            .decrypt_symmetric(&self.server_state_key, &encrypted_state)?;
        let mut state: DoubleRatchetState = ciborium_deserialize(&decrypted_state)?;

        // 5. Try skipped keys lookup first
        // In the envelope, we don't pass the remote_dh public key directly. But wait, in a real Double Ratchet, the sender's DH public key MUST be passed in the header!
        // Where is the sender's DH public key in our Envelope?
        // Ah! In our Envelope struct definition we didn't add a `dh_pub` field!
        // Wait, how does the receiver get the sender's current DH public key if it's not in the envelope?
        // Oh! We must put the sender's DH public key inside the Envelope!
        // Let's see: in `Envelope` we have:
        // message_id, conversation_id, sender_device_id, recipient_device_id, timestamp, ciphertext, signature, major_version, minor_version, message_number.
        // We forgot to add a `dh_pub: Vec<u8>` field to `Envelope`!
        // Let's look back at `Envelope` in `domain/messaging.rs`:
        // Yes, we need to modify `Envelope` to add `dh_pub: Vec<u8>` so that the receiver can compute the DH ratchet!
        // That is an extremely important fix! Let's update `domain/messaging.rs` and add `dh_pub` to `Envelope`.
        // Wait, let's look at what we signed: we included `state.dhs_pub` in the signed data in `encrypt_message` but didn't serialize it in `Envelope`!
        // Yes! Adding `dh_pub: Vec<u8>` to `Envelope` completes the protocol envelope perfectly!
        // Let's update the `Envelope` definition. Let's do that right away.
        // But first, let's finish thinking about the Double Ratchet flow:
        // If the remote DH key in the envelope matches `state.dhr_pub`, we are in the same ratchet chain. We just advance the receiving chain key.
        // If the remote DH key is different, it means the sender did a DH ratchet step.
        // In this case, we:
        // - Skip keys in the old receiving chain (from `state.nr` to `state.pn`).
        // - Perform a DH ratchet step:
        //   - `dh_out = DH(recipient_identity_private, remote_dh)`
        //   - `(next_rk, ckr) = kdf_rk(state.rk, dh_out)`
        //   - Update `state.rk = next_rk`
        //   - Update `state.dhr_pub = Some(remote_dh)`
        //   - Update `state.pn = state.ns`
        //   - Update `state.nr = 0`
        // - Advance the receiving chain key.
        // Let's implement this!

        // Let's check if the key is already in `skipped_keys`:
        // The lookup key is `format!("{}:{}", hex::encode(remote_dh), msg_num)`
        // Let's extract remote_dh from envelope. Since envelope has no `dh_pub` yet, we'll add it. Let's assume we have `envelope.dh_pub`.
        let remote_dh = &envelope.dh_pub;
        let skipped_key = format!("{}:{}", hex::encode(remote_dh), envelope.message_number);

        let msg_key = if let Some(key) = state.mkskipped.remove(&skipped_key) {
            key
        } else {
            // Check if DH ratchet step is needed
            if Some(remote_dh.clone()) != state.dhr_pub {
                // Skip keys in current receiving chain
                skip_message_keys(&mut state, envelope.message_number, self.crypto)?;

                // DH Ratchet step
                let dh_out = self
                    .crypto
                    .diffie_hellman(recipient_identity_private, remote_dh)?;
                let (next_rk, ckr) = kdf_rk(&state.rk, &dh_out, self.crypto)?;
                state.rk = next_rk;
                state.ckr = Some(ckr);
                state.dhr_pub = Some(remote_dh.clone());
                state.pn = state.ns;
                state.nr = 0;

                // Also update local DH keys for next sending chain
                let (new_dhs_pub, new_dhs_priv) = self
                    .crypto
                    .generate_keypair(crate::domain::KeyCurve::X25519)?;
                state.dhs_pub = new_dhs_pub;
                state.dhs_priv = new_dhs_priv;
            } else {
                // Skip keys in current receiving chain up to msg_num
                skip_message_keys(&mut state, envelope.message_number, self.crypto)?;
            }

            // Ratchet the receiving chain key
            let ckr = state.ckr.clone().ok_or_else(|| {
                Error::CryptoError("Receiving chain key not initialized".to_string())
            })?;
            let (next_ckr, mkey) = kdf_ck(&ckr, self.crypto)?;
            state.ckr = Some(next_ckr);
            state.nr += 1;
            mkey
        };

        // 6. Decrypt ciphertext using message key
        let payload_bytes = self
            .crypto
            .decrypt_symmetric(&msg_key, &envelope.ciphertext)?;
        let payload: MessagePayload = ciborium_deserialize(&payload_bytes)?;

        // 7. Save updated ratchet state
        let new_state_bytes = ciborium_serialize(&state)?;
        let new_encrypted_state = self
            .crypto
            .encrypt_symmetric(&self.server_state_key, &new_state_bytes)?;
        self.session_repo
            .save_session(
                &session_id,
                &recipient_device_id,
                &sender_device_id,
                &version,
                &new_encrypted_state,
                envelope.message_number as i32,
            )
            .await?;

        Ok(payload)
    }
}

// Skips message keys in receiving chain up to msg_num, storing skipped keys
fn skip_message_keys(
    state: &mut DoubleRatchetState,
    msg_num: u32,
    crypto: &dyn CryptoProvider,
) -> Result<(), Error> {
    if state.nr + 100 < msg_num {
        return Err(Error::CryptoError(
            "Message gap too large (possible DoS protection limit exceeded)".to_string(),
        ));
    }
    if let Some(ref ckr) = state.ckr {
        let mut current_ckr = ckr.clone();
        let dhr = state
            .dhr_pub
            .clone()
            .ok_or_else(|| Error::CryptoError("DH receiver public key missing".to_string()))?;
        let dhr_hex = hex::encode(dhr);
        while state.nr < msg_num {
            let (next_ckr, msg_key) = kdf_ck(&current_ckr, crypto)?;
            current_ckr = next_ckr;
            let skipped_key = format!("{}:{}", dhr_hex, state.nr);
            state.mkskipped.insert(skipped_key, msg_key);
            state.nr += 1;
        }
        state.ckr = Some(current_ckr);
    }
    Ok(())
}

// Serialization helpers
pub fn ciborium_serialize<T: serde::Serialize>(val: &T) -> Result<Vec<u8>, Error> {
    let mut buffer = Vec::new();
    ciborium::into_writer(val, &mut buffer)
        .map_err(|e| Error::ValidationError(format!("CBOR encoding error: {}", e)))?;
    Ok(buffer)
}

pub fn ciborium_deserialize<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    ciborium::from_reader(bytes)
        .map_err(|e| Error::ValidationError(format!("CBOR decoding error: {}", e)))
}

// Signed Prekey 30-day Rotation UseCase
pub struct PreKeyRotationUseCase<'a> {
    pub prekey_repo: &'a dyn PreKeyRepository,
    pub crypto: &'a dyn CryptoProvider,
}

impl<'a> PreKeyRotationUseCase<'a> {
    pub async fn rotate_signed_prekey(
        &self,
        device_id: Uuid,
        identity_signing_key: &[u8],
        identity_dh_key: &[u8],
        identity_dh_signature: &[u8],
        device_identity_signing_private: &[u8], // Ed25519 signing key
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        // 1. Generate new X25519 prekey pair
        let (spk_pub, _spk_priv) = self
            .crypto
            .generate_keypair(crate::domain::KeyCurve::X25519)?;

        // 2. Sign the new public prekey
        let signature = self
            .crypto
            .sign_ed25519(device_identity_signing_private, &spk_pub)?;

        // 3. Save to database
        self.prekey_repo
            .save_identity_key(
                &device_id,
                identity_signing_key,
                identity_dh_key,
                identity_dh_signature,
                &spk_pub,
                &signature,
            )
            .await?;

        Ok((spk_pub, signature))
    }
}

// CryptoManager: Encapsulates all cryptographic operations behind a single unified interface.
pub struct CryptoManager<'a> {
    pub session_repo: &'a dyn DeviceSessionRepository,
    pub prekey_repo: &'a dyn PreKeyRepository,
    pub replay_repo: &'a dyn ReplayCacheRepository,
    pub crypto: &'a dyn CryptoProvider,
    pub server_state_key: Vec<u8>,
}

impl<'a> CryptoManager<'a> {
    pub fn new(
        session_repo: &'a dyn DeviceSessionRepository,
        prekey_repo: &'a dyn PreKeyRepository,
        replay_repo: &'a dyn ReplayCacheRepository,
        crypto: &'a dyn CryptoProvider,
        server_state_key: Vec<u8>,
    ) -> Self {
        Self {
            session_repo,
            prekey_repo,
            replay_repo,
            crypto,
            server_state_key,
        }
    }

    pub async fn encrypt(
        &self,
        sender_device_id: Uuid,
        recipient_device_id: Uuid,
        conversation_id: Uuid,
        sender_identity_signing_private: &[u8],
        payload: &MessagePayload,
    ) -> Result<Envelope, Error> {
        let ratchet = DoubleRatchetUseCase {
            session_repo: self.session_repo,
            replay_repo: self.replay_repo,
            crypto: self.crypto,
            server_state_key: self.server_state_key.clone(),
        };
        ratchet
            .encrypt_message(
                sender_device_id,
                recipient_device_id,
                conversation_id,
                sender_identity_signing_private,
                payload,
            )
            .await
    }

    pub async fn decrypt(
        &self,
        recipient_device_id: Uuid,
        sender_device_id: Uuid,
        envelope: &Envelope,
        sender_identity_signing_public: &[u8],
        recipient_identity_dh_private: &[u8],
    ) -> Result<MessagePayload, Error> {
        let ratchet = DoubleRatchetUseCase {
            session_repo: self.session_repo,
            replay_repo: self.replay_repo,
            crypto: self.crypto,
            server_state_key: self.server_state_key.clone(),
        };
        ratchet
            .decrypt_message(
                recipient_device_id,
                sender_device_id,
                envelope,
                sender_identity_signing_public,
                recipient_identity_dh_private,
            )
            .await
    }

    pub async fn establish_session(
        &self,
        initiator_device_id: Uuid,
        recipient_device_id: Uuid,
        initiator_identity_dh_private: &[u8],
    ) -> Result<DoubleRatchetState, Error> {
        let x3dh = EstablishSessionUseCase {
            session_repo: self.session_repo,
            prekey_repo: self.prekey_repo,
            crypto: self.crypto,
            server_state_key: self.server_state_key.clone(),
        };
        x3dh.execute(
            initiator_device_id,
            recipient_device_id,
            initiator_identity_dh_private,
        )
        .await
    }

    pub async fn rotate_signed_prekey(
        &self,
        device_id: Uuid,
        identity_signing_key: &[u8],
        identity_dh_key: &[u8],
        identity_dh_signature: &[u8],
        device_identity_signing_private: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let rotation = PreKeyRotationUseCase {
            prekey_repo: self.prekey_repo,
            crypto: self.crypto,
        };
        rotation
            .rotate_signed_prekey(
                device_id,
                identity_signing_key,
                identity_dh_key,
                identity_dh_signature,
                device_identity_signing_private,
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::crypto::RustCryptoProvider;
    use crate::infrastructure::repositories::in_memory::InMemoryRepository;

    struct TestContext {
        repo: InMemoryRepository,
        crypto: RustCryptoProvider,
        server_state_key: Vec<u8>,
    }

    fn setup_context() -> TestContext {
        TestContext {
            repo: InMemoryRepository::new(),
            crypto: RustCryptoProvider,
            server_state_key: vec![1u8; 32],
        }
    }

    #[tokio::test]
    async fn test_x3dh_and_double_ratchet_e2e() {
        let ctx = setup_context();
        let alice_device_id = Uuid::new_v4();
        let bob_device_id = Uuid::new_v4();

        // 1. Generate Alice's keys
        let (alice_sig_pub, alice_sig_priv) = ctx
            .crypto
            .generate_keypair(crate::domain::KeyCurve::Ed25519)
            .unwrap();
        let (alice_dh_pub, alice_dh_priv) = ctx
            .crypto
            .generate_keypair(crate::domain::KeyCurve::X25519)
            .unwrap();
        let alice_dh_sig = ctx
            .crypto
            .sign_ed25519(&alice_sig_priv, &alice_dh_pub)
            .unwrap();

        // 2. Generate Bob's keys
        let (bob_sig_pub, bob_sig_priv) = ctx
            .crypto
            .generate_keypair(crate::domain::KeyCurve::Ed25519)
            .unwrap();
        let (bob_dh_pub, bob_dh_priv) = ctx
            .crypto
            .generate_keypair(crate::domain::KeyCurve::X25519)
            .unwrap();
        let bob_dh_sig = ctx.crypto.sign_ed25519(&bob_sig_priv, &bob_dh_pub).unwrap();

        let (bob_spk_pub, bob_spk_priv) = ctx
            .crypto
            .generate_keypair(crate::domain::KeyCurve::X25519)
            .unwrap();
        let bob_spk_sig = ctx
            .crypto
            .sign_ed25519(&bob_sig_priv, &bob_spk_pub)
            .unwrap();

        let (bob_otk_pub, bob_otk_priv) = ctx
            .crypto
            .generate_keypair(crate::domain::KeyCurve::X25519)
            .unwrap();

        // Register Bob's prekeys on server
        ctx.repo
            .save_identity_key(
                &bob_device_id,
                &bob_sig_pub,
                &bob_dh_pub,
                &bob_dh_sig,
                &bob_spk_pub,
                &bob_spk_sig,
            )
            .await
            .unwrap();
        ctx.repo
            .save_one_time_keys(&bob_device_id, &[bob_otk_pub.clone()])
            .await
            .unwrap();

        // 3. Establish session as Alice (Initiator)
        let manager = CryptoManager::new(
            &ctx.repo,
            &ctx.repo,
            &ctx.repo,
            &ctx.crypto,
            ctx.server_state_key.clone(),
        );

        let _alice_state = manager
            .establish_session(alice_device_id, bob_device_id, &alice_dh_priv)
            .await
            .unwrap();

        // 4. Alice encrypts Message 0
        let payload_sent = MessagePayload {
            payload_type: MessageType::Text as u8,
            content: b"Hello Bob, this is a secure chat.".to_vec(),
        };

        let envelope = manager
            .encrypt(
                alice_device_id,
                bob_device_id,
                Uuid::new_v4(),
                &alice_sig_priv,
                &payload_sent,
            )
            .await
            .unwrap();

        // 5. Bob (Receiver) gets message, executes receiver X3DH to establish session
        // DH1 = DH(bob_signed_prekey_private, alice_identity_dh_public)
        let dh1 = ctx
            .crypto
            .diffie_hellman(&bob_spk_priv, &alice_dh_pub)
            .unwrap();
        // DH2 = DH(bob_identity_dh_private, alice_ephemeral_public)
        let dh2 = ctx
            .crypto
            .diffie_hellman(&bob_dh_priv, &envelope.dh_pub)
            .unwrap();
        // DH3 = DH(bob_signed_prekey_private, alice_ephemeral_public)
        let dh3 = ctx
            .crypto
            .diffie_hellman(&bob_spk_priv, &envelope.dh_pub)
            .unwrap();
        // DH4 = DH(bob_one_time_key_private, alice_ephemeral_public)
        let dh4 = ctx
            .crypto
            .diffie_hellman(&bob_otk_priv, &envelope.dh_pub)
            .unwrap();

        let mut ikm = Vec::new();
        ikm.extend_from_slice(&dh1);
        ikm.extend_from_slice(&dh2);
        ikm.extend_from_slice(&dh3);
        ikm.extend_from_slice(&dh4);

        let shared_secret = hkdf_sha256(
            &[0u8; 32],
            &ikm,
            b"VeilX3DHSessionSetupInfo",
            64,
            &ctx.crypto,
        )
        .unwrap();
        let rk = shared_secret[0..32].to_vec();
        let ckr = shared_secret[32..64].to_vec();

        let bob_state = DoubleRatchetState {
            dhs_priv: bob_spk_priv,
            dhs_pub: bob_spk_pub,
            dhr_pub: Some(envelope.dh_pub.clone()),
            rk,
            cks: None,
            ckr: Some(ckr),
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: HashMap::new(),
        };

        // Bob saves Bob's session
        let serialized_bob = ciborium_serialize(&bob_state).unwrap();
        let encrypted_bob = ctx
            .crypto
            .encrypt_symmetric(&ctx.server_state_key, &serialized_bob)
            .unwrap();
        ctx.repo
            .save_session(
                &Uuid::new_v4(),
                &bob_device_id,
                &alice_device_id,
                "1.0",
                &encrypted_bob,
                0,
            )
            .await
            .unwrap();

        // 6. Bob decrypts Alice's envelope message
        let payload_recv = manager
            .decrypt(
                bob_device_id,
                alice_device_id,
                &envelope,
                &alice_sig_pub,
                &bob_dh_priv,
            )
            .await
            .unwrap();

        assert_eq!(payload_sent.content, payload_recv.content);
    }

    #[tokio::test]
    async fn test_replay_attack_rejection() {
        let ctx = setup_context();
        let message_id = Uuid::new_v4();

        // First attempt must succeed
        let first = ctx.repo.add_to_cache(&message_id).await.unwrap();
        assert!(first);

        // Second attempt must fail
        let second = ctx.repo.add_to_cache(&message_id).await.unwrap();
        assert!(!second);
    }

    #[tokio::test]
    async fn test_signature_corruption_rejection() {
        let ctx = setup_context();
        let alice_device_id = Uuid::new_v4();
        let bob_device_id = Uuid::new_v4();

        let (alice_sig_pub, _alice_sig_priv) = ctx
            .crypto
            .generate_keypair(crate::domain::KeyCurve::Ed25519)
            .unwrap();

        let envelope = Envelope {
            message_id: Uuid::new_v4(),
            conversation_id: Uuid::new_v4(),
            sender_device_id: alice_device_id,
            recipient_device_id: bob_device_id,
            timestamp: Utc::now().timestamp_millis(),
            dh_pub: vec![0u8; 32],
            ciphertext: b"some secret data".to_vec(),
            signature: vec![9u8; 64], // corrupted
            major_version: 1,
            minor_version: 0,
            message_number: 0,
        };

        // Decrypt must fail verification
        let manager = CryptoManager::new(
            &ctx.repo,
            &ctx.repo,
            &ctx.repo,
            &ctx.crypto,
            ctx.server_state_key.clone(),
        );

        let result = manager
            .decrypt(
                bob_device_id,
                alice_device_id,
                &envelope,
                &alice_sig_pub,
                &[0u8; 32],
            )
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_cbor_fuzz_parser_failures() {
        let bad_bytes = b"invalid_binary_cbor_fuzz_payload_12345";
        let result = Envelope::from_cbor(bad_bytes);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_x3dh_missing_opk() {
        let ctx = setup_context();
        let alice_device_id = Uuid::new_v4();
        let bob_device_id = Uuid::new_v4();

        let (alice_sig_pub, alice_sig_priv) = ctx
            .crypto
            .generate_keypair(crate::domain::KeyCurve::Ed25519)
            .unwrap();
        let (alice_dh_pub, alice_dh_priv) = ctx
            .crypto
            .generate_keypair(crate::domain::KeyCurve::X25519)
            .unwrap();
        let _alice_dh_sig = ctx
            .crypto
            .sign_ed25519(&alice_sig_priv, &alice_dh_pub)
            .unwrap();

        let (bob_sig_pub, bob_sig_priv) = ctx
            .crypto
            .generate_keypair(crate::domain::KeyCurve::Ed25519)
            .unwrap();
        let (bob_dh_pub, bob_dh_priv) = ctx
            .crypto
            .generate_keypair(crate::domain::KeyCurve::X25519)
            .unwrap();
        let bob_dh_sig = ctx.crypto.sign_ed25519(&bob_sig_priv, &bob_dh_pub).unwrap();

        let (bob_spk_pub, _bob_spk_priv) = ctx
            .crypto
            .generate_keypair(crate::domain::KeyCurve::X25519)
            .unwrap();
        let bob_spk_sig = ctx
            .crypto
            .sign_ed25519(&bob_sig_priv, &bob_spk_pub)
            .unwrap();

        // Register Bob's keys (no OPK)
        ctx.repo
            .save_identity_key(
                &bob_device_id,
                &bob_sig_pub,
                &bob_dh_pub,
                &bob_dh_sig,
                &bob_spk_pub,
                &bob_spk_sig,
            )
            .await
            .unwrap();

        let manager = CryptoManager::new(
            &ctx.repo,
            &ctx.repo,
            &ctx.repo,
            &ctx.crypto,
            ctx.server_state_key.clone(),
        );

        let result = manager
            .establish_session(alice_device_id, bob_device_id, &alice_dh_priv)
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_x3dh_invalid_prekey_signature() {
        let ctx = setup_context();
        let alice_device_id = Uuid::new_v4();
        let bob_device_id = Uuid::new_v4();

        let (_alice_sig_pub, _alice_sig_priv) = ctx
            .crypto
            .generate_keypair(crate::domain::KeyCurve::Ed25519)
            .unwrap();
        let (_alice_dh_pub, alice_dh_priv) = ctx
            .crypto
            .generate_keypair(crate::domain::KeyCurve::X25519)
            .unwrap();

        let (bob_sig_pub, bob_sig_priv) = ctx
            .crypto
            .generate_keypair(crate::domain::KeyCurve::Ed25519)
            .unwrap();
        let (bob_dh_pub, _bob_dh_priv) = ctx
            .crypto
            .generate_keypair(crate::domain::KeyCurve::X25519)
            .unwrap();
        let bob_dh_sig = ctx.crypto.sign_ed25519(&bob_sig_priv, &bob_dh_pub).unwrap();

        let (bob_spk_pub, _bob_spk_priv) = ctx
            .crypto
            .generate_keypair(crate::domain::KeyCurve::X25519)
            .unwrap();
        // Corrupted signed prekey signature
        let corrupt_sig = vec![9u8; 64];

        ctx.repo
            .save_identity_key(
                &bob_device_id,
                &bob_sig_pub,
                &bob_dh_pub,
                &bob_dh_sig,
                &bob_spk_pub,
                &corrupt_sig,
            )
            .await
            .unwrap();

        let manager = CryptoManager::new(
            &ctx.repo,
            &ctx.repo,
            &ctx.repo,
            &ctx.crypto,
            ctx.server_state_key.clone(),
        );

        let result = manager
            .establish_session(alice_device_id, bob_device_id, &alice_dh_priv)
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_double_ratchet_out_of_order_and_lost_messages() {
        let ctx = setup_context();
        let alice_device_id = Uuid::new_v4();
        let bob_device_id = Uuid::new_v4();

        let alice_dhs_priv = vec![1u8; 32];
        let alice_dhs_pub = vec![2u8; 32];
        let bob_dhs_priv = vec![3u8; 32];
        let bob_dhs_pub = vec![4u8; 32];

        let rk = vec![5u8; 32];
        let ck_send = vec![6u8; 32];
        let ck_recv = vec![6u8; 32];

        let alice_state = DoubleRatchetState {
            dhs_priv: alice_dhs_priv.clone(),
            dhs_pub: alice_dhs_pub.clone(),
            dhr_pub: Some(bob_dhs_pub.clone()),
            rk: rk.clone(),
            cks: Some(ck_send.clone()),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: HashMap::new(),
        };

        let bob_state = DoubleRatchetState {
            dhs_priv: bob_dhs_priv.clone(),
            dhs_pub: bob_dhs_pub.clone(),
            dhr_pub: Some(alice_dhs_pub.clone()),
            rk: rk.clone(),
            cks: None,
            ckr: Some(ck_recv.clone()),
            ns: 0,
            nr: 0,
            pn: 0,
            mkskipped: HashMap::new(),
        };

        let ser_alice = ciborium_serialize(&alice_state).unwrap();
        let enc_alice = ctx
            .crypto
            .encrypt_symmetric(&ctx.server_state_key, &ser_alice)
            .unwrap();
        ctx.repo
            .save_session(
                &Uuid::new_v4(),
                &alice_device_id,
                &bob_device_id,
                "1.0",
                &enc_alice,
                0,
            )
            .await
            .unwrap();

        let ser_bob = ciborium_serialize(&bob_state).unwrap();
        let enc_bob = ctx
            .crypto
            .encrypt_symmetric(&ctx.server_state_key, &ser_bob)
            .unwrap();
        ctx.repo
            .save_session(
                &Uuid::new_v4(),
                &bob_device_id,
                &alice_device_id,
                "1.0",
                &enc_bob,
                0,
            )
            .await
            .unwrap();

        let (alice_sig_pub, alice_sig_priv) = ctx
            .crypto
            .generate_keypair(crate::domain::KeyCurve::Ed25519)
            .unwrap();
        let (bob_sig_pub, _bob_sig_priv) = ctx
            .crypto
            .generate_keypair(crate::domain::KeyCurve::Ed25519)
            .unwrap();

        let manager = CryptoManager::new(
            &ctx.repo,
            &ctx.repo,
            &ctx.repo,
            &ctx.crypto,
            ctx.server_state_key.clone(),
        );

        let p0 = MessagePayload {
            payload_type: 0,
            content: b"Msg 0".to_vec(),
        };
        let p1 = MessagePayload {
            payload_type: 0,
            content: b"Msg 1".to_vec(),
        };
        let p2 = MessagePayload {
            payload_type: 0,
            content: b"Msg 2".to_vec(),
        };

        let env0 = manager
            .encrypt(
                alice_device_id,
                bob_device_id,
                Uuid::new_v4(),
                &alice_sig_priv,
                &p0,
            )
            .await
            .unwrap();
        let env1 = manager
            .encrypt(
                alice_device_id,
                bob_device_id,
                Uuid::new_v4(),
                &alice_sig_priv,
                &p1,
            )
            .await
            .unwrap();
        let env2 = manager
            .encrypt(
                alice_device_id,
                bob_device_id,
                Uuid::new_v4(),
                &alice_sig_priv,
                &p2,
            )
            .await
            .unwrap();

        // Decrypt Msg 2 first
        let recv2 = manager
            .decrypt(
                bob_device_id,
                alice_device_id,
                &env2,
                &alice_sig_pub,
                &bob_dhs_priv,
            )
            .await
            .unwrap();
        assert_eq!(recv2.content, b"Msg 2");

        // Decrypt Msg 0
        let recv0 = manager
            .decrypt(
                bob_device_id,
                alice_device_id,
                &env0,
                &alice_sig_pub,
                &bob_dhs_priv,
            )
            .await
            .unwrap();
        assert_eq!(recv0.content, b"Msg 0");

        // Decrypt Msg 1
        let recv1 = manager
            .decrypt(
                bob_device_id,
                alice_device_id,
                &env1,
                &alice_sig_pub,
                &bob_dhs_priv,
            )
            .await
            .unwrap();
        assert_eq!(recv1.content, b"Msg 1");
    }

    #[tokio::test]
    async fn test_replay_cache_reconnect() {
        let ctx = setup_context();
        let message_id = Uuid::new_v4();

        // Save once
        let saved = ctx.repo.add_to_cache(&message_id).await.unwrap();
        assert!(saved);

        // Try again: must fail
        let saved_again = ctx.repo.add_to_cache(&message_id).await.unwrap();
        assert!(!saved_again);
    }

    #[tokio::test]
    async fn test_secure_attachments_upload_and_download() {
        use crate::domain::messaging::AttachmentBlob;
        use crate::domain::repositories::AttachmentRepository;
        use crate::infrastructure::repositories::in_memory::InMemoryRepository;

        let repo = InMemoryRepository::new();
        let blob_id = Uuid::new_v4();
        let uploader_device_id = Uuid::new_v4();
        let conversation_id = Uuid::new_v4();

        // 1. Create a mock blob
        let blob = AttachmentBlob {
            id: blob_id,
            uploader_device_id,
            conversation_id,
            message_id: None,
            file_size: 100,
            file_hash: vec![1, 2, 3, 4],
            mime_type: "image/png".to_string(),
            blob_version: 1,
            blob_encryption_version: 1,
            compression_flag: false,
            chunk_count: 2,
            uploaded_chunks: vec![],
            is_completed: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            deleted_at: None,
        };

        repo.create_blob(&blob).await.unwrap();

        // Retrieve and check
        let fetched = repo.get_blob_by_id(&blob_id).await.unwrap().unwrap();
        assert_eq!(fetched.chunk_count, 2);
        assert!(!fetched.is_completed);

        // 2. Update upload progress
        repo.update_blob_progress(&blob_id, &[0], false)
            .await
            .unwrap();
        let progress = repo.get_blob_by_id(&blob_id).await.unwrap().unwrap();
        assert_eq!(progress.uploaded_chunks, vec![0]);
        assert!(!progress.is_completed);

        // Complete upload
        repo.update_blob_progress(&blob_id, &[0, 1], true)
            .await
            .unwrap();
        let completed = repo.get_blob_by_id(&blob_id).await.unwrap().unwrap();
        assert_eq!(completed.uploaded_chunks, vec![0, 1]);
        assert!(completed.is_completed);

        // 3. Bind to message
        let message_id = Uuid::new_v4();
        repo.bind_blob_to_message(&blob_id, &message_id)
            .await
            .unwrap();
        let bound = repo.get_blob_by_id(&blob_id).await.unwrap().unwrap();
        assert_eq!(bound.message_id, Some(message_id));

        // 4. Test soft-deletion and expiration
        let unreferenced = repo.get_unreferenced_blobs(0).await.unwrap();
        // Since it is referenced (message_id is Some), it should not appear in unreferenced
        assert!(unreferenced.is_empty());

        // Create an unreferenced blob
        let orphan_id = Uuid::new_v4();
        let orphan = AttachmentBlob {
            id: orphan_id,
            uploader_device_id,
            conversation_id,
            message_id: None,
            file_size: 50,
            file_hash: vec![5, 6, 7],
            mime_type: "text/plain".to_string(),
            blob_version: 1,
            blob_encryption_version: 1,
            compression_flag: false,
            chunk_count: 1,
            uploaded_chunks: vec![],
            is_completed: false,
            created_at: Utc::now() - chrono::Duration::hours(25),
            updated_at: Utc::now(),
            deleted_at: None,
        };
        repo.create_blob(&orphan).await.unwrap();

        let unreferenced_list = repo.get_unreferenced_blobs(24).await.unwrap();
        assert_eq!(unreferenced_list.len(), 1);
        assert_eq!(unreferenced_list[0].id, orphan_id);

        // Soft delete the orphan
        repo.soft_delete_blob(&orphan_id).await.unwrap();
        let deleted = repo.get_blob_by_id(&orphan_id).await.unwrap().unwrap();
        assert!(deleted.deleted_at.is_some());

        // Check expired blobs (for 7 days, we mock it by modifying created_at/deleted_at or using 0 days here)
        let expired = repo.get_expired_blobs(0).await.unwrap();
        assert_eq!(expired.len(), 1);

        // Delete permanently
        repo.delete_blob_permanently(&orphan_id).await.unwrap();
        let missing = repo.get_blob_by_id(&orphan_id).await.unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn test_webrtc_signaling_parsing() {
        use crate::presentation::ws::VoIpSignalingFrame;

        let frame = VoIpSignalingFrame {
            message_id: Uuid::new_v4(),
            sender_device_id: Uuid::new_v4(),
            recipient_device_id: Uuid::new_v4(),
            signal_type: 8, // Offer
            sdp_or_candidate: "v=0\no=alice...".to_string(),
            timestamp: 123456789,
        };

        let bin = frame.to_cbor().unwrap();
        let decoded = VoIpSignalingFrame::from_cbor(&bin).unwrap();

        assert_eq!(decoded.signal_type, 8);
        assert_eq!(decoded.sdp_or_candidate, "v=0\no=alice...");
    }
}
