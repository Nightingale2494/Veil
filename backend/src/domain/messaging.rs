// backend/src/domain/messaging.rs

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::domain::Error;

// Binary Message Type Enum matching CBOR compact payloads
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    Text = 0,
    Image = 1,
    Video = 2,
    Voice = 3,
    Receipt = 4,
    Typing = 5,
    Reaction = 6,
    System = 7,
    CallOffer = 8,
    CallAnswer = 9,
    CallIceCandidate = 10,
    CallDecline = 11,
}

impl MessageType {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(Self::Text),
            1 => Some(Self::Image),
            2 => Some(Self::Video),
            3 => Some(Self::Voice),
            4 => Some(Self::Receipt),
            5 => Some(Self::Typing),
            6 => Some(Self::Reaction),
            7 => Some(Self::System),
            8 => Some(Self::CallOffer),
            9 => Some(Self::CallAnswer),
            10 => Some(Self::CallIceCandidate),
            11 => Some(Self::CallDecline),
            _ => None,
        }
    }
}

// Binary Encrypted Envelope Schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub message_id: Uuid,
    pub conversation_id: Uuid,
    pub sender_device_id: Uuid,
    pub recipient_device_id: Uuid,
    pub timestamp: i64,  // millisecond epoch
    pub dh_pub: Vec<u8>, // Sender's current DH X25519 public key (32 bytes)
    pub ciphertext: Vec<u8>,
    pub signature: Vec<u8>, // Ed25519 signature computed over all fields
    pub major_version: u8,
    pub minor_version: u8,
    pub message_number: u32,
}

// Unencrypted inner payload structure (to be CBOR-serialized then encrypted as Envelope.ciphertext)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagePayload {
    pub payload_type: u8, // MessageType repr
    pub content: Vec<u8>, // Encrypted text UTF-8 or media metadata
}

// Double Ratchet Serialized State
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoubleRatchetState {
    pub dhs_priv: Vec<u8>,        // Active local DH X25519 private key (32 bytes)
    pub dhs_pub: Vec<u8>,         // Active local DH X25519 public key (32 bytes)
    pub dhr_pub: Option<Vec<u8>>, // Last received remote DH X25519 public key (32 bytes)
    pub rk: Vec<u8>,              // Root Key (32 bytes)
    pub cks: Option<Vec<u8>>,     // Chain Key Sender (32 bytes)
    pub ckr: Option<Vec<u8>>,     // Chain Key Receiver (32 bytes)
    pub ns: u32,                  // Message sequence number for sending chain
    pub nr: u32,                  // Message sequence number for receiving chain
    pub pn: u32,                  // Previous chain length
    pub mkskipped: HashMap<String, Vec<u8>>, // Skipped message keys mapped as "hex_dhr_pub:sequence" -> key
}

// X3DH Pre-Key Bundle fetched from server to initiate E2E chat session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreKeyBundle {
    pub device_id: Uuid,
    pub identity_signing_key: Vec<u8>, // long-term Ed25519 identity key
    pub identity_dh_key: Vec<u8>,      // long-term X25519 identity key
    pub identity_dh_signature: Vec<u8>, // signature of identity_dh_key under identity_signing_key
    pub signed_prekey: Vec<u8>,        // X25519 signed prekey
    pub prekey_signature: Vec<u8>,     // signature of signed_prekey under identity_signing_key
    pub one_time_key: Option<Vec<u8>>, // Optional one-time prekey
    pub bundle_version: u32,           // for future protocol iterations
}

// Helper serializers
impl Envelope {
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        let mut buffer = Vec::new();
        ciborium::into_writer(self, &mut buffer)
            .map_err(|e| Error::ValidationError(format!("CBOR serialization error: {}", e)))?;
        Ok(buffer)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        let val: Self = ciborium::from_reader(bytes)
            .map_err(|e| Error::ValidationError(format!("CBOR deserialization error: {}", e)))?;
        Ok(val)
    }
}

// Secure Attachment Blob tracker
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentBlob {
    pub id: Uuid,
    pub uploader_device_id: Uuid,
    pub conversation_id: Uuid,
    pub message_id: Option<Uuid>,
    pub file_size: i64,
    pub file_hash: Vec<u8>,
    pub mime_type: String,
    pub blob_version: i32,
    pub blob_encryption_version: i32,
    pub compression_flag: bool,
    pub chunk_count: i32,
    pub uploaded_chunks: Vec<i32>,
    pub is_completed: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
}
