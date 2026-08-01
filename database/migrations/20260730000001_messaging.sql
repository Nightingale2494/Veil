-- database/migrations/20260730000001_messaging.sql

-- 1. Clean up old user-linked prekey tables
DROP TABLE IF EXISTS one_time_keys CASCADE;
DROP TABLE IF EXISTS identity_keys CASCADE;

-- 2. Re-create prekey bundle tables mapped to device_id (with independent identity keys)
CREATE TABLE identity_keys (
    device_id UUID PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    identity_signing_key BYTEA NOT NULL, -- Device's long-term Ed25519 public key (32-byte)
    identity_dh_key BYTEA NOT NULL, -- Device's long-term X25519 public key (32-byte)
    identity_dh_signature BYTEA NOT NULL, -- Ed25519 signature of identity_dh_key under identity_signing_key (64-byte)
    signed_prekey BYTEA NOT NULL, -- X25519 Signed Prekey (32-byte)
    prekey_signature BYTEA NOT NULL, -- Ed25519 signature of signed_prekey under identity_signing_key (64-byte)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE TABLE one_time_keys (
    id SERIAL PRIMARY KEY,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    key_value BYTEA NOT NULL, -- X25519 Public Key (32-byte)
    used BOOLEAN DEFAULT FALSE NOT NULL
);

-- 3. Create device sessions table storing encrypted ratchet state and queryable metadata
CREATE TABLE device_sessions (
    id UUID PRIMARY KEY,
    sender_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    recipient_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    session_version VARCHAR(10) DEFAULT '1.0' NOT NULL, -- e.g. "1.0"
    encrypted_ratchet_state BYTEA NOT NULL, -- CBOR serialized state encrypted at rest
    last_message_number INT DEFAULT 0 NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE TRIGGER update_device_sessions_modtime 
BEFORE UPDATE ON device_sessions 
FOR EACH ROW EXECUTE FUNCTION update_modified_column();

-- Prevent duplicate sessions between same devices
CREATE UNIQUE INDEX idx_sender_recipient_device ON device_sessions(sender_device_id, recipient_device_id);

-- 4. Create replay cache table for transport-layer deduplication
CREATE TABLE replay_cache (
    message_id UUID PRIMARY KEY,
    processed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE INDEX idx_replay_processed_at ON replay_cache(processed_at);
