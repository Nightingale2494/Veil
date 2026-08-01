-- database/migrations/20260730000000_init.sql

-- Setup Enums
CREATE TYPE friend_status AS ENUM ('pending_sent', 'pending_received', 'accepted', 'blocked');
CREATE TYPE device_approval_status AS ENUM ('pending', 'approved', 'rejected');
CREATE TYPE message_delivery_status AS ENUM ('queued', 'delivered', 'acknowledged', 'expired');

-- Trigger to update updated_at automatically
CREATE OR REPLACE FUNCTION update_modified_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Reserved Usernames table
CREATE TABLE reserved_usernames (
    username VARCHAR(20) PRIMARY KEY
);

-- Populate initial reserved usernames
INSERT INTO reserved_usernames (username) VALUES
('admin'), ('administrator'), ('support'), ('system'), ('veil'), ('root'), ('owner'), ('moderator');

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY,
    username VARCHAR(20) UNIQUE NOT NULL,
    account_id VARCHAR(14) UNIQUE NOT NULL, -- Format: VX7A-82KF-1QPL
    password_hash VARCHAR(255) NOT NULL, -- Argon2id hash
    recovery_key_hash VARCHAR(255) NOT NULL, -- Argon2id hash (BIP-39 hash)
    display_name VARCHAR(100),
    avatar_blob_id UUID, -- Encrypted file reference
    bio TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    deleted_at TIMESTAMP WITH TIME ZONE, -- Soft delete support
    
    -- Format constraints
    CONSTRAINT check_username_format CHECK (username ~ '^[a-z0-9_\.]{3,20}$'),
    CONSTRAINT check_account_id_format CHECK (account_id ~ '^[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$')
);

CREATE TRIGGER update_users_modtime BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_modified_column();

-- User Devices (tracks active client installations)
CREATE TABLE devices (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_name VARCHAR(100) NOT NULL, -- e.g. Pixel 9
    device_type VARCHAR(50) NOT NULL, -- e.g. Phone, Desktop
    platform VARCHAR(50) NOT NULL, -- e.g. Android, iOS, Windows
    app_version VARCHAR(20) NOT NULL, -- e.g. 1.0.0
    device_public_key BYTEA NOT NULL, -- Device-specific public key
    approval_status device_approval_status DEFAULT 'pending' NOT NULL,
    verification_fingerprint VARCHAR(64) NOT NULL, -- Fingerprint representation
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    last_active_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    deleted_at TIMESTAMP WITH TIME ZONE -- Soft delete support
);

-- Encrypted keys storage for backup & multi-device transfer
CREATE TABLE encrypted_keys (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
    key_type VARCHAR(50) NOT NULL, -- 'master_identity_private', 'device_private'
    encrypted_key_data BYTEA NOT NULL, -- Encrypted locally using password-derived key
    key_version INT DEFAULT 1 NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Master Identity Keys for E2E Setup (Extended Triple Diffie-Hellman - X3DH)
CREATE TABLE identity_keys (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    identity_key BYTEA NOT NULL, -- Master Ed25519 Public Key (32 bytes)
    signed_prekey BYTEA NOT NULL, -- X25519 Public Key (32 bytes)
    prekey_signature BYTEA NOT NULL, -- Ed25519 signature of the signed_prekey (64 bytes)
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- One-Time Prekeys for X3DH (consumed on initial session handshake)
CREATE TABLE one_time_keys (
    id SERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_value BYTEA NOT NULL, -- X25519 Public Key (32 bytes)
    used BOOLEAN DEFAULT FALSE NOT NULL
);

-- Friend System (bi-directional relations)
CREATE TABLE friends (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    friend_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status friend_status NOT NULL,
    requested_by UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE, -- Identifies requester
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    PRIMARY KEY (user_id, friend_id),
    CONSTRAINT check_not_self_friend CHECK (user_id <> friend_id)
);

CREATE TRIGGER update_friends_modtime BEFORE UPDATE ON friends FOR EACH ROW EXECUTE FUNCTION update_modified_column();

-- Sessions table for token management (never storing raw refresh tokens or access tokens)
CREATE TABLE sessions (
    id UUID PRIMARY KEY,
    device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    access_token_hash VARCHAR(64) UNIQUE NOT NULL, -- SHA-256 hash of random 256-bit access token
    refresh_token_hash VARCHAR(64) UNIQUE NOT NULL, -- HMAC-SHA256 hash of random 256-bit refresh token
    ip_hash VARCHAR(255),
    revoked BOOLEAN DEFAULT FALSE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

-- Temporary Message Store (Relay queue: deleted after delivery/ack)
CREATE TABLE pending_messages (
    id UUID PRIMARY KEY,
    sender_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    client_message_id UUID NOT NULL, -- Client-generated UUID, server acts only as relay
    encrypted_payload BYTEA NOT NULL, -- E2E encrypted ciphertext
    message_type VARCHAR(50) DEFAULT 'text' NOT NULL, -- metadata
    message_size INT NOT NULL, -- metadata
    delivery_status message_delivery_status DEFAULT 'queued' NOT NULL,
    retry_count INT DEFAULT 0 NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    server_received_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL -- auto-expiry (7 days)
);

-- Attachments Table (supports future Phase 6 file uploads)
CREATE TABLE attachments (
    id UUID PRIMARY KEY,
    pending_message_id UUID NOT NULL REFERENCES pending_messages(id) ON DELETE CASCADE,
    blob_id UUID NOT NULL, -- References external encrypted object store
    encrypted_key BYTEA NOT NULL, -- E2E encrypted key specific to this file blob
    mime_type VARCHAR(100) NOT NULL,
    file_size INT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- User Settings Table
CREATE TABLE user_settings (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    theme VARCHAR(20) DEFAULT 'dark' NOT NULL,
    language VARCHAR(10) DEFAULT 'en' NOT NULL,
    notifications_enabled BOOLEAN DEFAULT TRUE NOT NULL,
    read_receipts_enabled BOOLEAN DEFAULT TRUE NOT NULL,
    typing_indicator_enabled BOOLEAN DEFAULT TRUE NOT NULL,
    last_seen_enabled BOOLEAN DEFAULT TRUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

CREATE TRIGGER update_user_settings_modtime BEFORE UPDATE ON user_settings FOR EACH ROW EXECUTE FUNCTION update_modified_column();

-- Login Attempts (brute-force detection)
CREATE TABLE login_attempts (
    id UUID PRIMARY KEY,
    ip_hash VARCHAR(255) NOT NULL,
    username VARCHAR(50) NOT NULL,
    user_agent TEXT,
    device_fingerprint VARCHAR(64),
    attempt_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    successful BOOLEAN NOT NULL
);

-- Recovery Attempts (rate-limiting recovery)
CREATE TABLE recovery_attempts (
    id UUID PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    ip_hash VARCHAR(255) NOT NULL,
    attempt_time TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    successful BOOLEAN NOT NULL
);

-- Audit Log Table (Only logs security-relevant metadata)
CREATE TABLE audit_log (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    event_type VARCHAR(50) NOT NULL, -- 'device_added', 'password_changed', 'login_success', 'account_recovered', etc.
    ip_hash VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- High-performance database indexes
CREATE INDEX idx_users_username ON users(username) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_account_id ON users(account_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_devices_user_id ON devices(user_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_pending_messages_recipient ON pending_messages(recipient_device_id, delivery_status);
CREATE INDEX idx_sessions_access_hash ON sessions(access_token_hash) WHERE revoked = FALSE;
CREATE INDEX idx_sessions_refresh_hash ON sessions(refresh_token_hash) WHERE revoked = FALSE;
CREATE INDEX idx_audit_log_user ON audit_log(user_id);
CREATE INDEX idx_login_attempts_username ON login_attempts(username, attempt_time);
CREATE INDEX idx_recovery_attempts_username ON recovery_attempts(username, attempt_time);
CREATE INDEX idx_attachments_message ON attachments(pending_message_id);
