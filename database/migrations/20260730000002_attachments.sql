-- database/migrations/20260730000002_attachments.sql

CREATE TABLE attachment_blobs (
    id UUID PRIMARY KEY, -- Random UUIDv4 only
    uploader_device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    conversation_id UUID NOT NULL, -- Logical group scope
    message_id UUID REFERENCES pending_messages(id) ON DELETE SET NULL, -- References message in the queue
    file_size BIGINT NOT NULL,
    file_hash BYTEA NOT NULL, -- SHA-256 of completed ciphertext
    mime_type VARCHAR(255) NOT NULL,
    blob_version INT DEFAULT 1 NOT NULL,
    blob_encryption_version INT DEFAULT 1 NOT NULL, -- 1 = ChaCha20-Poly1305
    compression_flag BOOLEAN DEFAULT FALSE NOT NULL,
    chunk_count INT DEFAULT 1 NOT NULL,
    uploaded_chunks INT[] DEFAULT '{}'::INT[] NOT NULL, -- Track uploaded chunk indexes for resumption
    is_completed BOOLEAN DEFAULT FALSE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    deleted_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_blobs_hash ON attachment_blobs(file_hash);
CREATE INDEX idx_blobs_uploader ON attachment_blobs(uploader_device_id);
CREATE INDEX idx_blobs_conversation ON attachment_blobs(conversation_id);
CREATE INDEX idx_blobs_message ON attachment_blobs(message_id);

CREATE TRIGGER update_attachment_blobs_modtime 
BEFORE UPDATE ON attachment_blobs 
FOR EACH ROW EXECUTE FUNCTION update_modified_column();
