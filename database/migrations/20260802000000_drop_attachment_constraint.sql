-- Drop foreign key constraint on message_id in attachment_blobs

ALTER TABLE attachment_blobs DROP CONSTRAINT IF EXISTS attachment_blobs_message_id_fkey;
ALTER TABLE attachment_blobs DROP CONSTRAINT IF EXISTS attachment_blobs_msg_id_fkey;
