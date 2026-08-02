-- Clean up any invalid message_id mappings to preserve referential integrity before adding the constraint
UPDATE attachment_blobs 
SET message_id = NULL 
WHERE message_id IS NOT NULL 
  AND message_id NOT IN (SELECT id FROM pending_messages);

-- Restore the foreign key constraint
ALTER TABLE attachment_blobs 
  DROP CONSTRAINT IF EXISTS attachment_blobs_message_id_fkey;

ALTER TABLE attachment_blobs 
  ADD CONSTRAINT attachment_blobs_message_id_fkey 
  FOREIGN KEY (message_id) 
  REFERENCES pending_messages(id) 
  ON DELETE SET NULL;
