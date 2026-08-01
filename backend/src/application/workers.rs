// backend/src/application/workers.rs

use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::{error, info};

use crate::domain::repositories::AttachmentRepository;

pub struct AttachmentCleanupWorker {
    pub repo: Arc<dyn AttachmentRepository>,
}

impl AttachmentCleanupWorker {
    pub fn new(repo: Arc<dyn AttachmentRepository>) -> Self {
        Self { repo }
    }

    pub async fn start(self) {
        info!("Starting Attachment Cleanup background worker loop (runs every hour)...");
        loop {
            // Run every 1 hour
            sleep(Duration::from_secs(3600)).await;

            if let Err(e) = self.run_cleanup().await {
                error!("Attachment cleanup task failed: {}", e);
            }
        }
    }

    pub async fn run_cleanup(&self) -> Result<(), crate::domain::Error> {
        info!("Running attachment soft and physical cleanup pass...");

        // 1. Soft delete unreferenced blobs (older than 24 hours)
        let unreferenced = self.repo.get_unreferenced_blobs(24).await?;
        for blob in &unreferenced {
            info!("Soft deleting orphaned blob: {}", blob.id);
            let _ = self.repo.soft_delete_blob(&blob.id).await;
        }

        // 2. Physical delete expired soft-deleted blobs (older than 7 days)
        let expired = self.repo.get_expired_blobs(7).await?;
        for blob in &expired {
            info!("Physically purging expired blob: {}", blob.id);
            // Delete file from disk
            let file_path = format!("./uploads/{}", blob.id);
            let _ = tokio::fs::remove_file(&file_path).await;

            // Purge any left-over chunk files in case upload was interrupted
            for idx in 0..blob.chunk_count {
                let chunk_path = format!("./uploads/{}_chunk_{}", blob.id, idx);
                let _ = tokio::fs::remove_file(&chunk_path).await;
            }

            // Permanently delete from DB
            let _ = self.repo.delete_blob_permanently(&blob.id).await;
        }

        Ok(())
    }
}
