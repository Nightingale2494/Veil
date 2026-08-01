// backend/src/infrastructure/notifications/mod.rs

use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
pub trait NotificationProvider: Send + Sync {
    async fn send_silent_push(&self, fcm_token: &str, device_id: &Uuid) -> Result<(), crate::domain::Error>;
}

pub struct MockNotificationProvider;

#[async_trait]
impl NotificationProvider for MockNotificationProvider {
    async fn send_silent_push(&self, fcm_token: &str, device_id: &Uuid) -> Result<(), crate::domain::Error> {
        tracing::info!(
            "MOCK FCM: Dispatching silent push to token {} for target device {}",
            fcm_token,
            device_id
        );
        Ok(())
    }
}
