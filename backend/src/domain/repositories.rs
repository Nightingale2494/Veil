// backend/src/domain/repositories.rs

use crate::domain::device::{Device, DeviceApprovalStatus};
use crate::domain::session::{AuditLog, LoginAttempt, RecoveryAttempt, Session};
use crate::domain::user::{User, UserSettings};
use crate::domain::Error;
use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn create_user(&self, user: &User, settings: &UserSettings) -> Result<(), Error>;
    async fn get_user_by_id(&self, id: &Uuid) -> Result<Option<User>, Error>;
    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, Error>;
    async fn get_user_by_account_id(&self, account_id: &str) -> Result<Option<User>, Error>;
    async fn update_user_password(
        &self,
        user_id: &Uuid,
        password_hash: &str,
        recovery_key_hash: &str,
    ) -> Result<(), Error>;
    async fn is_username_reserved(&self, username: &str) -> Result<bool, Error>;
    async fn get_user_settings(&self, user_id: &Uuid) -> Result<Option<UserSettings>, Error>;
    async fn update_user_settings(&self, settings: &UserSettings) -> Result<(), Error>;
}

#[async_trait]
pub trait DeviceRepository: Send + Sync {
    async fn create_device(&self, device: &Device) -> Result<(), Error>;
    async fn get_device_by_id(&self, id: &Uuid) -> Result<Option<Device>, Error>;
    async fn get_devices_by_user_id(&self, user_id: &Uuid) -> Result<Vec<Device>, Error>;
    async fn update_device_status(
        &self,
        id: &Uuid,
        status: DeviceApprovalStatus,
    ) -> Result<(), Error>;
    async fn count_active_devices_by_user_id(&self, user_id: &Uuid) -> Result<usize, Error>;
    async fn delete_device(&self, id: &Uuid) -> Result<(), Error>;
}

#[async_trait]
pub trait SessionRepository: Send + Sync {
    async fn create_session(&self, session: &Session) -> Result<(), Error>;
    async fn get_session_by_id(&self, id: &Uuid) -> Result<Option<Session>, Error>;
    async fn get_session_by_access_token_hash(&self, hash: &str) -> Result<Option<Session>, Error>;
    async fn get_session_by_refresh_token_hash(&self, hash: &str)
        -> Result<Option<Session>, Error>;
    async fn revoke_session(&self, id: &Uuid) -> Result<(), Error>;
    async fn revoke_all_user_sessions_except(
        &self,
        user_id: &Uuid,
        except_session_id: Option<Uuid>,
    ) -> Result<(), Error>;
}

#[async_trait]
pub trait LoginAttemptRepository: Send + Sync {
    async fn log_attempt(&self, attempt: &LoginAttempt) -> Result<(), Error>;
    async fn count_failed_attempts_in_window(
        &self,
        username: &str,
        ip_hash: &str,
        minutes: i64,
    ) -> Result<usize, Error>;
}

#[async_trait]
pub trait RecoveryAttemptRepository: Send + Sync {
    async fn log_attempt(&self, attempt: &RecoveryAttempt) -> Result<(), Error>;
    async fn count_failed_attempts_in_window(
        &self,
        username: &str,
        ip_hash: &str,
        minutes: i64,
    ) -> Result<usize, Error>;
}

#[async_trait]
pub trait AuditLogRepository: Send + Sync {
    async fn log_event(&self, log: &AuditLog) -> Result<(), Error>;
}

use crate::domain::messaging::PreKeyBundle;

#[async_trait]
pub trait PreKeyRepository: Send + Sync {
    async fn save_identity_key(
        &self,
        device_id: &Uuid,
        identity_signing_key: &[u8],
        identity_dh_key: &[u8],
        identity_dh_signature: &[u8],
        signed_prekey: &[u8],
        prekey_signature: &[u8],
    ) -> Result<(), Error>;
    async fn save_one_time_keys(&self, device_id: &Uuid, keys: &[Vec<u8>]) -> Result<(), Error>;
    async fn get_prekey_bundle(&self, device_id: &Uuid) -> Result<Option<PreKeyBundle>, Error>;
    async fn consume_one_time_key(&self, device_id: &Uuid) -> Result<Option<Vec<u8>>, Error>;
    async fn get_one_time_keys_count(&self, device_id: &Uuid) -> Result<usize, Error>;
}

#[async_trait]
pub trait DeviceSessionRepository: Send + Sync {
    async fn save_session(
        &self,
        session_id: &Uuid,
        sender_device_id: &Uuid,
        recipient_device_id: &Uuid,
        version: &str,
        encrypted_state: &[u8],
        last_msg_num: i32,
    ) -> Result<(), Error>;

    async fn get_session(
        &self,
        sender_device_id: &Uuid,
        recipient_device_id: &Uuid,
    ) -> Result<Option<(Uuid, String, Vec<u8>, i32)>, Error>;

    async fn revoke_session(&self, session_id: &Uuid) -> Result<(), Error>;
}

#[async_trait]
pub trait ReplayCacheRepository: Send + Sync {
    async fn add_to_cache(&self, message_id: &Uuid) -> Result<bool, Error>;
}

use crate::domain::messaging::AttachmentBlob;

#[async_trait]
pub trait AttachmentRepository: Send + Sync {
    async fn create_blob(&self, blob: &AttachmentBlob) -> Result<(), Error>;
    async fn get_blob_by_id(&self, id: &Uuid) -> Result<Option<AttachmentBlob>, Error>;
    async fn update_blob_progress(
        &self,
        id: &Uuid,
        uploaded_chunks: &[i32],
        is_completed: bool,
    ) -> Result<(), Error>;
    async fn bind_blob_to_message(&self, id: &Uuid, message_id: &Uuid) -> Result<(), Error>;
    async fn get_unreferenced_blobs(&self, hours_old: i32) -> Result<Vec<AttachmentBlob>, Error>;
    async fn soft_delete_blob(&self, id: &Uuid) -> Result<(), Error>;
    async fn get_expired_blobs(&self, days_old: i32) -> Result<Vec<AttachmentBlob>, Error>;
    async fn delete_blob_permanently(&self, id: &Uuid) -> Result<(), Error>;
}
