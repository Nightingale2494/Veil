// backend/src/domain/session.rs

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub device_id: Uuid,
    pub access_token_hash: String,
    pub refresh_token_hash: String,
    pub ip_hash: Option<String>,
    pub revoked: bool,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginAttempt {
    pub id: Uuid,
    pub ip_hash: String,
    pub username: String,
    pub user_agent: Option<String>,
    pub device_fingerprint: Option<String>,
    pub attempt_time: DateTime<Utc>,
    pub successful: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryAttempt {
    pub id: Uuid,
    pub username: String,
    pub ip_hash: String,
    pub attempt_time: DateTime<Utc>,
    pub successful: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub id: Uuid,
    pub user_id: Uuid,
    pub device_id: Option<Uuid>,
    pub event_type: String,
    pub ip_hash: Option<String>,
    pub created_at: DateTime<Utc>,
}
