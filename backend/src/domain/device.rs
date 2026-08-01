// backend/src/domain/device.rs

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "device_approval_status", rename_all = "lowercase")]
pub enum DeviceApprovalStatus {
    Pending,
    Approved,
    Rejected,
}

impl DeviceApprovalStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Rejected => "rejected",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "approved" => Some(Self::Approved),
            "rejected" => Some(Self::Rejected),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: Uuid,
    pub user_id: Uuid,
    pub device_name: String,
    pub device_type: String,
    pub platform: String,
    pub app_version: String,
    pub device_public_key: Vec<u8>,
    pub approval_status: DeviceApprovalStatus,
    pub verification_fingerprint: String,
    pub created_at: DateTime<Utc>,
    pub last_active_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}
