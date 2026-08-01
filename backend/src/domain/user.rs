// backend/src/domain/user.rs

use crate::domain::Error;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub account_id: String,
    pub password_hash: String,
    pub recovery_key_hash: String,
    pub display_name: Option<String>,
    pub avatar_blob_id: Option<Uuid>,
    pub bio: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSettings {
    pub user_id: Uuid,
    pub theme: String,
    pub language: String,
    pub notifications_enabled: bool,
    pub read_receipts_enabled: bool,
    pub typing_indicator_enabled: bool,
    pub last_seen_enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    /// Normalizes a username (converts to lowercase, performs Unicode NFKC normalization,
    /// and validates length/characters).
    pub fn normalize_and_validate_username(raw_username: &str) -> Result<String, Error> {
        // 1. Lowercase
        let lowered = raw_username.to_lowercase();

        // 2. Unicode normalization (NFKC)
        let normalized: String =
            unicode_normalization::UnicodeNormalization::nfkc(lowered.as_str()).collect();

        // 3. Length check
        if normalized.len() < 3 || normalized.len() > 20 {
            return Err(Error::ValidationError(
                "Username must be between 3 and 20 characters long.".to_string(),
            ));
        }

        // 4. Character format check: only allowed characters: a-z, 0-9, _, .
        let is_valid = normalized
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.');

        if !is_valid {
            return Err(Error::ValidationError(
                "Username can only contain lowercase letters, digits, underscores, and dots."
                    .to_string(),
            ));
        }

        Ok(normalized)
    }

    /// Enforces the password validation policy (length check, supports Unicode)
    pub fn validate_password_policy(password: &str) -> Result<(), Error> {
        let len = password.chars().count();
        if len < 12 {
            return Err(Error::ValidationError(
                "Password must be at least 12 characters long.".to_string(),
            ));
        }
        if len > 128 {
            return Err(Error::ValidationError(
                "Password must not exceed 128 characters.".to_string(),
            ));
        }
        Ok(())
    }
}
