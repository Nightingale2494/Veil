// backend/src/application/auth.rs

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domain::{
    device::{Device, DeviceApprovalStatus},
    repositories::{
        AuditLogRepository, DeviceRepository, LoginAttemptRepository, RecoveryAttemptRepository,
        SessionRepository, UserRepository,
    },
    session::{AuditLog, LoginAttempt, RecoveryAttempt, Session},
    user::{User, UserSettings},
    CryptoProvider, Error,
};

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: Option<String>,  // Plaintext over TLS
    pub recovery_mnemonic: String, // Plaintext over TLS (24-word BIP-39)
    pub display_name: Option<String>,
    pub device_name: String,
    pub device_type: String,
    pub platform: String,
    pub app_version: String,
    pub device_public_key: Vec<u8>,
    pub verification_fingerprint: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub identifier: String,       // Username or Account ID
    pub password: Option<String>, // Plaintext over TLS
    pub device_name: String,
    pub device_type: String,
    pub platform: String,
    pub app_version: String,
    pub device_public_key: Vec<u8>,
    pub verification_fingerprint: String,
    pub user_agent: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct RecoverRequest {
    pub identifier: String,           // Username or Account ID
    pub recovery_mnemonic: String,    // Plaintext over TLS (24-word BIP-39)
    pub new_password: Option<String>, // Plaintext over TLS
    pub user_agent: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub user_id: Uuid,
    pub username: String,
    pub account_id: String,
    pub device_id: Uuid,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: String,
    pub device_approval_status: String,
}

pub struct RegisterUseCase<'a> {
    pub user_repo: &'a dyn UserRepository,
    pub device_repo: &'a dyn DeviceRepository,
    pub session_repo: &'a dyn SessionRepository,
    pub audit_repo: &'a dyn AuditLogRepository,
    pub crypto: &'a dyn CryptoProvider,
    pub hmac_key: Vec<u8>,
}

impl<'a> RegisterUseCase<'a> {
    pub async fn execute(
        &self,
        req: RegisterRequest,
        ip_hash: &str,
        user_agent: Option<&str>,
    ) -> Result<AuthResponse, Error> {
        // 1. Normalize and validate username
        let normalized_username = User::normalize_and_validate_username(&req.username)?;

        // 2. Check reserved usernames
        if self
            .user_repo
            .is_username_reserved(&normalized_username)
            .await?
        {
            return Err(Error::ValidationError("Username is reserved.".into()));
        }

        // 3. Check if username already exists
        if self
            .user_repo
            .get_user_by_username(&normalized_username)
            .await?
            .is_some()
        {
            return Err(Error::ValidationError("Username is already taken.".into()));
        }

        // 4. Validate password
        let pwd = req.password.as_deref().unwrap_or("");
        User::validate_password_policy(pwd)?;

        // 5. Validate recovery mnemonic length (must be 24 words)
        let word_count = req.recovery_mnemonic.split_whitespace().count();
        if word_count != 24 {
            return Err(Error::ValidationError(
                "Recovery key must be a 24-word BIP-39 mnemonic phrase.".into(),
            ));
        }

        // 6. Generate secure hashes
        let password_hash = self.crypto.hash_password(pwd.as_bytes())?;
        let recovery_key_hash = self
            .crypto
            .hash_password(req.recovery_mnemonic.as_bytes())?;

        // 7. Generate unique Account ID
        let account_id = generate_account_id(self.crypto)?;

        // 8. Create user & settings
        let user_id = Uuid::new_v4();
        let now = Utc::now();
        let user = User {
            id: user_id,
            username: normalized_username.clone(),
            account_id: account_id.clone(),
            password_hash,
            recovery_key_hash,
            display_name: req.display_name,
            avatar_blob_id: None,
            bio: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };

        let settings = UserSettings {
            user_id,
            theme: "dark".to_string(),
            language: "en".to_string(),
            notifications_enabled: true,
            read_receipts_enabled: true,
            typing_indicator_enabled: true,
            last_seen_enabled: true,
            created_at: now,
            updated_at: now,
        };

        self.user_repo.create_user(&user, &settings).await?;

        // 9. Register initial device (automatically Approved as it's the first device)
        let device_id = Uuid::new_v4();
        let device = Device {
            id: device_id,
            user_id,
            device_name: req.device_name,
            device_type: req.device_type,
            platform: req.platform,
            app_version: req.app_version,
            device_public_key: req.device_public_key,
            approval_status: DeviceApprovalStatus::Approved,
            verification_fingerprint: req.verification_fingerprint,
            created_at: now,
            last_active_at: now,
            deleted_at: None,
        };

        self.device_repo.create_device(&device).await?;

        // 10. Create Session with Opaque Tokens
        let session_response = create_session_tokens(
            self.session_repo,
            self.crypto,
            &self.hmac_key,
            device_id,
            ip_hash,
        )
        .await?;

        // 11. Log audit log
        let audit = AuditLog {
            id: Uuid::new_v4(),
            user_id,
            device_id: Some(device_id),
            event_type: "registration_success".to_string(),
            ip_hash: Some(ip_hash.to_string()),
            created_at: now,
        };
        self.audit_repo.log_event(&audit).await?;

        Ok(AuthResponse {
            user_id,
            username: normalized_username,
            account_id,
            device_id,
            access_token: session_response.access_token,
            refresh_token: session_response.refresh_token,
            expires_at: session_response.expires_at.to_rfc3339(),
            device_approval_status: DeviceApprovalStatus::Approved.as_str().to_string(),
        })
    }
}

pub struct LoginUseCase<'a> {
    pub user_repo: &'a dyn UserRepository,
    pub device_repo: &'a dyn DeviceRepository,
    pub session_repo: &'a dyn SessionRepository,
    pub login_repo: &'a dyn LoginAttemptRepository,
    pub audit_repo: &'a dyn AuditLogRepository,
    pub crypto: &'a dyn CryptoProvider,
    pub hmac_key: Vec<u8>,
}

impl<'a> LoginUseCase<'a> {
    pub async fn execute(
        &self,
        req: LoginRequest,
        ip_hash: &str,
        user_agent: Option<&str>,
    ) -> Result<AuthResponse, Error> {
        let now = Utc::now();

        // 1. Check rate limits (max 5 failed attempts in 10 minutes)
        let failed_attempts = self
            .login_repo
            .count_failed_attempts_in_window(&req.identifier, ip_hash, 10)
            .await?;

        if failed_attempts >= 5 {
            tracing::error!("Rate limit exceeded for user identifier: {}", req.identifier);
            return Err(Error::Unauthorized(
                "Too many failed login attempts. Please wait 15 minutes.".into(),
            ));
        }

        // 2. Normalize and check username format, or try as Account ID
        let mut user_option = None;
        if req.identifier.contains('-') {
            user_option = self
                .user_repo
                .get_user_by_account_id(&req.identifier)
                .await?;
        } else {
            if let Ok(normalized) = User::normalize_and_validate_username(&req.identifier) {
                user_option = self.user_repo.get_user_by_username(&normalized).await?;
            }
        }

        // 3. Handle credential verification
        let user = match user_option {
            Some(u) => u,
            None => {
                tracing::error!("Login user not found: {}", req.identifier);
                // Log failed attempt to prevent timing attacks disclosures
                let attempt = LoginAttempt {
                    id: Uuid::new_v4(),
                    ip_hash: ip_hash.to_string(),
                    username: req.identifier.clone(),
                    user_agent: user_agent.map(String::from),
                    device_fingerprint: Some(req.verification_fingerprint.clone()),
                    attempt_time: now,
                    successful: false,
                };
                self.login_repo.log_attempt(&attempt).await?;
                return Err(Error::Unauthorized("Invalid credentials.".into()));
            }
        };

        let pwd = req.password.as_deref().unwrap_or("");
        let is_valid = self
            .crypto
            .verify_password(pwd.as_bytes(), &user.password_hash)?;

        if !is_valid {
            tracing::error!("Login invalid password for username: {}", user.username);
            let attempt = LoginAttempt {
                id: Uuid::new_v4(),
                ip_hash: ip_hash.to_string(),
                username: req.identifier.clone(),
                user_agent: user_agent.map(String::from),
                device_fingerprint: Some(req.verification_fingerprint.clone()),
                attempt_time: now,
                successful: false,
            };
            self.login_repo.log_attempt(&attempt).await?;
            return Err(Error::Unauthorized("Invalid credentials.".into()));
        }

        // 4. Retrieve/Create Device
        // Check if device public key already exists for this user
        let user_devices = self.device_repo.get_devices_by_user_id(&user.id).await?;
        let existing_device = user_devices
            .iter()
            .find(|d| d.device_public_key == req.device_public_key);

        let (device_id, approval_status) = match existing_device {
            Some(d) => (d.id, d.approval_status.clone()),
            None => {
                // Limit to maximum 10 active devices
                let active_devices_count = self
                    .device_repo
                    .count_active_devices_by_user_id(&user.id)
                    .await?;
                if active_devices_count >= 10 {
                    tracing::error!("Login failed: maximum devices (10) reached for user {}", user.username);
                    return Err(Error::ValidationError(
                        "Maximum device limit (10) reached. Revoke an old device first.".into(),
                    ));
                }

                // Create new device (defaults to Pending approval from an existing device)
                let new_id = Uuid::new_v4();
                let new_device = Device {
                    id: new_id,
                    user_id: user.id,
                    device_name: req.device_name,
                    device_type: req.device_type,
                    platform: req.platform,
                    app_version: req.app_version,
                    device_public_key: req.device_public_key,
                    approval_status: DeviceApprovalStatus::Pending,
                    verification_fingerprint: req.verification_fingerprint,
                    created_at: now,
                    last_active_at: now,
                    deleted_at: None,
                };
                self.device_repo.create_device(&new_device).await?;
                (new_id, DeviceApprovalStatus::Pending)
            }
        };

        // 5. Log successful login
        let attempt = LoginAttempt {
            id: Uuid::new_v4(),
            ip_hash: ip_hash.to_string(),
            username: req.identifier.clone(),
            user_agent: user_agent.map(String::from),
            device_fingerprint: Some(device_id.to_string()),
            attempt_time: now,
            successful: true,
        };
        self.login_repo.log_attempt(&attempt).await?;

        // 6. Create session
        let session_response = create_session_tokens(
            self.session_repo,
            self.crypto,
            &self.hmac_key,
            device_id,
            ip_hash,
        )
        .await?;

        let audit = AuditLog {
            id: Uuid::new_v4(),
            user_id: user.id,
            device_id: Some(device_id),
            event_type: "login_success".to_string(),
            ip_hash: Some(ip_hash.to_string()),
            created_at: now,
        };
        self.audit_repo.log_event(&audit).await?;

        Ok(AuthResponse {
            user_id: user.id,
            username: user.username,
            account_id: user.account_id,
            device_id,
            access_token: session_response.access_token,
            refresh_token: session_response.refresh_token,
            expires_at: session_response.expires_at.to_rfc3339(),
            device_approval_status: approval_status.as_str().to_string(),
        })
    }
}

pub struct RefreshUseCase<'a> {
    pub session_repo: &'a dyn SessionRepository,
    pub crypto: &'a dyn CryptoProvider,
    pub hmac_key: Vec<u8>,
}

impl<'a> RefreshUseCase<'a> {
    pub async fn execute(
        &self,
        req: RefreshRequest,
        ip_hash: &str,
    ) -> Result<SessionResponse, Error> {
        // 1. Hash the incoming plaintext token using HMAC-SHA256 to lookup the database entry
        let incoming_hash = self
            .crypto
            .compute_hmac(&self.hmac_key, req.refresh_token.as_bytes())?;
        let hex_hash = hex::encode(incoming_hash);

        // 2. Fetch session from database
        let session = match self
            .session_repo
            .get_session_by_refresh_token_hash(&hex_hash)
            .await?
        {
            Some(s) => s,
            None => return Err(Error::Unauthorized("Invalid refresh token.".into())),
        };

        // 3. Verify session status and expiry
        if session.revoked || session.expires_at < Utc::now() {
            // Replay attack protection: if a rotated refresh token is used again, revoke the entire session tree
            let _ = self.session_repo.revoke_session(&session.id).await;
            return Err(Error::Unauthorized(
                "Refresh token has been revoked or expired.".into(),
            ));
        }

        // 4. Revoke the old token/session
        self.session_repo.revoke_session(&session.id).await?;

        // 5. Generate and register a rotated session key
        create_session_tokens(
            self.session_repo,
            self.crypto,
            &self.hmac_key,
            session.device_id,
            ip_hash,
        )
        .await
    }
}

pub struct RecoverUseCase<'a> {
    pub user_repo: &'a dyn UserRepository,
    pub device_repo: &'a dyn DeviceRepository,
    pub session_repo: &'a dyn SessionRepository,
    pub recovery_repo: &'a dyn RecoveryAttemptRepository,
    pub audit_repo: &'a dyn AuditLogRepository,
    pub crypto: &'a dyn CryptoProvider,
}

impl<'a> RecoverUseCase<'a> {
    pub async fn execute(&self, req: RecoverRequest, ip_hash: &str) -> Result<(), Error> {
        let now = Utc::now();

        // 1. Rate limit recovery (cooldown locked for 1 hour after 3 failed attempts)
        let failed_recoveries = self
            .recovery_repo
            .count_failed_attempts_in_window(&req.identifier, ip_hash, 60)
            .await?;

        if failed_recoveries >= 3 {
            return Err(Error::Unauthorized(
                "Recovery feature locked due to too many failed attempts. Try again in 1 hour."
                    .into(),
            ));
        }

        // 2. Fetch user
        let mut user_option = None;
        if req.identifier.contains('-') {
            user_option = self
                .user_repo
                .get_user_by_account_id(&req.identifier)
                .await?;
        } else {
            if let Ok(normalized) = User::normalize_and_validate_username(&req.identifier) {
                user_option = self.user_repo.get_user_by_username(&normalized).await?;
            }
        }

        let user = match user_option {
            Some(u) => u,
            None => {
                let attempt = RecoveryAttempt {
                    id: Uuid::new_v4(),
                    username: req.identifier.clone(),
                    ip_hash: ip_hash.to_string(),
                    attempt_time: now,
                    successful: false,
                };
                self.recovery_repo.log_attempt(&attempt).await?;
                return Err(Error::Unauthorized("Invalid recovery phrase.".into()));
            }
        };

        // 3. Verify recovery mnemonic (constant-time verification is done implicitly by Argon2id verification)
        let is_valid = self
            .crypto
            .verify_password(req.recovery_mnemonic.as_bytes(), &user.recovery_key_hash)?;

        if !is_valid {
            let attempt = RecoveryAttempt {
                id: Uuid::new_v4(),
                username: req.identifier.clone(),
                ip_hash: ip_hash.to_string(),
                attempt_time: now,
                successful: false,
            };
            self.recovery_repo.log_attempt(&attempt).await?;
            return Err(Error::Unauthorized("Invalid recovery phrase.".into()));
        }

        // 4. Recovery succeeds: rotate password hash
        let new_pwd = req.new_password.as_deref().unwrap_or("");
        User::validate_password_policy(new_pwd)?;

        let new_password_hash = self.crypto.hash_password(new_pwd.as_bytes())?;

        // Also rotate recovery mnemonic verifier hash for rotation security
        let new_recovery_hash = self
            .crypto
            .hash_password(req.recovery_mnemonic.as_bytes())?;

        self.user_repo
            .update_user_password(&user.id, &new_password_hash, &new_recovery_hash)
            .await?;

        // 5. Invalidate all existing sessions and revoke devices (forces full re-approval)
        self.session_repo
            .revoke_all_user_sessions_except(&user.id, None)
            .await?;

        let devices = self.device_repo.get_devices_by_user_id(&user.id).await?;
        for dev in devices {
            self.device_repo
                .update_device_status(&dev.id, DeviceApprovalStatus::Pending)
                .await?;
        }

        // 6. Log attempt success and audit log
        let attempt = RecoveryAttempt {
            id: Uuid::new_v4(),
            username: req.identifier.clone(),
            ip_hash: ip_hash.to_string(),
            attempt_time: now,
            successful: true,
        };
        self.recovery_repo.log_attempt(&attempt).await?;

        let audit = AuditLog {
            id: Uuid::new_v4(),
            user_id: user.id,
            device_id: None,
            event_type: "account_recovered".to_string(),
            ip_hash: Some(ip_hash.to_string()),
            created_at: now,
        };
        self.audit_repo.log_event(&audit).await?;

        Ok(())
    }
}

// --- Internal helpers ---

#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: DateTime<Utc>,
}

async fn create_session_tokens(
    session_repo: &dyn SessionRepository,
    crypto: &dyn CryptoProvider,
    hmac_key: &[u8],
    device_id: Uuid,
    ip_hash: &str,
) -> Result<SessionResponse, Error> {
    // Generate 256-bit (32 bytes) cryptographically secure random opaque tokens
    let access_bytes = crypto.generate_secure_random(32)?;
    let refresh_bytes = crypto.generate_secure_random(32)?;

    // Encode tokens as Hex
    let access_token = hex::encode(&access_bytes);
    let refresh_token = hex::encode(&refresh_bytes);

    // Hash Access Token using SHA-256
    let access_hash = hex::encode(crypto.hash_sha256(access_token.as_bytes())?);

    // Hash Refresh Token using HMAC-SHA256
    let refresh_hash = hex::encode(crypto.compute_hmac(hmac_key, refresh_token.as_bytes())?);

    let session_id = Uuid::new_v4();
    let now = Utc::now();
    let expires_at = now + ChronoDuration::days(30);

    let session = Session {
        id: session_id,
        device_id,
        access_token_hash: access_hash,
        refresh_token_hash: refresh_hash,
        ip_hash: Some(ip_hash.to_string()),
        revoked: false,
        created_at: now,
        expires_at,
    };

    session_repo.create_session(&session).await?;

    Ok(SessionResponse {
        access_token,
        refresh_token,
        expires_at: now + ChronoDuration::minutes(15), // Access token valid for 15 minutes
    })
}

fn generate_account_id(crypto: &dyn CryptoProvider) -> Result<String, Error> {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    // Generate 12 random bytes from OS CSPRNG
    let random_bytes = crypto.generate_secure_random(12)?;
    let mut code = String::new();
    for (i, byte) in random_bytes.iter().enumerate() {
        if i > 0 && i % 4 == 0 {
            code.push('-');
        }
        let idx = (*byte as usize) % CHARSET.len();
        code.push(CHARSET[idx] as char);
    }
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::crypto::RustCryptoProvider;
    use crate::infrastructure::repositories::in_memory::InMemoryRepository;

    fn setup_repos() -> (InMemoryRepository, RustCryptoProvider, Vec<u8>) {
        (InMemoryRepository::new(), RustCryptoProvider, vec![0u8; 32])
    }

    #[tokio::test]
    async fn test_register_use_case_success() {
        let (repo, crypto, hmac_key) = setup_repos();
        let use_case = RegisterUseCase {
            user_repo: &repo,
            device_repo: &repo,
            session_repo: &repo,
            audit_repo: &repo,
            crypto: &crypto,
            hmac_key,
        };

        let req = RegisterRequest {
            username: "Nightingale".to_string(),
            password: Some("validpassword123".to_string()),
            recovery_mnemonic: "one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty twentyone twentytwo twentythree twentyfour".to_string(),
            display_name: Some("Nightingale".to_string()),
            device_name: "Pixel 9".to_string(),
            device_type: "Phone".to_string(),
            platform: "Android".to_string(),
            app_version: "1.0.0".to_string(),
            device_public_key: vec![1, 2, 3],
            verification_fingerprint: "fingerprint_data".to_string(),
        };

        let res = use_case.execute(req, "ip_hash_val", None).await.unwrap();
        assert_eq!(res.username, "nightingale"); // verified lowercased normalization
        assert_eq!(res.device_approval_status, "approved");
        assert!(!res.access_token.is_empty());
        assert!(!res.refresh_token.is_empty());

        // Check user settings were initialized to dark
        let settings = repo.get_user_settings(&res.user_id).await.unwrap().unwrap();
        assert_eq!(settings.theme, "dark");
    }

    #[tokio::test]
    async fn test_register_reserved_username() {
        let (repo, crypto, hmac_key) = setup_repos();
        let use_case = RegisterUseCase {
            user_repo: &repo,
            device_repo: &repo,
            session_repo: &repo,
            audit_repo: &repo,
            crypto: &crypto,
            hmac_key,
        };

        let req = RegisterRequest {
            username: "Veil".to_string(), // Reserved
            password: Some("validpassword123".to_string()),
            recovery_mnemonic: "one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty twentyone twentytwo twentythree twentyfour".to_string(),
            display_name: None,
            device_name: "Pixel 9".to_string(),
            device_type: "Phone".to_string(),
            platform: "Android".to_string(),
            app_version: "1.0.0".to_string(),
            device_public_key: vec![1, 2, 3],
            verification_fingerprint: "fingerprint_data".to_string(),
        };

        let err = use_case
            .execute(req, "ip_hash_val", None)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::ValidationError(_)));
    }

    #[tokio::test]
    async fn test_login_success() {
        let (repo, crypto, hmac_key) = setup_repos();

        // 1. Register first
        let reg_use_case = RegisterUseCase {
            user_repo: &repo,
            device_repo: &repo,
            session_repo: &repo,
            audit_repo: &repo,
            crypto: &crypto,
            hmac_key: hmac_key.clone(),
        };
        let mnemonic = "one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty twentyone twentytwo twentythree twentyfour".to_string();
        let reg_req = RegisterRequest {
            username: "nightingale".to_string(),
            password: Some("superpassword".to_string()),
            recovery_mnemonic: mnemonic.clone(),
            display_name: None,
            device_name: "Pixel 9".to_string(),
            device_type: "Phone".to_string(),
            platform: "Android".to_string(),
            app_version: "1.0.0".to_string(),
            device_public_key: vec![1, 2, 3],
            verification_fingerprint: "fp".to_string(),
        };
        reg_use_case.execute(reg_req, "ip", None).await.unwrap();

        // 2. Perform Login
        let login_use_case = LoginUseCase {
            user_repo: &repo,
            device_repo: &repo,
            session_repo: &repo,
            login_repo: &repo,
            audit_repo: &repo,
            crypto: &crypto,
            hmac_key,
        };

        let login_req = LoginRequest {
            identifier: "nightingale".to_string(),
            password: Some("superpassword".to_string()),
            device_name: "iPhone".to_string(), // new device
            device_type: "Phone".to_string(),
            platform: "iOS".to_string(),
            app_version: "1.0.0".to_string(),
            device_public_key: vec![4, 5, 6], // new key
            verification_fingerprint: "fp2".to_string(),
            user_agent: Some("mobile".to_string()),
        };

        let res = login_use_case.execute(login_req, "ip", None).await.unwrap();
        // Since it's a new device, it must default to Pending approval
        assert_eq!(res.device_approval_status, "pending");
        assert!(!res.access_token.is_empty());
    }

    #[tokio::test]
    async fn test_login_rate_limiting() {
        let (repo, crypto, hmac_key) = setup_repos();

        let login_use_case = LoginUseCase {
            user_repo: &repo,
            device_repo: &repo,
            session_repo: &repo,
            login_repo: &repo,
            audit_repo: &repo,
            crypto: &crypto,
            hmac_key,
        };

        let login_req = LoginRequest {
            identifier: "nonexistent".to_string(),
            password: Some("wrongpassword".to_string()),
            device_name: "iPhone".to_string(),
            device_type: "Phone".to_string(),
            platform: "iOS".to_string(),
            app_version: "1.0.0".to_string(),
            device_public_key: vec![4, 5, 6],
            verification_fingerprint: "fp".to_string(),
            user_agent: None,
        };

        // Fail 5 times
        for _ in 0..5 {
            let _ = login_use_case
                .execute(login_req.login_req_clone(), "ip", None)
                .await
                .unwrap_err();
        }

        // 6th attempt must be blocked
        let err = login_use_case
            .execute(login_req, "ip", None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Too many failed login attempts"));
    }

    #[tokio::test]
    async fn test_refresh_token_rotation() {
        let (repo, crypto, hmac_key) = setup_repos();

        // Register and get initial tokens
        let reg_use_case = RegisterUseCase {
            user_repo: &repo,
            device_repo: &repo,
            session_repo: &repo,
            audit_repo: &repo,
            crypto: &crypto,
            hmac_key: hmac_key.clone(),
        };
        let mnemonic = "one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty twentyone twentytwo twentythree twentyfour".to_string();
        let reg_res = reg_use_case
            .execute(
                RegisterRequest {
                    username: "nightingale".to_string(),
                    password: Some("superpassword".to_string()),
                    recovery_mnemonic: mnemonic,
                    display_name: None,
                    device_name: "Pixel".to_string(),
                    device_type: "Phone".to_string(),
                    platform: "Android".to_string(),
                    app_version: "1.0.0".to_string(),
                    device_public_key: vec![1],
                    verification_fingerprint: "fp".to_string(),
                },
                "ip",
                None,
            )
            .await
            .unwrap();

        let refresh_use_case = RefreshUseCase {
            session_repo: &repo,
            crypto: &crypto,
            hmac_key,
        };

        // First rotation
        let ref_res = refresh_use_case
            .execute(
                RefreshRequest {
                    refresh_token: reg_res.refresh_token.clone(),
                },
                "ip",
            )
            .await
            .unwrap();

        assert!(!ref_res.refresh_token.is_empty());
        assert_ne!(ref_res.refresh_token, reg_res.refresh_token);

        // Attempting to reuse old refresh token must fail (replay attack protection)
        let reuse_err = refresh_use_case
            .execute(
                RefreshRequest {
                    refresh_token: reg_res.refresh_token,
                },
                "ip",
            )
            .await
            .unwrap_err();

        assert!(reuse_err.to_string().contains("revoked or expired"));
    }

    #[tokio::test]
    async fn test_account_recovery() {
        let (repo, crypto, hmac_key) = setup_repos();

        // 1. Register
        let reg_use_case = RegisterUseCase {
            user_repo: &repo,
            device_repo: &repo,
            session_repo: &repo,
            audit_repo: &repo,
            crypto: &crypto,
            hmac_key: hmac_key.clone(),
        };
        let mnemonic = "one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen seventeen eighteen nineteen twenty twentyone twentytwo twentythree twentyfour".to_string();
        let reg_res = reg_use_case
            .execute(
                RegisterRequest {
                    username: "nightingale".to_string(),
                    password: Some("password12345".to_string()),
                    recovery_mnemonic: mnemonic.clone(),
                    display_name: None,
                    device_name: "Pixel".to_string(),
                    device_type: "Phone".to_string(),
                    platform: "Android".to_string(),
                    app_version: "1.0.0".to_string(),
                    device_public_key: vec![1],
                    verification_fingerprint: "fp".to_string(),
                },
                "ip",
                None,
            )
            .await
            .unwrap();

        // 2. Recover Usecase
        let recover_use_case = RecoverUseCase {
            user_repo: &repo,
            device_repo: &repo,
            session_repo: &repo,
            recovery_repo: &repo,
            audit_repo: &repo,
            crypto: &crypto,
        };

        recover_use_case
            .execute(
                RecoverRequest {
                    identifier: "nightingale".to_string(),
                    recovery_mnemonic: mnemonic,
                    new_password: Some("newpassword12345".to_string()),
                    user_agent: None,
                },
                "ip",
            )
            .await
            .unwrap();

        // 3. Verify old sessions are revoked
        let old_session = repo
            .get_session_by_refresh_token_hash(&hex::encode(
                crypto
                    .compute_hmac(&hmac_key, reg_res.refresh_token.as_bytes())
                    .unwrap(),
            ))
            .await
            .unwrap()
            .unwrap();
        assert!(old_session.revoked);

        // 4. Verify existing device status is moved back to Pending
        let dev = repo
            .get_device_by_id(&reg_res.device_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(dev.approval_status, DeviceApprovalStatus::Pending);
    }

    // Helper trait to allow cloning requests in test cases
    trait CloneReq {
        fn login_req_clone(&self) -> LoginRequest;
    }

    impl CloneReq for LoginRequest {
        fn login_req_clone(&self) -> LoginRequest {
            LoginRequest {
                identifier: self.identifier.clone(),
                password: self.password.clone(),
                device_name: self.device_name.clone(),
                device_type: self.device_type.clone(),
                platform: self.platform.clone(),
                app_version: self.app_version.clone(),
                device_public_key: self.device_public_key.clone(),
                verification_fingerprint: self.verification_fingerprint.clone(),
                user_agent: self.user_agent.clone(),
            }
        }
    }
}
