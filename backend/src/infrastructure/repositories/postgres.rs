// backend/src/infrastructure/repositories/postgres.rs

use async_trait::async_trait;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::domain::{
    device::{Device, DeviceApprovalStatus},
    messaging::{AttachmentBlob, PreKeyBundle},
    repositories::{
        AttachmentRepository, AuditLogRepository, DeviceRepository, DeviceSessionRepository,
        LoginAttemptRepository, PreKeyRepository, RecoveryAttemptRepository, ReplayCacheRepository,
        SessionRepository, UserRepository,
    },
    session::{AuditLog, LoginAttempt, RecoveryAttempt, Session},
    user::{User, UserSettings},
    Error,
};

pub struct PostgresRepository {
    pub pool: PgPool,
}

impl PostgresRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for PostgresRepository {
    async fn create_user(&self, user: &User, settings: &UserSettings) -> Result<(), Error> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Error::DatabaseError(e.to_string()))?;

        sqlx::query(
            "INSERT INTO users (id, username, account_id, password_hash, recovery_key_hash, display_name, avatar_blob_id, bio, created_at, updated_at, deleted_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)"
        )
        .bind(user.id)
        .bind(&user.username)
        .bind(&user.account_id)
        .bind(&user.password_hash)
        .bind(&user.recovery_key_hash)
        .bind(&user.display_name)
        .bind(user.avatar_blob_id)
        .bind(&user.bio)
        .bind(user.created_at)
        .bind(user.updated_at)
        .bind(user.deleted_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| Error::DatabaseError(e.to_string()))?;

        sqlx::query(
            "INSERT INTO user_settings (user_id, theme, language, notifications_enabled, read_receipts_enabled, typing_indicator_enabled, last_seen_enabled, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"
        )
        .bind(settings.user_id)
        .bind(&settings.theme)
        .bind(&settings.language)
        .bind(settings.notifications_enabled)
        .bind(settings.read_receipts_enabled)
        .bind(settings.typing_indicator_enabled)
        .bind(settings.last_seen_enabled)
        .bind(settings.created_at)
        .bind(settings.updated_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| Error::DatabaseError(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| Error::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn get_user_by_id(&self, id: &Uuid) -> Result<Option<User>, Error> {
        let row = sqlx::query("SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| Error::DatabaseError(e.to_string()))?;

        match row {
            Some(r) => Ok(Some(map_user_row(r)?)),
            None => Ok(None),
        }
    }

    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, Error> {
        let row = sqlx::query(
            "SELECT * FROM users WHERE LOWER(username) = LOWER($1) AND deleted_at IS NULL",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Error::DatabaseError(e.to_string()))?;

        match row {
            Some(r) => Ok(Some(map_user_row(r)?)),
            None => Ok(None),
        }
    }

    async fn get_user_by_account_id(&self, account_id: &str) -> Result<Option<User>, Error> {
        let row = sqlx::query("SELECT * FROM users WHERE account_id = $1 AND deleted_at IS NULL")
            .bind(account_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| Error::DatabaseError(e.to_string()))?;

        match row {
            Some(r) => Ok(Some(map_user_row(r)?)),
            None => Ok(None),
        }
    }

    async fn update_user_password(
        &self,
        user_id: &Uuid,
        password_hash: &str,
        recovery_key_hash: &str,
    ) -> Result<(), Error> {
        sqlx::query("UPDATE users SET password_hash = $2, recovery_key_hash = $3, updated_at = NOW() WHERE id = $1")
            .bind(user_id)
            .bind(password_hash)
            .bind(recovery_key_hash)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn is_username_reserved(&self, username: &str) -> Result<bool, Error> {
        let row = sqlx::query(
            "SELECT EXISTS(SELECT 1 FROM reserved_usernames WHERE LOWER(username) = LOWER($1))",
        )
        .bind(username)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| Error::DatabaseError(e.to_string()))?;

        let exists: bool = row.get(0);
        Ok(exists)
    }

    async fn get_user_settings(&self, user_id: &Uuid) -> Result<Option<UserSettings>, Error> {
        let row = sqlx::query("SELECT * FROM user_settings WHERE user_id = $1")
            .bind(user_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| Error::DatabaseError(e.to_string()))?;

        match row {
            Some(r) => Ok(Some(UserSettings {
                user_id: r.get("user_id"),
                theme: r.get("theme"),
                language: r.get("language"),
                notifications_enabled: r.get("notifications_enabled"),
                read_receipts_enabled: r.get("read_receipts_enabled"),
                typing_indicator_enabled: r.get("typing_indicator_enabled"),
                last_seen_enabled: r.get("last_seen_enabled"),
                created_at: r.get("created_at"),
                updated_at: r.get("updated_at"),
            })),
            None => Ok(None),
        }
    }

    async fn update_user_settings(&self, settings: &UserSettings) -> Result<(), Error> {
        sqlx::query(
            "UPDATE user_settings SET theme = $2, language = $3, notifications_enabled = $4, \
             read_receipts_enabled = $5, typing_indicator_enabled = $6, last_seen_enabled = $7, updated_at = NOW() \
             WHERE user_id = $1"
        )
        .bind(settings.user_id)
        .bind(&settings.theme)
        .bind(&settings.language)
        .bind(settings.notifications_enabled)
        .bind(settings.read_receipts_enabled)
        .bind(settings.typing_indicator_enabled)
        .bind(settings.last_seen_enabled)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }
}

#[async_trait]
impl DeviceRepository for PostgresRepository {
    async fn create_device(&self, device: &Device) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO devices (id, user_id, device_name, device_type, platform, app_version, device_public_key, approval_status, verification_fingerprint, created_at, last_active_at, deleted_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8::device_approval_status, $9, $10, $11, $12)"
        )
        .bind(device.id)
        .bind(device.user_id)
        .bind(&device.device_name)
        .bind(&device.device_type)
        .bind(&device.platform)
        .bind(&device.app_version)
        .bind(&device.device_public_key)
        .bind(&device.approval_status)
        .bind(&device.verification_fingerprint)
        .bind(device.created_at)
        .bind(device.last_active_at)
        .bind(device.deleted_at)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn get_device_by_id(&self, id: &Uuid) -> Result<Option<Device>, Error> {
        let row = sqlx::query("SELECT * FROM devices WHERE id = $1 AND deleted_at IS NULL")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| Error::DatabaseError(e.to_string()))?;

        match row {
            Some(r) => Ok(Some(map_device_row(r)?)),
            None => Ok(None),
        }
    }

    async fn get_devices_by_user_id(&self, user_id: &Uuid) -> Result<Vec<Device>, Error> {
        let rows = sqlx::query("SELECT * FROM devices WHERE user_id = $1 AND deleted_at IS NULL")
            .bind(user_id)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| Error::DatabaseError(e.to_string()))?;

        let mut devices = Vec::new();
        for r in rows {
            devices.push(map_device_row(r)?);
        }
        Ok(devices)
    }

    async fn update_device_status(
        &self,
        id: &Uuid,
        status: DeviceApprovalStatus,
    ) -> Result<(), Error> {
        sqlx::query("UPDATE devices SET approval_status = $2::device_approval_status, last_active_at = NOW() WHERE id = $1")
            .bind(id)
            .bind(status)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn count_active_devices_by_user_id(&self, user_id: &Uuid) -> Result<usize, Error> {
        let row =
            sqlx::query("SELECT COUNT(*) FROM devices WHERE user_id = $1 AND deleted_at IS NULL")
                .bind(user_id)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| Error::DatabaseError(e.to_string()))?;

        let count: i64 = row.get(0);
        Ok(count as usize)
    }

    async fn delete_device(&self, id: &Uuid) -> Result<(), Error> {
        sqlx::query("UPDATE devices SET deleted_at = NOW() WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }
}

#[async_trait]
impl SessionRepository for PostgresRepository {
    async fn create_session(&self, session: &Session) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO sessions (id, device_id, access_token_hash, refresh_token_hash, ip_hash, revoked, created_at, expires_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
        )
        .bind(session.id)
        .bind(session.device_id)
        .bind(&session.access_token_hash)
        .bind(&session.refresh_token_hash)
        .bind(&session.ip_hash)
        .bind(session.revoked)
        .bind(session.created_at)
        .bind(session.expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn get_session_by_id(&self, id: &Uuid) -> Result<Option<Session>, Error> {
        let row = sqlx::query("SELECT * FROM sessions WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| Error::DatabaseError(e.to_string()))?;

        match row {
            Some(r) => Ok(Some(map_session_row(r)?)),
            None => Ok(None),
        }
    }

    async fn get_session_by_access_token_hash(&self, hash: &str) -> Result<Option<Session>, Error> {
        let row = sqlx::query("SELECT * FROM sessions WHERE access_token_hash = $1")
            .bind(hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| Error::DatabaseError(e.to_string()))?;

        match row {
            Some(r) => Ok(Some(map_session_row(r)?)),
            None => Ok(None),
        }
    }

    async fn get_session_by_refresh_token_hash(
        &self,
        hash: &str,
    ) -> Result<Option<Session>, Error> {
        let row = sqlx::query("SELECT * FROM sessions WHERE refresh_token_hash = $1")
            .bind(hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| Error::DatabaseError(e.to_string()))?;

        match row {
            Some(r) => Ok(Some(map_session_row(r)?)),
            None => Ok(None),
        }
    }

    async fn revoke_session(&self, id: &Uuid) -> Result<(), Error> {
        sqlx::query("UPDATE sessions SET revoked = TRUE WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn revoke_all_user_sessions_except(
        &self,
        user_id: &Uuid,
        except_session_id: Option<Uuid>,
    ) -> Result<(), Error> {
        sqlx::query(
            "UPDATE sessions SET revoked = TRUE WHERE device_id IN (SELECT id FROM devices WHERE user_id = $1) \
             AND ($2::uuid IS NULL OR id <> $2)"
        )
        .bind(user_id)
        .bind(except_session_id)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }
}

#[async_trait]
impl LoginAttemptRepository for PostgresRepository {
    async fn log_attempt(&self, attempt: &LoginAttempt) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO login_attempts (id, ip_hash, username, user_agent, device_fingerprint, attempt_time, successful) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)"
        )
        .bind(attempt.id)
        .bind(&attempt.ip_hash)
        .bind(&attempt.username)
        .bind(&attempt.user_agent)
        .bind(&attempt.device_fingerprint)
        .bind(attempt.attempt_time)
        .bind(attempt.successful)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn count_failed_attempts_in_window(
        &self,
        username: &str,
        ip_hash: &str,
        minutes: i64,
    ) -> Result<usize, Error> {
        let row = sqlx::query(
            "SELECT COUNT(*) FROM login_attempts WHERE (LOWER(username) = LOWER($1) OR ip_hash = $2) \
             AND successful = FALSE AND attempt_time >= NOW() - ($3 || ' minutes')::interval"
        )
        .bind(username)
        .bind(ip_hash)
        .bind(format!("{}", minutes))
        .fetch_one(&self.pool)
        .await
        .map_err(|e| Error::DatabaseError(e.to_string()))?;

        let count: i64 = row.get(0);
        Ok(count as usize)
    }
}

#[async_trait]
impl RecoveryAttemptRepository for PostgresRepository {
    async fn log_attempt(&self, attempt: &RecoveryAttempt) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO recovery_attempts (id, username, ip_hash, attempt_time, successful) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(attempt.id)
        .bind(&attempt.username)
        .bind(&attempt.ip_hash)
        .bind(attempt.attempt_time)
        .bind(attempt.successful)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn count_failed_attempts_in_window(
        &self,
        username: &str,
        ip_hash: &str,
        minutes: i64,
    ) -> Result<usize, Error> {
        let row = sqlx::query(
            "SELECT COUNT(*) FROM recovery_attempts WHERE (LOWER(username) = LOWER($1) OR ip_hash = $2) \
             AND successful = FALSE AND attempt_time >= NOW() - ($3 || ' minutes')::interval"
        )
        .bind(username)
        .bind(ip_hash)
        .bind(format!("{}", minutes))
        .fetch_one(&self.pool)
        .await
        .map_err(|e| Error::DatabaseError(e.to_string()))?;

        let count: i64 = row.get(0);
        Ok(count as usize)
    }
}

#[async_trait]
impl AuditLogRepository for PostgresRepository {
    async fn log_event(&self, log: &AuditLog) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO audit_log (id, user_id, device_id, event_type, ip_hash, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(log.id)
        .bind(log.user_id)
        .bind(log.device_id)
        .bind(&log.event_type)
        .bind(&log.ip_hash)
        .bind(log.created_at)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }
}

#[async_trait]
impl PreKeyRepository for PostgresRepository {
    async fn save_identity_key(
        &self,
        device_id: &Uuid,
        identity_signing_key: &[u8],
        identity_dh_key: &[u8],
        identity_dh_signature: &[u8],
        signed_prekey: &[u8],
        prekey_signature: &[u8],
    ) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO identity_keys (device_id, identity_signing_key, identity_dh_key, identity_dh_signature, signed_prekey, prekey_signature) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (device_id) DO UPDATE \
             SET identity_signing_key = EXCLUDED.identity_signing_key, \
                 identity_dh_key = EXCLUDED.identity_dh_key, \
                 identity_dh_signature = EXCLUDED.identity_dh_signature, \
                 signed_prekey = EXCLUDED.signed_prekey, \
                 prekey_signature = EXCLUDED.prekey_signature"
        )
        .bind(device_id)
        .bind(identity_signing_key)
        .bind(identity_dh_key)
        .bind(identity_dh_signature)
        .bind(signed_prekey)
        .bind(prekey_signature)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn save_one_time_keys(&self, device_id: &Uuid, keys: &[Vec<u8>]) -> Result<(), Error> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Error::DatabaseError(e.to_string()))?;

        for key in keys {
            sqlx::query(
                "INSERT INTO one_time_keys (device_id, key_value, used) \
                 VALUES ($1, $2, FALSE)",
            )
            .bind(device_id)
            .bind(key)
            .execute(&mut *tx)
            .await
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        }

        tx.commit()
            .await
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn get_prekey_bundle(&self, device_id: &Uuid) -> Result<Option<PreKeyBundle>, Error> {
        let row = sqlx::query(
            "SELECT ik.device_id, ik.identity_signing_key, ik.identity_dh_key, ik.identity_dh_signature, ik.signed_prekey, ik.prekey_signature, \
             (SELECT key_value FROM one_time_keys WHERE device_id = ik.device_id AND used = FALSE ORDER BY id ASC LIMIT 1) AS otk \
             FROM identity_keys ik \
             WHERE ik.device_id = $1"
        )
        .bind(device_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Error::DatabaseError(e.to_string()))?;

        match row {
            Some(r) => {
                let dev_id: Uuid = r.get("device_id");
                let isk: Vec<u8> = r.get("identity_signing_key");
                let idk: Vec<u8> = r.get("identity_dh_key");
                let idsig: Vec<u8> = r.get("identity_dh_signature");
                let spk: Vec<u8> = r.get("signed_prekey");
                let sig: Vec<u8> = r.get("prekey_signature");
                let otk: Option<Vec<u8>> = r.get("otk");

                Ok(Some(PreKeyBundle {
                    device_id: dev_id,
                    identity_signing_key: isk,
                    identity_dh_key: idk,
                    identity_dh_signature: idsig,
                    signed_prekey: spk,
                    prekey_signature: sig,
                    one_time_key: otk,
                    bundle_version: 1,
                }))
            }
            None => Ok(None),
        }
    }

    async fn consume_one_time_key(&self, device_id: &Uuid) -> Result<Option<Vec<u8>>, Error> {
        // Run update in transaction to safely fetch and mark as used atomically
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| Error::DatabaseError(e.to_string()))?;

        let row = sqlx::query(
            "SELECT id, key_value FROM one_time_keys \
             WHERE device_id = $1 AND used = FALSE \
             ORDER BY id ASC LIMIT 1 FOR UPDATE",
        )
        .bind(device_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| Error::DatabaseError(e.to_string()))?;

        match row {
            Some(r) => {
                let id: i32 = r.get("id");
                let val: Vec<u8> = r.get("key_value");

                sqlx::query("UPDATE one_time_keys SET used = TRUE WHERE id = $1")
                    .bind(id)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| Error::DatabaseError(e.to_string()))?;

                tx.commit()
                    .await
                    .map_err(|e| Error::DatabaseError(e.to_string()))?;
                Ok(Some(val))
            }
            None => {
                tx.rollback()
                    .await
                    .map_err(|e| Error::DatabaseError(e.to_string()))?;
                Ok(None)
            }
        }
    }

    async fn get_one_time_keys_count(&self, device_id: &Uuid) -> Result<usize, Error> {
        let row =
            sqlx::query("SELECT COUNT(*) FROM one_time_keys WHERE device_id = $1 AND used = FALSE")
                .bind(device_id)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| Error::DatabaseError(e.to_string()))?;
        let count: i64 = row.get(0);
        Ok(count as usize)
    }
}

#[async_trait]
impl DeviceSessionRepository for PostgresRepository {
    async fn save_session(
        &self,
        session_id: &Uuid,
        sender_device_id: &Uuid,
        recipient_device_id: &Uuid,
        version: &str,
        encrypted_state: &[u8],
        last_msg_num: i32,
    ) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO device_sessions (id, sender_device_id, recipient_device_id, session_version, encrypted_ratchet_state, last_message_number, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, NOW()) \
             ON CONFLICT (sender_device_id, recipient_device_id) DO UPDATE \
             SET encrypted_ratchet_state = EXCLUDED.encrypted_ratchet_state, last_message_number = EXCLUDED.last_message_number, updated_at = NOW()"
        )
        .bind(session_id)
        .bind(sender_device_id)
        .bind(recipient_device_id)
        .bind(version)
        .bind(encrypted_state)
        .bind(last_msg_num)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn get_session(
        &self,
        sender_device_id: &Uuid,
        recipient_device_id: &Uuid,
    ) -> Result<Option<(Uuid, String, Vec<u8>, i32)>, Error> {
        let row = sqlx::query(
            "SELECT id, session_version, encrypted_ratchet_state, last_message_number \
             FROM device_sessions \
             WHERE sender_device_id = $1 AND recipient_device_id = $2",
        )
        .bind(sender_device_id)
        .bind(recipient_device_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| Error::DatabaseError(e.to_string()))?;

        match row {
            Some(r) => {
                let id: Uuid = r.get("id");
                let version: String = r.get("session_version");
                let state: Vec<u8> = r.get("encrypted_ratchet_state");
                let last_msg: i32 = r.get("last_message_number");
                Ok(Some((id, version, state, last_msg)))
            }
            None => Ok(None),
        }
    }

    async fn revoke_session(&self, session_id: &Uuid) -> Result<(), Error> {
        sqlx::query("DELETE FROM device_sessions WHERE id = $1")
            .bind(session_id)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }
}

#[async_trait]
impl ReplayCacheRepository for PostgresRepository {
    async fn add_to_cache(&self, message_id: &Uuid) -> Result<bool, Error> {
        let result = sqlx::query(
            "INSERT INTO replay_cache (message_id) VALUES ($1) ON CONFLICT (message_id) DO NOTHING",
        )
        .bind(message_id)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::DatabaseError(e.to_string()))?;

        Ok(result.rows_affected() > 0)
    }
}

// --- Mapper helpers ---

fn map_user_row(r: sqlx::postgres::PgRow) -> Result<User, Error> {
    Ok(User {
        id: r.get("id"),
        username: r.get("username"),
        account_id: r.get("account_id"),
        password_hash: r.get("password_hash"),
        recovery_key_hash: r.get("recovery_key_hash"),
        display_name: r.get("display_name"),
        avatar_blob_id: r.get("avatar_blob_id"),
        bio: r.get("bio"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
        deleted_at: r.get("deleted_at"),
    })
}

fn map_device_row(r: sqlx::postgres::PgRow) -> Result<Device, Error> {
    let approval_status: DeviceApprovalStatus = r.get("approval_status");

    Ok(Device {
        id: r.get("id"),
        user_id: r.get("user_id"),
        device_name: r.get("device_name"),
        device_type: r.get("device_type"),
        platform: r.get("platform"),
        app_version: r.get("app_version"),
        device_public_key: r.get("device_public_key"),
        approval_status,
        verification_fingerprint: r.get("verification_fingerprint"),
        created_at: r.get("created_at"),
        last_active_at: r.get("last_active_at"),
        deleted_at: r.get("deleted_at"),
    })
}

fn map_session_row(r: sqlx::postgres::PgRow) -> Result<Session, Error> {
    Ok(Session {
        id: r.get("id"),
        device_id: r.get("device_id"),
        access_token_hash: r.get("access_token_hash"),
        refresh_token_hash: r.get("refresh_token_hash"),
        ip_hash: r.get("ip_hash"),
        revoked: r.get("revoked"),
        created_at: r.get("created_at"),
        expires_at: r.get("expires_at"),
    })
}

fn map_blob_row(r: sqlx::postgres::PgRow) -> Result<AttachmentBlob, Error> {
    Ok(AttachmentBlob {
        id: r.get("id"),
        uploader_device_id: r.get("uploader_device_id"),
        conversation_id: r.get("conversation_id"),
        message_id: r.get("message_id"),
        file_size: r.get("file_size"),
        file_hash: r.get("file_hash"),
        mime_type: r.get("mime_type"),
        blob_version: r.get("blob_version"),
        blob_encryption_version: r.get("blob_encryption_version"),
        compression_flag: r.get("compression_flag"),
        chunk_count: r.get("chunk_count"),
        uploaded_chunks: r.get("uploaded_chunks"),
        is_completed: r.get("is_completed"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
        deleted_at: r.get("deleted_at"),
    })
}

#[async_trait]
impl AttachmentRepository for PostgresRepository {
    async fn create_blob(&self, blob: &AttachmentBlob) -> Result<(), Error> {
        sqlx::query(
            "INSERT INTO attachment_blobs (id, uploader_device_id, conversation_id, message_id, file_size, file_hash, mime_type, blob_version, blob_encryption_version, compression_flag, chunk_count, uploaded_chunks, is_completed, created_at, updated_at, deleted_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)"
        )
        .bind(blob.id)
        .bind(blob.uploader_device_id)
        .bind(blob.conversation_id)
        .bind(blob.message_id)
        .bind(blob.file_size)
        .bind(&blob.file_hash)
        .bind(&blob.mime_type)
        .bind(blob.blob_version)
        .bind(blob.blob_encryption_version)
        .bind(blob.compression_flag)
        .bind(blob.chunk_count)
        .bind(&blob.uploaded_chunks)
        .bind(blob.is_completed)
        .bind(blob.created_at)
        .bind(blob.updated_at)
        .bind(blob.deleted_at)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn get_blob_by_id(&self, id: &Uuid) -> Result<Option<AttachmentBlob>, Error> {
        let row = sqlx::query("SELECT * FROM attachment_blobs WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        match row {
            Some(r) => map_blob_row(r).map(Some),
            None => Ok(None),
        }
    }

    async fn update_blob_progress(
        &self,
        id: &Uuid,
        uploaded_chunks: &[i32],
        is_completed: bool,
    ) -> Result<(), Error> {
        sqlx::query(
            "UPDATE attachment_blobs SET uploaded_chunks = $1, is_completed = $2, updated_at = NOW() WHERE id = $3"
        )
        .bind(uploaded_chunks)
        .bind(is_completed)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn bind_blob_to_message(&self, id: &Uuid, message_id: &Uuid) -> Result<(), Error> {
        sqlx::query(
            "UPDATE attachment_blobs SET message_id = $1, updated_at = NOW() WHERE id = $2",
        )
        .bind(message_id)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn get_unreferenced_blobs(&self, hours_old: i32) -> Result<Vec<AttachmentBlob>, Error> {
        let rows = sqlx::query(
            "SELECT * FROM attachment_blobs WHERE message_id IS NULL AND created_at < NOW() - $1 * INTERVAL '1 hour' AND deleted_at IS NULL"
        )
        .bind(hours_old as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Error::DatabaseError(e.to_string()))?;
        rows.into_iter().map(map_blob_row).collect()
    }

    async fn soft_delete_blob(&self, id: &Uuid) -> Result<(), Error> {
        sqlx::query(
            "UPDATE attachment_blobs SET deleted_at = NOW(), updated_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }

    async fn get_expired_blobs(&self, days_old: i32) -> Result<Vec<AttachmentBlob>, Error> {
        let rows = sqlx::query(
            "SELECT * FROM attachment_blobs WHERE deleted_at IS NOT NULL AND deleted_at < NOW() - $1 * INTERVAL '1 day'"
        )
        .bind(days_old as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| Error::DatabaseError(e.to_string()))?;
        rows.into_iter().map(map_blob_row).collect()
    }

    async fn delete_blob_permanently(&self, id: &Uuid) -> Result<(), Error> {
        sqlx::query("DELETE FROM attachment_blobs WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::DatabaseError(e.to_string()))?;
        Ok(())
    }
}
