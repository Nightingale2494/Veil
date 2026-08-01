// backend/src/infrastructure/repositories/in_memory.rs

use async_trait::async_trait;
use chrono::Utc;
use std::collections::{HashMap, HashSet};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::domain::{
    device::{Device, DeviceApprovalStatus},
    group::{Group, GroupMember, GroupRole},
    messaging::{AttachmentBlob, PreKeyBundle},
    repositories::{
        AttachmentRepository, AuditLogRepository, DeviceRepository, DeviceSessionRepository,
        GroupRepository, LoginAttemptRepository, PreKeyRepository, PushTokenRepository,
        RecoveryAttemptRepository, ReplayCacheRepository, SessionRepository, UserRepository,
    },
    session::{AuditLog, LoginAttempt, RecoveryAttempt, Session},
    user::{User, UserSettings},
    Error,
};

pub struct InMemoryRepository {
    pub users: Mutex<HashMap<Uuid, User>>,
    pub settings: Mutex<HashMap<Uuid, UserSettings>>,
    pub devices: Mutex<HashMap<Uuid, Device>>,
    pub sessions: Mutex<HashMap<Uuid, Session>>,
    pub logins: Mutex<Vec<LoginAttempt>>,
    pub recoveries: Mutex<Vec<RecoveryAttempt>>,
    pub audits: Mutex<Vec<AuditLog>>,
    pub reserved_names: HashSet<String>,

    // Phase 3 additions
    pub identity_keys: Mutex<HashMap<Uuid, (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)>>, // device_id -> (signing_key, dh_key, dh_sig, spk, spk_sig)
    pub one_time_keys: Mutex<HashMap<Uuid, Vec<Vec<u8>>>>, // device_id -> array of keys
    pub device_sessions: Mutex<HashMap<(Uuid, Uuid), (Uuid, String, Vec<u8>, i32)>>, // (sender_device, recipient_device) -> (session_id, version, encrypted_state, last_message_number)
    pub replay_cache: Mutex<HashSet<Uuid>>,                                          // message_id

    // Phase 4 additions
    pub attachments: Mutex<HashMap<Uuid, AttachmentBlob>>,

    // Group & Notification additions
    pub groups: Mutex<HashMap<Uuid, Group>>,
    pub group_members: Mutex<HashMap<Uuid, Vec<GroupMember>>>,
    pub push_tokens: Mutex<HashMap<Uuid, String>>,
}

impl InMemoryRepository {
    pub fn new() -> Self {
        let mut reserved = HashSet::new();
        reserved.insert("admin".to_string());
        reserved.insert("administrator".to_string());
        reserved.insert("support".to_string());
        reserved.insert("system".to_string());
        reserved.insert("veil".to_string());
        reserved.insert("root".to_string());
        reserved.insert("owner".to_string());
        reserved.insert("moderator".to_string());

        Self {
            users: Mutex::new(HashMap::new()),
            settings: Mutex::new(HashMap::new()),
            devices: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
            logins: Mutex::new(Vec::new()),
            recoveries: Mutex::new(Vec::new()),
            audits: Mutex::new(Vec::new()),
            reserved_names: reserved,
            identity_keys: Mutex::new(HashMap::new()),
            one_time_keys: Mutex::new(HashMap::new()),
            device_sessions: Mutex::new(HashMap::new()),
            replay_cache: Mutex::new(HashSet::new()),
            attachments: Mutex::new(HashMap::new()),
            groups: Mutex::new(HashMap::new()),
            group_members: Mutex::new(HashMap::new()),
            push_tokens: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl UserRepository for InMemoryRepository {
    async fn create_user(&self, user: &User, settings: &UserSettings) -> Result<(), Error> {
        let mut users = self.users.lock().await;
        let mut user_settings = self.settings.lock().await;
        users.insert(user.id, user.clone());
        user_settings.insert(settings.user_id, settings.clone());
        Ok(())
    }

    async fn get_user_by_id(&self, id: &Uuid) -> Result<Option<User>, Error> {
        let users = self.users.lock().await;
        Ok(users.get(id).cloned().filter(|u| u.deleted_at.is_none()))
    }

    async fn get_user_by_username(&self, username: &str) -> Result<Option<User>, Error> {
        let users = self.users.lock().await;
        let normalized = username.to_lowercase();
        Ok(users
            .values()
            .find(|u| u.username.to_lowercase() == normalized && u.deleted_at.is_none())
            .cloned())
    }

    async fn get_user_by_account_id(&self, account_id: &str) -> Result<Option<User>, Error> {
        let users = self.users.lock().await;
        Ok(users
            .values()
            .find(|u| u.account_id == account_id && u.deleted_at.is_none())
            .cloned())
    }

    async fn update_user_password(
        &self,
        user_id: &Uuid,
        password_hash: &str,
        recovery_key_hash: &str,
    ) -> Result<(), Error> {
        let mut users = self.users.lock().await;
        if let Some(user) = users.get_mut(user_id) {
            user.password_hash = password_hash.to_string();
            user.recovery_key_hash = recovery_key_hash.to_string();
            user.updated_at = Utc::now();
            Ok(())
        } else {
            Err(Error::NotFound("User not found".into()))
        }
    }

    async fn is_username_reserved(&self, username: &str) -> Result<bool, Error> {
        Ok(self.reserved_names.contains(&username.to_lowercase()))
    }

    async fn get_user_settings(&self, user_id: &Uuid) -> Result<Option<UserSettings>, Error> {
        let settings = self.settings.lock().await;
        Ok(settings.get(user_id).cloned())
    }

    async fn update_user_settings(&self, settings: &UserSettings) -> Result<(), Error> {
        let mut user_settings = self.settings.lock().await;
        user_settings.insert(settings.user_id, settings.clone());
        Ok(())
    }
}

#[async_trait]
impl DeviceRepository for InMemoryRepository {
    async fn create_device(&self, device: &Device) -> Result<(), Error> {
        let mut devices = self.devices.lock().await;
        devices.insert(device.id, device.clone());
        Ok(())
    }

    async fn get_device_by_id(&self, id: &Uuid) -> Result<Option<Device>, Error> {
        let devices = self.devices.lock().await;
        Ok(devices.get(id).cloned().filter(|d| d.deleted_at.is_none()))
    }

    async fn get_devices_by_user_id(&self, user_id: &Uuid) -> Result<Vec<Device>, Error> {
        let devices = self.devices.lock().await;
        Ok(devices
            .values()
            .filter(|d| d.user_id == *user_id && d.deleted_at.is_none())
            .cloned()
            .collect())
    }

    async fn update_device_status(
        &self,
        id: &Uuid,
        status: DeviceApprovalStatus,
    ) -> Result<(), Error> {
        let mut devices = self.devices.lock().await;
        if let Some(device) = devices.get_mut(id) {
            device.approval_status = status;
            device.last_active_at = Utc::now();
            Ok(())
        } else {
            Err(Error::NotFound("Device not found".into()))
        }
    }

    async fn count_active_devices_by_user_id(&self, user_id: &Uuid) -> Result<usize, Error> {
        let devices = self.devices.lock().await;
        Ok(devices
            .values()
            .filter(|d| d.user_id == *user_id && d.deleted_at.is_none())
            .count())
    }

    async fn delete_device(&self, id: &Uuid) -> Result<(), Error> {
        let mut devices = self.devices.lock().await;
        if let Some(device) = devices.get_mut(id) {
            device.deleted_at = Some(Utc::now());
            Ok(())
        } else {
            Err(Error::NotFound("Device not found".into()))
        }
    }
}

#[async_trait]
impl SessionRepository for InMemoryRepository {
    async fn create_session(&self, session: &Session) -> Result<(), Error> {
        let mut sessions = self.sessions.lock().await;
        sessions.insert(session.id, session.clone());
        Ok(())
    }

    async fn get_session_by_id(&self, id: &Uuid) -> Result<Option<Session>, Error> {
        let sessions = self.sessions.lock().await;
        Ok(sessions.get(id).cloned())
    }

    async fn get_session_by_access_token_hash(&self, hash: &str) -> Result<Option<Session>, Error> {
        let sessions = self.sessions.lock().await;
        Ok(sessions
            .values()
            .find(|s| s.access_token_hash == hash)
            .cloned())
    }

    async fn get_session_by_refresh_token_hash(
        &self,
        hash: &str,
    ) -> Result<Option<Session>, Error> {
        let sessions = self.sessions.lock().await;
        Ok(sessions
            .values()
            .find(|s| s.refresh_token_hash == hash)
            .cloned())
    }

    async fn revoke_session(&self, id: &Uuid) -> Result<(), Error> {
        let mut sessions = self.sessions.lock().await;
        if let Some(session) = sessions.get_mut(id) {
            session.revoked = true;
            Ok(())
        } else {
            Err(Error::NotFound("Session not found".into()))
        }
    }

    async fn revoke_all_user_sessions_except(
        &self,
        user_id: &Uuid,
        except_session_id: Option<Uuid>,
    ) -> Result<(), Error> {
        let mut sessions = self.sessions.lock().await;
        let devices = self.devices.lock().await;

        let user_device_ids: HashSet<Uuid> = devices
            .values()
            .filter(|d| d.user_id == *user_id)
            .map(|d| d.id)
            .collect();

        for session in sessions.values_mut() {
            if user_device_ids.contains(&session.device_id) {
                if let Some(except_id) = except_session_id {
                    if session.id == except_id {
                        continue;
                    }
                }
                session.revoked = true;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl LoginAttemptRepository for InMemoryRepository {
    async fn log_attempt(&self, attempt: &LoginAttempt) -> Result<(), Error> {
        let mut logins = self.logins.lock().await;
        logins.push(attempt.clone());
        Ok(())
    }

    async fn count_failed_attempts_in_window(
        &self,
        username: &str,
        ip_hash: &str,
        minutes: i64,
    ) -> Result<usize, Error> {
        let logins = self.logins.lock().await;
        let cutoff = Utc::now() - chrono::Duration::minutes(minutes);
        let count = logins
            .iter()
            .filter(|l| {
                !l.successful
                    && l.attempt_time >= cutoff
                    && (l.username.to_lowercase() == username.to_lowercase()
                        || l.ip_hash == ip_hash)
            })
            .count();
        Ok(count)
    }
}

#[async_trait]
impl RecoveryAttemptRepository for InMemoryRepository {
    async fn log_attempt(&self, attempt: &RecoveryAttempt) -> Result<(), Error> {
        let mut recoveries = self.recoveries.lock().await;
        recoveries.push(attempt.clone());
        Ok(())
    }

    async fn count_failed_attempts_in_window(
        &self,
        username: &str,
        ip_hash: &str,
        minutes: i64,
    ) -> Result<usize, Error> {
        let recoveries = self.recoveries.lock().await;
        let cutoff = Utc::now() - chrono::Duration::minutes(minutes);
        let count = recoveries
            .iter()
            .filter(|r| {
                !r.successful
                    && r.attempt_time >= cutoff
                    && (r.username.to_lowercase() == username.to_lowercase()
                        || r.ip_hash == ip_hash)
            })
            .count();
        Ok(count)
    }
}

#[async_trait]
impl AuditLogRepository for InMemoryRepository {
    async fn log_event(&self, log: &AuditLog) -> Result<(), Error> {
        let mut audits = self.audits.lock().await;
        audits.push(log.clone());
        Ok(())
    }
}

#[async_trait]
impl PreKeyRepository for InMemoryRepository {
    async fn save_identity_key(
        &self,
        device_id: &Uuid,
        identity_signing_key: &[u8],
        identity_dh_key: &[u8],
        identity_dh_signature: &[u8],
        signed_prekey: &[u8],
        prekey_signature: &[u8],
    ) -> Result<(), Error> {
        let mut iks = self.identity_keys.lock().await;
        iks.insert(
            *device_id,
            (
                identity_signing_key.to_vec(),
                identity_dh_key.to_vec(),
                identity_dh_signature.to_vec(),
                signed_prekey.to_vec(),
                prekey_signature.to_vec(),
            ),
        );
        Ok(())
    }

    async fn save_one_time_keys(&self, device_id: &Uuid, keys: &[Vec<u8>]) -> Result<(), Error> {
        let mut otks = self.one_time_keys.lock().await;
        let entry = otks.entry(*device_id).or_insert_with(Vec::new);
        entry.extend(keys.iter().cloned());
        Ok(())
    }

    async fn get_prekey_bundle(&self, device_id: &Uuid) -> Result<Option<PreKeyBundle>, Error> {
        let iks = self.identity_keys.lock().await;
        let mut otks = self.one_time_keys.lock().await;
        if let Some((signing_key, dh_key, dh_sig, spk, spk_sig)) = iks.get(device_id) {
            let otk = otks.get_mut(device_id).and_then(|v| {
                if v.is_empty() {
                    None
                } else {
                    Some(v[0].clone())
                }
            });
            Ok(Some(PreKeyBundle {
                device_id: *device_id,
                identity_signing_key: signing_key.clone(),
                identity_dh_key: dh_key.clone(),
                identity_dh_signature: dh_sig.clone(),
                signed_prekey: spk.clone(),
                prekey_signature: spk_sig.clone(),
                one_time_key: otk,
                bundle_version: 1,
            }))
        } else {
            Ok(None)
        }
    }

    async fn consume_one_time_key(&self, device_id: &Uuid) -> Result<Option<Vec<u8>>, Error> {
        let mut otks = self.one_time_keys.lock().await;
        if let Some(keys) = otks.get_mut(device_id) {
            if !keys.is_empty() {
                Ok(Some(keys.remove(0)))
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    async fn get_one_time_keys_count(&self, device_id: &Uuid) -> Result<usize, Error> {
        let otks = self.one_time_keys.lock().await;
        Ok(otks.get(device_id).map(|v| v.len()).unwrap_or(0))
    }
}

#[async_trait]
impl DeviceSessionRepository for InMemoryRepository {
    async fn save_session(
        &self,
        session_id: &Uuid,
        sender_device_id: &Uuid,
        recipient_device_id: &Uuid,
        version: &str,
        encrypted_state: &[u8],
        last_msg_num: i32,
    ) -> Result<(), Error> {
        let mut ds = self.device_sessions.lock().await;
        ds.insert(
            (*sender_device_id, *recipient_device_id),
            (
                *session_id,
                version.to_string(),
                encrypted_state.to_vec(),
                last_msg_num,
            ),
        );
        Ok(())
    }

    async fn get_session(
        &self,
        sender_device_id: &Uuid,
        recipient_device_id: &Uuid,
    ) -> Result<Option<(Uuid, String, Vec<u8>, i32)>, Error> {
        let ds = self.device_sessions.lock().await;
        if let Some((sid, ver, state, last_msg)) =
            ds.get(&(*sender_device_id, *recipient_device_id))
        {
            Ok(Some((*sid, ver.clone(), state.clone(), *last_msg)))
        } else {
            Ok(None)
        }
    }

    async fn revoke_session(&self, session_id: &Uuid) -> Result<(), Error> {
        let mut ds = self.device_sessions.lock().await;
        ds.retain(|_, (sid, _, _, _)| sid != session_id);
        Ok(())
    }
}

#[async_trait]
impl ReplayCacheRepository for InMemoryRepository {
    async fn add_to_cache(&self, message_id: &Uuid) -> Result<bool, Error> {
        let mut cache = self.replay_cache.lock().await;
        let inserted = cache.insert(*message_id);
        Ok(inserted)
    }
}

#[async_trait]
impl AttachmentRepository for InMemoryRepository {
    async fn create_blob(&self, blob: &AttachmentBlob) -> Result<(), Error> {
        let mut atts = self.attachments.lock().await;
        atts.insert(blob.id, blob.clone());
        Ok(())
    }

    async fn get_blob_by_id(&self, id: &Uuid) -> Result<Option<AttachmentBlob>, Error> {
        let atts = self.attachments.lock().await;
        Ok(atts.get(id).cloned())
    }

    async fn update_blob_progress(
        &self,
        id: &Uuid,
        uploaded_chunks: &[i32],
        is_completed: bool,
    ) -> Result<(), Error> {
        let mut atts = self.attachments.lock().await;
        if let Some(blob) = atts.get_mut(id) {
            blob.uploaded_chunks = uploaded_chunks.to_vec();
            blob.is_completed = is_completed;
            blob.updated_at = Utc::now();
            Ok(())
        } else {
            Err(Error::NotFound("Attachment blob not found".to_string()))
        }
    }

    async fn bind_blob_to_message(&self, id: &Uuid, message_id: &Uuid) -> Result<(), Error> {
        let mut atts = self.attachments.lock().await;
        if let Some(blob) = atts.get_mut(id) {
            blob.message_id = Some(*message_id);
            blob.updated_at = Utc::now();
            Ok(())
        } else {
            Err(Error::NotFound("Attachment blob not found".to_string()))
        }
    }

    async fn get_unreferenced_blobs(&self, hours_old: i32) -> Result<Vec<AttachmentBlob>, Error> {
        let atts = self.attachments.lock().await;
        let cutoff = Utc::now() - chrono::Duration::hours(hours_old as i64);
        let list = atts
            .values()
            .filter(|b| b.message_id.is_none() && b.created_at < cutoff && b.deleted_at.is_none())
            .cloned()
            .collect();
        Ok(list)
    }

    async fn soft_delete_blob(&self, id: &Uuid) -> Result<(), Error> {
        let mut atts = self.attachments.lock().await;
        if let Some(blob) = atts.get_mut(id) {
            blob.deleted_at = Some(Utc::now());
            blob.updated_at = Utc::now();
            Ok(())
        } else {
            Err(Error::NotFound("Attachment blob not found".to_string()))
        }
    }

    async fn get_expired_blobs(&self, days_old: i32) -> Result<Vec<AttachmentBlob>, Error> {
        let atts = self.attachments.lock().await;
        let cutoff = Utc::now() - chrono::Duration::days(days_old as i64);
        let list = atts
            .values()
            .filter(|b| b.deleted_at.map(|d| d < cutoff).unwrap_or(false))
            .cloned()
            .collect();
        Ok(list)
    }

    async fn delete_blob_permanently(&self, id: &Uuid) -> Result<(), Error> {
        let mut atts = self.attachments.lock().await;
        atts.remove(id);
        Ok(())
    }
}

#[async_trait]
impl GroupRepository for InMemoryRepository {
    async fn create_group(&self, group: &Group, owner_id: &Uuid) -> Result<(), Error> {
        let mut groups = self.groups.lock().await;
        groups.insert(group.id, group.clone());

        let mut members = self.group_members.lock().await;
        let owner_member = GroupMember {
            group_id: group.id,
            user_id: *owner_id,
            role: GroupRole::Owner,
            joined_at: Utc::now(),
        };
        members.insert(group.id, vec![owner_member]);
        Ok(())
    }

    async fn get_group_by_id(&self, id: &Uuid) -> Result<Option<Group>, Error> {
        let groups = self.groups.lock().await;
        Ok(groups.get(id).cloned())
    }

    async fn get_group_members(&self, group_id: &Uuid) -> Result<Vec<GroupMember>, Error> {
        let members = self.group_members.lock().await;
        Ok(members.get(group_id).cloned().unwrap_or_default())
    }

    async fn get_member_role(&self, group_id: &Uuid, user_id: &Uuid) -> Result<Option<GroupRole>, Error> {
        let members = self.group_members.lock().await;
        if let Some(list) = members.get(group_id) {
            let role = list.iter().find(|m| m.user_id == *user_id).map(|m| m.role.clone());
            Ok(role)
        } else {
            Ok(None)
        }
    }

    async fn add_member(&self, member: &GroupMember) -> Result<(), Error> {
        let mut members = self.group_members.lock().await;
        let list = members.entry(member.group_id).or_insert_with(Vec::new);
        if !list.iter().any(|m| m.user_id == member.user_id) {
            list.push(member.clone());
        }
        Ok(())
    }

    async fn remove_member(&self, group_id: &Uuid, user_id: &Uuid) -> Result<(), Error> {
        let mut members = self.group_members.lock().await;
        if let Some(list) = members.get_mut(group_id) {
            list.retain(|m| m.user_id != *user_id);
        }
        Ok(())
    }

    async fn update_member_role(&self, group_id: &Uuid, user_id: &Uuid, role: GroupRole) -> Result<(), Error> {
        let mut members = self.group_members.lock().await;
        if let Some(list) = members.get_mut(group_id) {
            if let Some(m) = list.iter_mut().find(|m| m.user_id == *user_id) {
                m.role = role;
            }
        }
        Ok(())
    }

    async fn get_user_groups(&self, user_id: &Uuid) -> Result<Vec<Group>, Error> {
        let groups = self.groups.lock().await;
        let members = self.group_members.lock().await;
        let mut result = Vec::new();
        for (gid, m_list) in members.iter() {
            if m_list.iter().any(|m| m.user_id == *user_id) {
                if let Some(g) = groups.get(gid) {
                    result.push(g.clone());
                }
            }
        }
        Ok(result)
    }
}

#[async_trait]
impl PushTokenRepository for InMemoryRepository {
    async fn register_token(&self, device_id: &Uuid, token: &str) -> Result<(), Error> {
        let mut tokens = self.push_tokens.lock().await;
        tokens.insert(*device_id, token.to_string());
        Ok(())
    }

    async fn get_token_by_device_id(&self, device_id: &Uuid) -> Result<Option<String>, Error> {
        let tokens = self.push_tokens.lock().await;
        Ok(tokens.get(device_id).cloned())
    }
}
