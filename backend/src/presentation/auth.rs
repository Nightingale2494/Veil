// backend/src/presentation/auth.rs

use axum::{
    extract::{ConnectInfo, State, Path},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;

use crate::application::auth::{
    LoginRequest, LoginUseCase, RecoverRequest, RecoverUseCase, RefreshRequest, RefreshUseCase,
    RegisterRequest, RegisterUseCase,
};
use crate::domain::{
    repositories::{
        AttachmentRepository, AuditLogRepository, DeviceRepository, DeviceSessionRepository,
        GroupRepository, LoginAttemptRepository, PreKeyRepository, PushTokenRepository,
        RecoveryAttemptRepository, ReplayCacheRepository, SessionRepository, UserRepository,
    },
    session::AuditLog,
    CryptoProvider, Error,
};

pub struct AppState {
    pub user_repo: Arc<dyn UserRepository>,
    pub device_repo: Arc<dyn DeviceRepository>,
    pub session_repo: Arc<dyn SessionRepository>,
    pub login_repo: Arc<dyn LoginAttemptRepository>,
    pub recovery_repo: Arc<dyn RecoveryAttemptRepository>,
    pub audit_repo: Arc<dyn AuditLogRepository>,
    pub crypto: Arc<dyn CryptoProvider>,
    pub hmac_key: Vec<u8>,

    // Phase 3 additions
    pub prekey_repo: Arc<dyn PreKeyRepository>,
    pub device_session_repo: Arc<dyn DeviceSessionRepository>,
    pub replay_repo: Arc<dyn ReplayCacheRepository>,
    pub server_state_key: Vec<u8>,
    pub active_peers: Arc<
        tokio::sync::Mutex<
            std::collections::HashMap<
                Uuid,
                tokio::sync::mpsc::UnboundedSender<axum::extract::ws::Message>,
            >,
        >,
    >,

    // Phase 4 additions
    pub attachment_repo: Arc<dyn AttachmentRepository>,
    pub pg_pool: Option<sqlx::PgPool>,

    // Group & Push notification additions
    pub group_repo: Arc<dyn GroupRepository>,
    pub push_token_repo: Arc<dyn PushTokenRepository>,
}

pub fn auth_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/register", post(register_handler))
        .route("/login", post(login_handler))
        .route("/refresh", post(refresh_handler))
        .route("/recover", post(recover_handler))
        .route("/logout", post(logout_handler))
        .route("/approve", post(approve_device_handler))
        .route("/prekeys/upload", post(upload_prekeys_handler))
        .route("/prekeys/download/:device_id", get(download_prekeys_handler))
        .route("/test/cleanup", post(test_cleanup_handler))
        .route("/users/lookup/:username_or_id", get(lookup_user_handler))
        .route("/groups/create", post(create_group_handler))
        .route("/groups/invite", post(invite_member_handler))
        .route("/groups/remove", post(remove_member_handler))
        .route("/groups", get(get_groups_handler))
        .route("/notifications/register", post(register_push_token_handler))
        .with_state(state)
}

// Helper to hash IP address immediately for privacy preservation
fn hash_ip(addr: SocketAddr) -> String {
    let mut hasher = Sha256::new();
    hasher.update(addr.ip().to_string().as_bytes());
    hex::encode(hasher.finalize())
}

// Extractor helper for User-Agent
fn get_user_agent(headers: &HeaderMap) -> Option<&str> {
    headers.get("user-agent").and_then(|v| v.to_str().ok())
}

async fn register_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<RegisterRequest>,
) -> Result<Json<crate::application::auth::AuthResponse>, (StatusCode, String)> {
    let ip_hash = hash_ip(addr);
    let ua = get_user_agent(&headers);

    let use_case = RegisterUseCase {
        user_repo: state.user_repo.as_ref(),
        device_repo: state.device_repo.as_ref(),
        session_repo: state.session_repo.as_ref(),
        audit_repo: state.audit_repo.as_ref(),
        crypto: state.crypto.as_ref(),
        hmac_key: state.hmac_key.clone(),
    };

    match use_case.execute(payload, &ip_hash, ua).await {
        Ok(res) => Ok(Json(res)),
        Err(e) => Err(map_error(e)),
    }
}

async fn login_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<crate::application::auth::AuthResponse>, (StatusCode, String)> {
    let ip_hash = hash_ip(addr);
    let ua = get_user_agent(&headers);

    let use_case = LoginUseCase {
        user_repo: state.user_repo.as_ref(),
        device_repo: state.device_repo.as_ref(),
        session_repo: state.session_repo.as_ref(),
        login_repo: state.login_repo.as_ref(),
        audit_repo: state.audit_repo.as_ref(),
        crypto: state.crypto.as_ref(),
        hmac_key: state.hmac_key.clone(),
    };

    match use_case.execute(payload, &ip_hash, ua).await {
        Ok(res) => Ok(Json(res)),
        Err(e) => Err(map_error(e)),
    }
}

async fn refresh_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<RefreshRequest>,
) -> Result<Json<crate::application::auth::SessionResponse>, (StatusCode, String)> {
    let ip_hash = hash_ip(addr);

    let use_case = RefreshUseCase {
        session_repo: state.session_repo.as_ref(),
        crypto: state.crypto.as_ref(),
        hmac_key: state.hmac_key.clone(),
    };

    match use_case.execute(payload, &ip_hash).await {
        Ok(res) => Ok(Json(res)),
        Err(e) => Err(map_error(e)),
    }
}

async fn recover_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<RecoverRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let ip_hash = hash_ip(addr);

    let use_case = RecoverUseCase {
        user_repo: state.user_repo.as_ref(),
        device_repo: state.device_repo.as_ref(),
        session_repo: state.session_repo.as_ref(),
        recovery_repo: state.recovery_repo.as_ref(),
        audit_repo: state.audit_repo.as_ref(),
        crypto: state.crypto.as_ref(),
    };

    match use_case.execute(payload, &ip_hash).await {
        Ok(_) => Ok(StatusCode::OK),
        Err(e) => Err(map_error(e)),
    }
}

async fn logout_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RefreshRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    // 1. Hash incoming refresh token
    let incoming_hash = match state
        .crypto
        .compute_hmac(&state.hmac_key, payload.refresh_token.as_bytes())
    {
        Ok(h) => hex::encode(h),
        Err(e) => return Err((StatusCode::BAD_REQUEST, e.to_string())),
    };

    // 2. Fetch session and revoke it
    match state
        .session_repo
        .get_session_by_refresh_token_hash(&incoming_hash)
        .await
    {
        Ok(Some(session)) => {
            if let Err(e) = state.session_repo.revoke_session(&session.id).await {
                return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()));
            }
            Ok(StatusCode::OK)
        }
        Ok(None) => Err((
            StatusCode::UNAUTHORIZED,
            "Invalid refresh token.".to_string(),
        )),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

// Generic clean error mapper returning HTTP status code and response payload
fn map_error(err: Error) -> (StatusCode, String) {
    match err {
        Error::ValidationError(msg) => (StatusCode::BAD_REQUEST, msg),
        Error::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
        Error::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
        Error::CryptoError(msg) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Crypto failure: {}", msg),
        ),
        Error::DatabaseError(msg) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database failure: {}", msg),
        ),
    }
}

#[derive(serde::Deserialize)]
pub struct ApproveDeviceRequest {
    pub device_id: Uuid,
}

async fn approve_device_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ApproveDeviceRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    state
        .device_repo
        .update_device_status(&payload.device_id, crate::domain::device::DeviceApprovalStatus::Approved)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::OK)
}

#[derive(serde::Deserialize)]
pub struct UploadPrekeysRequest {
    pub device_id: Uuid,
    pub identity_signing_key: Vec<u8>,
    pub identity_dh_key: Vec<u8>,
    pub identity_dh_signature: Vec<u8>,
    pub signed_prekey: Vec<u8>,
    pub prekey_signature: Vec<u8>,
    pub one_time_keys: Vec<Vec<u8>>,
}

async fn upload_prekeys_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<UploadPrekeysRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    state
        .prekey_repo
        .save_identity_key(
            &payload.device_id,
            &payload.identity_signing_key,
            &payload.identity_dh_key,
            &payload.identity_dh_signature,
            &payload.signed_prekey,
            &payload.prekey_signature,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if !payload.one_time_keys.is_empty() {
        state
            .prekey_repo
            .save_one_time_keys(&payload.device_id, &payload.one_time_keys)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    Ok(StatusCode::OK)
}

async fn download_prekeys_handler(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<Uuid>,
) -> Result<Json<crate::domain::messaging::PreKeyBundle>, (StatusCode, String)> {
    let bundle = state
        .prekey_repo
        .get_prekey_bundle(&device_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Prekey bundle not found".to_string()))?;

    Ok(Json(bundle))
}

async fn test_cleanup_handler(
    State(state): State<Arc<AppState>>,
) -> Result<StatusCode, (StatusCode, String)> {
    // 1. Soft delete unreferenced blobs (older than 0 hours)
    let unreferenced = state
        .attachment_repo
        .get_unreferenced_blobs(0)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    for blob in &unreferenced {
        let _ = state.attachment_repo.soft_delete_blob(&blob.id).await;
    }

    // 2. Physical delete expired soft-deleted blobs (older than 0 days)
    let expired = state
        .attachment_repo
        .get_expired_blobs(0)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    for blob in &expired {
        let file_path = format!("./uploads/{}", blob.id);
        let _ = tokio::fs::remove_file(&file_path).await;

        for idx in 0..blob.chunk_count {
            let chunk_path = format!("./uploads/{}_chunk_{}", blob.id, idx);
            let _ = tokio::fs::remove_file(&chunk_path).await;
        }

        let _ = state.attachment_repo.delete_blob_permanently(&blob.id).await;
    }

    Ok(StatusCode::OK)
}

#[derive(serde::Serialize)]
pub struct UserSearchResponse {
    pub user_id: Uuid,
    pub username: String,
    pub display_name: Option<String>,
    pub devices: Vec<DeviceResponse>,
}

#[derive(serde::Serialize)]
pub struct DeviceResponse {
    pub device_id: Uuid,
    pub device_name: String,
    pub device_public_key: Vec<u8>,
}

async fn lookup_user_handler(
    State(state): State<Arc<AppState>>,
    Path(username_or_id): Path<String>,
) -> Result<Json<UserSearchResponse>, (StatusCode, String)> {
    let mut user_opt = state
        .user_repo
        .get_user_by_username(&username_or_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if user_opt.is_none() {
        user_opt = state
            .user_repo
            .get_user_by_account_id(&username_or_id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    let user = user_opt.ok_or_else(|| (StatusCode::NOT_FOUND, "User not found".to_string()))?;

    let devices = state
        .device_repo
        .get_devices_by_user_id(&user.id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let device_responses = devices
        .into_iter()
        .filter(|d| d.deleted_at.is_none() && d.approval_status == crate::domain::device::DeviceApprovalStatus::Approved)
        .map(|d| DeviceResponse {
            device_id: d.id,
            device_name: d.device_name,
            device_public_key: d.device_public_key,
        })
        .collect();

    Ok(Json(UserSearchResponse {
        user_id: user.id,
        username: user.username,
        display_name: user.display_name,
        devices: device_responses,
    }))
}

use crate::domain::session::Session;
use crate::domain::group::{Group, GroupMember, GroupRole};
use chrono::Utc;

async fn authenticate_request(
    state: &AppState,
    auth_header: Option<&str>,
) -> Result<Session, (StatusCode, String)> {
    let header = auth_header.ok_or_else(|| (StatusCode::UNAUTHORIZED, "Missing authorization header".to_string()))?;
    if !header.starts_with("Bearer ") {
        return Err((StatusCode::UNAUTHORIZED, "Invalid authorization format".to_string()));
    }
    let token = &header[7..];

    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let token_hash = hex::encode(hasher.finalize());

    let session = state
        .session_repo
        .get_session_by_access_token_hash(&token_hash)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Invalid session token".to_string()))?;

    if session.revoked || session.expires_at < Utc::now() {
        return Err((StatusCode::UNAUTHORIZED, "Session expired or revoked".to_string()));
    }
    Ok(session)
}

#[derive(Debug, serde::Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
}

#[derive(Debug, serde::Serialize)]
pub struct CreateGroupResponse {
    pub id: Uuid,
    pub name: String,
}

async fn create_group_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<CreateGroupRequest>,
) -> Result<Json<CreateGroupResponse>, (StatusCode, String)> {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    let session = authenticate_request(&state, auth_header).await?;

    let device = state
        .device_repo
        .get_device_by_id(&session.device_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Device not found".to_string()))?;
    let caller_user_id = device.user_id;

    let group_id = Uuid::new_v4();
    let group = Group {
        id: group_id,
        name: payload.name,
        created_at: Utc::now(),
    };

    state
        .group_repo
        .create_group(&group, &caller_user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Log membership event as system audit log
    let _ = state.audit_repo.log_event(&AuditLog {
        id: Uuid::new_v4(),
        user_id: caller_user_id,
        device_id: Some(session.device_id),
        event_type: "create_group".to_string(),
        ip_hash: None,
        created_at: Utc::now(),
    }).await;

    Ok(Json(CreateGroupResponse {
        id: group.id,
        name: group.name,
    }))
}

#[derive(Debug, serde::Deserialize)]
pub struct InviteMemberRequest {
    pub group_id: Uuid,
    pub username_or_id: String,
}

async fn invite_member_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<InviteMemberRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    let session = authenticate_request(&state, auth_header).await?;

    let device = state
        .device_repo
        .get_device_by_id(&session.device_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Device not found".to_string()))?;
    let caller_user_id = device.user_id;

    // Enforce authorization: only Owner or Admin can invite
    let caller_role = state
        .group_repo
        .get_member_role(&payload.group_id, &caller_user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::FORBIDDEN, "Not a group member".to_string()))?;

    if caller_role != GroupRole::Owner && caller_role != GroupRole::Admin {
        return Err((StatusCode::FORBIDDEN, "Only admins or owners can invite members".to_string()));
    }

    // Resolve target user
    let mut target_user_opt = state
        .user_repo
        .get_user_by_username(&payload.username_or_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    if target_user_opt.is_none() {
        target_user_opt = state
            .user_repo
            .get_user_by_account_id(&payload.username_or_id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    let target_user = target_user_opt.ok_or_else(|| (StatusCode::NOT_FOUND, "Target user not found".to_string()))?;

    let new_member = GroupMember {
        group_id: payload.group_id,
        user_id: target_user.id,
        role: GroupRole::Member,
        joined_at: Utc::now(),
    };

    state
        .group_repo
        .add_member(&new_member)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Log membership event as system audit log
    let _ = state.audit_repo.log_event(&AuditLog {
        id: Uuid::new_v4(),
        user_id: caller_user_id,
        device_id: Some(session.device_id),
        event_type: "invite_member".to_string(),
        ip_hash: None,
        created_at: Utc::now(),
    }).await;

    Ok(StatusCode::OK)
}

#[derive(Debug, serde::Deserialize)]
pub struct RemoveMemberRequest {
    pub group_id: Uuid,
    pub user_id: Uuid,
}

async fn remove_member_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<RemoveMemberRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    let session = authenticate_request(&state, auth_header).await?;

    let device = state
        .device_repo
        .get_device_by_id(&session.device_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Device not found".to_string()))?;
    let caller_user_id = device.user_id;

    // Self-removal is allowed for any member (leave group)
    let is_self_removal = caller_user_id == payload.user_id;

    if !is_self_removal {
        // Enforce authorization: only Owner or Admin can remove
        let caller_role = state
            .group_repo
            .get_member_role(&payload.group_id, &caller_user_id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or_else(|| (StatusCode::FORBIDDEN, "Not a group member".to_string()))?;

        if caller_role != GroupRole::Owner && caller_role != GroupRole::Admin {
            return Err((StatusCode::FORBIDDEN, "Only admins or owners can remove members".to_string()));
        }

        let target_role = state
            .group_repo
            .get_member_role(&payload.group_id, &payload.user_id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or_else(|| (StatusCode::NOT_FOUND, "Target member not found".to_string()))?;

        if caller_role == GroupRole::Admin {
            // Admin can only remove normal members
            if target_role == GroupRole::Owner || target_role == GroupRole::Admin {
                return Err((StatusCode::FORBIDDEN, "Admins cannot remove other admins or the owner".to_string()));
            }
        }
    } else {
        // Owner cannot leave group directly (must delete or transfer ownership)
        let caller_role = state
            .group_repo
            .get_member_role(&payload.group_id, &caller_user_id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
            .ok_or_else(|| (StatusCode::FORBIDDEN, "Not a group member".to_string()))?;
        if caller_role == GroupRole::Owner {
            return Err((StatusCode::BAD_REQUEST, "Owner cannot leave the group. Transfer ownership or delete group instead.".to_string()));
        }
    }

    state
        .group_repo
        .remove_member(&payload.group_id, &payload.user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Log membership event as system audit log
    let _ = state.audit_repo.log_event(&AuditLog {
        id: Uuid::new_v4(),
        user_id: caller_user_id,
        device_id: Some(session.device_id),
        event_type: "remove_member".to_string(),
        ip_hash: None,
        created_at: Utc::now(),
    }).await;

    Ok(StatusCode::OK)
}

#[derive(Debug, serde::Serialize)]
pub struct GroupListResponse {
    pub groups: Vec<GroupWithMembers>,
}

#[derive(Debug, serde::Serialize)]
pub struct GroupWithMembers {
    pub id: Uuid,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub members: Vec<GroupMemberResponse>,
}

#[derive(Debug, serde::Serialize)]
pub struct GroupMemberResponse {
    pub user_id: Uuid,
    pub username: String,
    pub role: String,
}

async fn get_groups_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<GroupListResponse>, (StatusCode, String)> {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    let session = authenticate_request(&state, auth_header).await?;

    let device = state
        .device_repo
        .get_device_by_id(&session.device_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Device not found".to_string()))?;
    let caller_user_id = device.user_id;

    let groups = state
        .group_repo
        .get_user_groups(&caller_user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut groups_with_members = Vec::new();
    for g in groups {
        let members = state
            .group_repo
            .get_group_members(&g.id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let mut member_responses = Vec::new();
        for m in members {
            let u = state
                .user_repo
                .get_user_by_id(&m.user_id)
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
                .ok_or_else(|| (StatusCode::NOT_FOUND, "User not found".to_string()))?;

            member_responses.push(GroupMemberResponse {
                user_id: m.user_id,
                username: u.username,
                role: m.role.as_str().to_string(),
            });
        }

        groups_with_members.push(GroupWithMembers {
            id: g.id,
            name: g.name,
            created_at: g.created_at,
            members: member_responses,
        });
    }

    Ok(Json(GroupListResponse {
        groups: groups_with_members,
    }))
}

#[derive(Debug, serde::Deserialize)]
pub struct RegisterPushTokenRequest {
    pub token: String,
}

async fn register_push_token_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<RegisterPushTokenRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());
    let session = authenticate_request(&state, auth_header).await?;

    state
        .push_token_repo
        .register_token(&session.device_id, &payload.token)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(StatusCode::OK)
}
