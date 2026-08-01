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
        LoginAttemptRepository, PreKeyRepository, RecoveryAttemptRepository, ReplayCacheRepository,
        SessionRepository, UserRepository,
    },
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
