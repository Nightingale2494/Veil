// backend/src/main.rs

mod application;
mod domain;
mod infrastructure;
mod presentation;

use crate::domain::repositories::{
    AttachmentRepository, AuditLogRepository, DeviceRepository, DeviceSessionRepository,
    GroupRepository, LoginAttemptRepository, PreKeyRepository, PushTokenRepository,
    RecoveryAttemptRepository, ReplayCacheRepository, SessionRepository, UserRepository,
};
use axum::{
    extract::Request,
    middleware::{self, Next},
    response::Response,
};
use infrastructure::{
    config::Config,
    crypto::RustCryptoProvider,
    database::DatabaseConnection,
    logging::init_logging,
    repositories::{in_memory::InMemoryRepository, postgres::PostgresRepository},
};
use presentation::{app_router, AppState};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    init_logging();

    info!("Starting Veil backend server...");

    // Load config
    let config = Config::from_env();

    // Initialize Database & Repositories State
    let state = match DatabaseConnection::connect(&config.database_url).await {
        Ok(db) => {
            info!("Database connected successfully. Initializing PostgreSQL adapters.");
            let pg_repo = Arc::new(PostgresRepository::new(db.pool.clone()));
            AppState {
                user_repo: pg_repo.clone() as Arc<dyn UserRepository>,
                device_repo: pg_repo.clone() as Arc<dyn DeviceRepository>,
                session_repo: pg_repo.clone() as Arc<dyn SessionRepository>,
                login_repo: pg_repo.clone() as Arc<dyn LoginAttemptRepository>,
                recovery_repo: pg_repo.clone() as Arc<dyn RecoveryAttemptRepository>,
                audit_repo: pg_repo.clone() as Arc<dyn AuditLogRepository>,
                crypto: Arc::new(RustCryptoProvider),
                hmac_key: b"production_server_refresh_token_hmac_secret_key_32_bytes".to_vec(),
                prekey_repo: pg_repo.clone() as Arc<dyn PreKeyRepository>,
                device_session_repo: pg_repo.clone() as Arc<dyn DeviceSessionRepository>,
                replay_repo: pg_repo.clone() as Arc<dyn ReplayCacheRepository>,
                server_state_key: b"production_ratchet_state_encrypt_key_32_b".to_vec(),
                active_peers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
                attachment_repo: pg_repo.clone() as Arc<dyn AttachmentRepository>,
                pg_pool: Some(db.pool),
                group_repo: pg_repo.clone() as Arc<dyn GroupRepository>,
                push_token_repo: pg_repo.clone() as Arc<dyn PushTokenRepository>,
            }
        }
        Err(e) => {
            warn!(
                "Database connection failed: {}. Continuing in offline/mock mode.",
                e
            );
            let mock_repo = Arc::new(InMemoryRepository::new());
            AppState {
                user_repo: mock_repo.clone() as Arc<dyn UserRepository>,
                device_repo: mock_repo.clone() as Arc<dyn DeviceRepository>,
                session_repo: mock_repo.clone() as Arc<dyn SessionRepository>,
                login_repo: mock_repo.clone() as Arc<dyn LoginAttemptRepository>,
                recovery_repo: mock_repo.clone() as Arc<dyn RecoveryAttemptRepository>,
                audit_repo: mock_repo.clone() as Arc<dyn AuditLogRepository>,
                crypto: Arc::new(RustCryptoProvider),
                hmac_key: b"mock_development_hmac_secret_key".to_vec(),
                prekey_repo: mock_repo.clone() as Arc<dyn PreKeyRepository>,
                device_session_repo: mock_repo.clone() as Arc<dyn DeviceSessionRepository>,
                replay_repo: mock_repo.clone() as Arc<dyn ReplayCacheRepository>,
                server_state_key: b"mock_ratchet_state_encrypt_key_32_b".to_vec(),
                active_peers: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
                attachment_repo: mock_repo.clone() as Arc<dyn AttachmentRepository>,
                pg_pool: None,
                group_repo: mock_repo.clone() as Arc<dyn GroupRepository>,
                push_token_repo: mock_repo.clone() as Arc<dyn PushTokenRepository>,
            }
        }
    };

    let shared_state = Arc::new(state);

    // Spawn attachment cleanup worker loop in the background
    let cleanup_worker =
        application::workers::AttachmentCleanupWorker::new(shared_state.attachment_repo.clone());
    tokio::spawn(cleanup_worker.start());

    // Build app router with state and register HTTP security headers middleware
    let app = app_router(shared_state.clone())
        .layer(axum::extract::DefaultBodyLimit::max(5 * 1024 * 1024)) // 5MB payload limit
        .layer(middleware::from_fn(add_security_headers));

    // Run the server
    let listener = tokio::net::TcpListener::bind(&config.server_address).await?;
    info!(
        "Veil backend is running on http://{}",
        config.server_address
    );

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

use std::net::SocketAddr;

// Middleware to inject secure HTTP response headers
async fn add_security_headers(req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();

    // Inject HSTS, nosniff, framing limits, and referrer policy
    headers.insert(
        "Strict-Transport-Security",
        "max-age=63072000; includeSubDomains; preload"
            .parse()
            .unwrap(),
    );
    headers.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    headers.insert("Referrer-Policy", "no-referrer".parse().unwrap());
    headers.insert("X-Frame-Options", "DENY".parse().unwrap());

    response
}
