pub mod attachments;
pub mod auth;
pub mod ws;

pub use auth::AppState;
use axum::{routing::get, Router};
use std::sync::Arc;

pub fn app_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .nest("/api/v1/auth", auth::auth_router(state.clone()))
        .nest("/api/v1", ws::ws_router(state.clone()))
        .nest("/api/v1", attachments::attachments_router(state))
}

async fn health_check() -> &'static str {
    "OK"
}
