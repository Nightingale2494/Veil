// backend/src/infrastructure/logging/mod.rs

use tracing_subscriber::{fmt, prelude::*, EnvFilter};

pub fn init_logging() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();
}
