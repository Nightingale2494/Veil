// backend/src/infrastructure/config/mod.rs

use std::env;

pub struct Config {
    pub database_url: String,
    pub server_address: String,
}

impl Config {
    pub fn from_env() -> Self {
        // Load environment variables from .env file if present
        dotenvy::dotenv().ok();

        let database_url = env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/veil".to_string());
        let server_address =
            env::var("SERVER_ADDRESS").unwrap_or_else(|_| "127.0.0.1:8080".to_string());

        Self {
            database_url,
            server_address,
        }
    }
}
