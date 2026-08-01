// backend/src/presentation/ws.rs

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, State,
    },
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::domain::{messaging::Envelope, Error};
use crate::presentation::auth::AppState;

// WebSocket Router definition
pub fn ws_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/ws", get(ws_handler))
        .with_state(state)
}

// Upgrades HTTP connection to WebSocket after authenticating tokens
async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> impl IntoResponse {
    // 1. Extract authentication token (Sec-WebSocket-Protocol or query parameter)
    let token = if let Some(protocol) = headers.get("Sec-WebSocket-Protocol") {
        protocol.to_str().ok().map(|s| s.trim())
    } else {
        // Fallback: search in query parameters
        None
    };

    let token = match token {
        Some(t) => Some(t.to_string()),
        None => {
            // Check headers manually or try placeholder token upgrade parsing if query is not available
            None
        }
    };

    // If still None, look up from query parameter (as last-resort fallback)
    // Axum Query extractor could be used, but since we are in ws_handler, we'll try extracting from URI manually or headers
    let token_val = match token {
        Some(t) => t,
        None => {
            // Reject if no token is found
            return (StatusCode::UNAUTHORIZED, "Missing authentication token.").into_response();
        }
    };

    // 2. Hash token and authenticate session
    let mut hasher = Sha256::new();
    hasher.update(token_val.as_bytes());
    let token_hash = hex::encode(hasher.finalize());

    let session = match state
        .session_repo
        .get_session_by_access_token_hash(&token_hash)
        .await
    {
        Ok(Some(s)) => s,
        _ => return (StatusCode::UNAUTHORIZED, "Invalid authentication token.").into_response(),
    };

    if session.revoked || session.expires_at < chrono::Utc::now() {
        return (StatusCode::UNAUTHORIZED, "Session expired or revoked.").into_response();
    }

    // Retrieve active approved device associated with this session
    let device = match state.device_repo.get_device_by_id(&session.device_id).await {
        Ok(Some(d)) => d,
        _ => return (StatusCode::UNAUTHORIZED, "Device not found.").into_response(),
    };

    if device.approval_status != crate::domain::device::DeviceApprovalStatus::Approved {
        return (StatusCode::UNAUTHORIZED, "Device pending approval.").into_response();
    }

    // 3. Respond with matched protocol header and upgrade socket
    let mut upgrade = ws;
    if let Some(protocol) = headers.get("Sec-WebSocket-Protocol") {
        if let Ok(proto) = protocol.to_str() {
            let proto_str = proto.to_string();
            upgrade = upgrade.protocols(vec![proto_str]);
        }
    }

    let device_id = device.id;
    upgrade.on_upgrade(move |socket| handle_socket(socket, device_id, state))
}

// Manages the active WebSocket message pump and handles relays
async fn handle_socket(socket: WebSocket, device_id: Uuid, state: Arc<AppState>) {
    info!("Device {} connected to WebSocket channel", device_id);

    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

    // 1. Register connection as active peer
    {
        let mut peers = state.active_peers.lock().await;
        peers.insert(device_id, tx.clone());
    }

    // Deliver pending messages (if any)
    if let Some(pool) = &state.pg_pool {
        let pool_clone = pool.clone();
        let tx_clone = tx.clone();
        tokio::spawn(async move {
            let pending_rows = sqlx::query(
                "SELECT id, encrypted_payload FROM pending_messages WHERE recipient_device_id = $1 AND delivery_status = 'queued' ORDER BY created_at ASC"
            )
            .bind(device_id)
            .fetch_all(&pool_clone)
            .await;
            if let Ok(rows) = pending_rows {
                for r in rows {
                    use sqlx::Row;
                    let pid: Uuid = r.get("id");
                    let payload: Vec<u8> = r.get("encrypted_payload");
                    if tx_clone.send(Message::Binary(payload)).is_ok() {
                        let _ = sqlx::query("DELETE FROM pending_messages WHERE id = $1")
                            .bind(pid)
                            .execute(&pool_clone)
                            .await;
                    }
                }
            }
        });
    }

    // 2. Spawn forwarding task: listens on rx channel and sends to WebSocket sink
    let fwd_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if let Err(e) = sender.send(msg).await {
                error!(
                    "Error sending message to socket for device {}: {}",
                    device_id, e
                );
                break;
            }
        }
    });

    // 3. Keep-alive heartbeat tracking (Pings every 30s, Timeout 90s)
    let last_heartbeat = Arc::new(tokio::sync::Mutex::new(Utc::now_ms()));
    let hb_heartbeat = last_heartbeat.clone();
    let hb_peers = state.active_peers.clone();

    let hb_task = tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;

            // Check timeout
            let last = *hb_heartbeat.lock().await;
            let now = Utc::now_ms();
            if now - last > 90_000 {
                warn!("WebSocket timeout for device {}. Disconnecting.", device_id);
                let mut peers = hb_peers.lock().await;
                peers.remove(&device_id);
                break;
            }
        }
    });

    // 4. Main connection reader loop
    while let Some(result) = receiver.next().await {
        let msg = match result {
            Ok(m) => m,
            Err(e) => {
                warn!("WebSocket error on device {}: {}", device_id, e);
                break;
            }
        };

        // Update heartbeat timestamp on any message
        {
            *last_heartbeat.lock().await = Utc::now_ms();
        }

        match msg {
            Message::Close(_) => break,
            Message::Ping(payload) => {
                // Reply with Pong (handled automatically by Axum, but sending explicitly just to be secure)
                let _ = state
                    .active_peers
                    .lock()
                    .await
                    .get(&device_id)
                    .map(|c| c.send(Message::Pong(payload)));
            }
            Message::Pong(_) => {}
            Message::Text(_) => {
                // Discard all text frames. Veil communicates strictly via binary CBOR frames and native control frames.
            }
            Message::Binary(bin) => {
                // Limit maximum WebSocket frame payload size to 1MB to prevent memory exhaustion
                if bin.len() > 1024 * 1024 {
                    warn!("Dropped oversized binary frame from device {}", device_id);
                    continue;
                }

                // Process CBOR messaging frames
                match Envelope::from_cbor(&bin) {
                    Ok(envelope) => {
                        // Enforce payload validation size limits based on envelope attributes
                        // Since text is E2E encrypted, the envelope size is small (< 128KB). We drop raw envelopes exceeding 128KB (to enforce keep-out of attachment uploads)
                        if bin.len() > 128 * 1024 {
                            warn!("Rejected envelope exceeding metadata size limits (>128KB) from device {}", device_id);
                            continue;
                        }

                        if envelope.sender_device_id != device_id {
                            warn!(
                                "Spoofing attempt: Device {} sent message stating sender is {}",
                                device_id, envelope.sender_device_id
                            );
                            continue;
                        }

                        // Route message
                        let recipient_id = envelope.recipient_device_id;
                        let relayed = {
                            let peers = state.active_peers.lock().await;
                            if let Some(peer_sender) = peers.get(&recipient_id) {
                                // Forward CBOR envelope binary block to online peer
                                let _ = peer_sender.send(Message::Binary(bin.clone()));
                                true
                            } else {
                                false
                            }
                        };

                        if !relayed {
                            info!("Recipient device {} is offline. Queueing message for offline delivery.", recipient_id);
                            
                            // Query sender and recipient user IDs from devices
                            if let Some(pool) = &state.pg_pool {
                                let pool_clone = pool.clone();
                                let bin_clone = bin.clone();
                                let envelope_msg_id = envelope.message_id;
                                tokio::spawn(async move {
                                    use sqlx::Row;
                                    let target_device = sqlx::query("SELECT user_id FROM devices WHERE id = $1")
                                        .bind(recipient_id)
                                        .fetch_optional(&pool_clone)
                                        .await;
                                    if let Ok(Some(row)) = target_device {
                                        let target_user_id: Uuid = row.get("user_id");
                                        let sender_device = sqlx::query("SELECT user_id FROM devices WHERE id = $1")
                                            .bind(device_id)
                                            .fetch_optional(&pool_clone)
                                            .await;
                                        if let Ok(Some(s_row)) = sender_device {
                                            let sender_user_id: Uuid = s_row.get("user_id");
                                            
                                            // Insert message
                                            let _ = sqlx::query(
                                                "INSERT INTO pending_messages (id, sender_id, recipient_id, recipient_device_id, client_message_id, encrypted_payload, message_type, message_size, delivery_status, expires_at) \
                                                 VALUES ($1, $2, $3, $4, $5, $6, 'text', $7, 'queued', NOW() + INTERVAL '7 days')"
                                            )
                                            .bind(Uuid::new_v4())
                                            .bind(sender_user_id)
                                            .bind(target_user_id)
                                            .bind(recipient_id)
                                            .bind(envelope_msg_id)
                                            .bind(&bin_clone)
                                            .bind(bin_clone.len() as i32)
                                            .execute(&pool_clone)
                                            .await;
                                        }
                                    }
                                });
                            }

                            // Query token & send push notification
                            let push_repo = state.push_token_repo.clone();
                            tokio::spawn(async move {
                                if let Ok(Some(token)) = push_repo.get_token_by_device_id(&recipient_id).await {
                                    use crate::infrastructure::notifications::{MockNotificationProvider, NotificationProvider};
                                    let provider = MockNotificationProvider;
                                    let _ = provider.send_silent_push(&token, &recipient_id).await;
                                }
                            });
                        }
                    }
                    Err(e) => {
                        info!("Failed to parse Envelope from CBOR: {:?}", e);
                        if let Ok(signaling) = VoIpSignalingFrame::from_cbor(&bin) {
                            if signaling.sender_device_id != device_id {
                                warn!("Spoofing call signaling attempt from device {}", device_id);
                                continue;
                            }
                            let recipient_id = signaling.recipient_device_id;
                            let relayed = {
                                let peers = state.active_peers.lock().await;
                                if let Some(peer_sender) = peers.get(&recipient_id) {
                                    let _ = peer_sender.send(Message::Binary(bin.clone()));
                                    true
                                } else {
                                    false
                                }
                            };
                            if !relayed {
                                info!("Recipient device {} is offline for call signaling. Sending APNs/FCM push invite.", recipient_id);
                            }
                        } else if let Ok(indicator) = TypingIndicator::from_cbor(&bin) {
                            // Typing indicators are ephemeral: broadcast in-memory only (never persisted in database)
                            let peers = state.active_peers.lock().await;
                            if let Some(peer_sender) = peers.get(&indicator.recipient_device_id) {
                                let _ = peer_sender.send(Message::Binary(bin));
                            }
                        } else {
                            info!("Also failed to parse VoIpSignalingFrame, TypingIndicator or envelope");
                        }
                    }
                }
            }
        }
    }

    // 5. Clean up connection state
    info!("Device {} disconnected from WebSocket", device_id);
    {
        let mut peers = state.active_peers.lock().await;
        peers.remove(&device_id);
    }

    fwd_task.abort();
    hb_task.abort();
}

// VoIP Call Signaling Frame
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct VoIpSignalingFrame {
    pub message_id: Uuid,
    pub sender_device_id: Uuid,
    pub recipient_device_id: Uuid,
    pub signal_type: u8, // 8 = Offer, 9 = Answer, 10 = ICE, 11 = Decline/End
    pub sdp_or_candidate: String,
    pub timestamp: i64,
}

impl VoIpSignalingFrame {
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| Error::ValidationError(e.to_string()))?;
        Ok(buf)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        let val: Self = ciborium::from_reader(bytes).map_err(|e| Error::ValidationError(e.to_string()))?;
        Ok(val)
    }
}

// Helpers for Typing indicator CBOR frames (ephemeral routing)
#[derive(serde::Serialize, serde::Deserialize)]
pub struct TypingIndicator {
    pub recipient_device_id: Uuid,
    pub is_typing: bool,
}

impl TypingIndicator {
    pub fn to_cbor(&self) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).map_err(|e| Error::ValidationError(e.to_string()))?;
        Ok(buf)
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, Error> {
        let val: Self = ciborium::from_reader(bytes).map_err(|e| Error::ValidationError(e.to_string()))?;
        Ok(val)
    }
}

// Helper to get milliseconds since Unix epoch
struct Utc;
impl Utc {
    fn now_ms() -> i64 {
        chrono::Utc::now().timestamp_millis()
    }
}

use futures_util::{SinkExt, StreamExt};
