//! Web dashboard and REST API for TanOS node.

use axum::{
    extract::{Path, State},
    response::Html,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::info;

use tanos_core::{identity::NodeIdentity, GossipPacket, InnerMessage};

use crate::{db, PeerStatus, PeerTable};

#[derive(Clone)]
pub struct AppState {
    pub identity: Arc<NodeIdentity>,
    pub peer_table: PeerTable,
    pub database: db::Db,
    pub msg_tx: mpsc::Sender<GossipPacket>,
}

// ─── Request / Response Types ────────────────────────────────────────────

#[derive(Serialize)]
struct IdentityResponse {
    tan_id: String,
    friendly_name: String,
    public_key: String,
}

#[derive(Deserialize)]
struct UpdateIdentityRequest {
    friendly_name: String,
}

#[derive(Serialize)]
struct PeerResponse {
    tan_id: String,
    friendly_name: String,
    status: String,
}

#[derive(Deserialize)]
pub struct ApproveRequest {
    tan_id: String,
}

#[derive(Deserialize)]
pub struct SendRequest {
    tan_id: String,
    message: String,
}

#[derive(Serialize)]
struct ApiResult {
    ok: bool,
    message: String,
}

#[derive(Serialize)]
struct StatusResponse {
    online: bool,
    tan_id: String,
}

// ─── Router ──────────────────────────────────────────────────────────────

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(serve_dashboard))
        .route("/api/status", get(get_status))
        .route("/api/identity", get(get_identity))
        .route("/api/identity", post(update_identity))
        .route("/api/peers", get(get_peers))
        .route("/api/messages/{peer_id}", get(get_messages))
        .route("/api/conversations", get(get_conversations))
        .route("/api/approve", post(approve_peer))
        .route("/api/send", post(send_message))
        .route("/api/console", post(execute_command))
        .with_state(state)
}

// ─── Handlers ────────────────────────────────────────────────────────────

async fn serve_dashboard() -> Html<&'static str> {
    Html(include_str!("dashboard.html"))
}

async fn get_status(State(state): State<AppState>) -> Json<StatusResponse> {
    Json(StatusResponse {
        online: true,
        tan_id: state.identity.tan_id.clone(),
    })
}

async fn get_identity(State(state): State<AppState>) -> Json<IdentityResponse> {
    Json(IdentityResponse {
        tan_id: state.identity.tan_id.clone(),
        friendly_name: state.identity.friendly_name.lock().unwrap().clone(),
        public_key: hex::encode(state.identity.public_key_bytes()),
    })
}

async fn update_identity(
    State(state): State<AppState>,
    Json(req): Json<UpdateIdentityRequest>,
) -> Json<ApiResult> {
    if req.friendly_name.trim().is_empty() {
        return Json(ApiResult { ok: false, message: "Name cannot be empty".to_string() });
    }
    
    let mut name = state.identity.friendly_name.lock().unwrap();
    *name = req.friendly_name.clone();
    drop(name);
    
    // Persist to file
    if let Err(e) = tanos_core::identity::save_identity(&state.identity) {
        return Json(ApiResult { ok: false, message: format!("Failed to save: {}", e) });
    }
    
    Json(ApiResult { ok: true, message: "Name updated".to_string() })
}

async fn get_peers(State(state): State<AppState>) -> Json<Vec<PeerResponse>> {
    let pt = state.peer_table.lock().await;
    Json(
        pt.iter()
            .map(|(id, info)| PeerResponse {
                tan_id: id.clone(),
                friendly_name: info.friendly_name.clone(),
                status: info.status.as_str().to_string(),
            })
            .collect(),
    )
}

async fn get_messages(
    State(state): State<AppState>,
    Path(peer_id): Path<String>,
) -> Json<Vec<db::StoredMessage>> {
    let db = state.database.lock().await;
    let msgs = db.get_messages_with_peer(&peer_id).unwrap_or_default();
    Json(msgs)
}

async fn get_conversations(
    State(state): State<AppState>,
) -> Json<Vec<db::ConversationPreview>> {
    let db = state.database.lock().await;
    let convos = db.get_conversations().unwrap_or_default();
    Json(convos)
}

async fn approve_peer(
    State(state): State<AppState>,
    Json(req): Json<ApproveRequest>,
) -> Json<ApiResult> {
    let mut pt = state.peer_table.lock().await;
    if let Some(p) = pt.get_mut(&req.tan_id) {
        p.status = PeerStatus::Approved;
        let approval = InnerMessage::FriendApproval {
            friendly_name: state.identity.friendly_name.lock().unwrap().clone(),
        };
        let beacon = p.beacon.clone();
        let friendly = p.friendly_name.clone();
        drop(pt);

        // Persist to DB
        {
            let db = state.database.lock().await;
            let _ = db.upsert_peer(&req.tan_id, &friendly, "approved");
        }

        match crate::send_inner_message(&state.identity, &beacon, approval, &state.msg_tx).await {
            Ok(_) => Json(ApiResult { ok: true, message: format!("Approved {}", req.tan_id) }),
            Err(e) => Json(ApiResult { ok: false, message: format!("Approved locally but send failed: {}", e) }),
        }
    } else {
        Json(ApiResult { ok: false, message: "Peer not found".to_string() })
    }
}

async fn send_message(
    State(state): State<AppState>,
    Json(req): Json<SendRequest>,
) -> Json<ApiResult> {
    let pt = state.peer_table.lock().await;
    if let Some(p) = pt.get(&req.tan_id) {
        if p.status != PeerStatus::Approved {
            return Json(ApiResult { ok: false, message: "Peer not approved yet".to_string() });
        }
        let beacon = p.beacon.clone();
        drop(pt);

        let inner = InnerMessage::Text(req.message.clone());
        match crate::send_inner_message(&state.identity, &beacon, inner, &state.msg_tx).await {
            Ok(_) => {
                // Persist sent message
                let db = state.database.lock().await;
                let _ = db.save_message(&req.tan_id, &req.message, "sent");
                Json(ApiResult { ok: true, message: "Sent".to_string() })
            }
            Err(e) => Json(ApiResult { ok: false, message: format!("Failed: {}", e) }),
        }
    } else {
        Json(ApiResult { ok: false, message: "Peer not found".to_string() })
    }
}

#[derive(Deserialize)]
pub struct ConsoleRequest {
    pub command: String,
}

#[derive(Serialize)]
pub struct ConsoleResponse {
    pub output: String,
}

async fn execute_command(
    State(state): State<AppState>,
    Json(req): Json<ConsoleRequest>,
) -> Json<ConsoleResponse> {
    let parts: Vec<&str> = req.command.trim().split_whitespace().collect();
    if parts.is_empty() {
        return Json(ConsoleResponse { output: String::new() });
    }

    let output = match parts[0] {
        "help" => "Available commands: id, peers, approve <id>, send <id> <msg>, clear, help".to_string(),
        "id" => format!(
            "Identity:\n  TanID: {}\n  Name:  {}\n  Key:   {}",
            state.identity.tan_id,
            state.identity.friendly_name.lock().unwrap(),
            hex::encode(state.identity.public_key_bytes())
        ),
        "peers" => {
            let pt = state.peer_table.lock().await;
            if pt.is_empty() {
                "No peers discovered yet.".to_string()
            } else {
                let mut s = String::from("Discovered Peers:\n");
                for (id, info) in pt.iter() {
                    s.push_str(&format!("  - {} [{}] ({:?})\n", info.friendly_name, id, info.status));
                }
                s
            }
        }
        "approve" => {
            if parts.len() < 2 {
                "Usage: approve <tan_id>".to_string()
            } else {
                let id = parts[1].to_string();
                let mut pt = state.peer_table.lock().await;
                if let Some(p) = pt.get_mut(&id) {
                    p.status = PeerStatus::Approved;
                    let approval = InnerMessage::FriendApproval {
                        friendly_name: state.identity.friendly_name.lock().unwrap().clone(),
                    };
                    let beacon = p.beacon.clone();
                    let friendly_name = p.friendly_name.clone();
                    drop(pt);

                    // Persist to DB
                    {
                        let db = state.database.lock().await;
                        let _ = db.upsert_peer(&id, &friendly_name, "approved");
                    }

                    match crate::send_inner_message(&state.identity, &beacon, approval, &state.msg_tx).await {
                        Ok(_) => format!("Approved peer: {}", id),
                        Err(e) => format!("Approved locally but send failed: {}", e),
                    }
                } else {
                    format!("Peer not found: {}", id)
                }
            }
        }
        "send" => {
            if parts.len() < 3 {
                "Usage: send <tan_id> <message...>".to_string()
            } else {
                let id = parts[1];
                let msg = parts[2..].join(" ");
                let pt = state.peer_table.lock().await;
                if let Some(p) = pt.get(id) {
                    if p.status != PeerStatus::Approved {
                        "Peer not approved yet.".to_string()
                    } else {
                        let beacon = p.beacon.clone();
                        drop(pt);

                        let inner = InnerMessage::Text(msg.clone());
                        match crate::send_inner_message(&state.identity, &beacon, inner, &state.msg_tx).await {
                            Ok(_) => {
                                let db = state.database.lock().await;
                                let _ = db.save_message(id, &msg, "sent");
                                format!("Message sent to {}", id)
                            }
                            Err(e) => format!("Failed to send: {}", e),
                        }
                    }
                } else {
                    format!("Peer not found: {}", id)
                }
            }
        }
        _ => format!("Unknown command: {}", parts[0]),
    };

    Json(ConsoleResponse { output })
}

// ─── Server ──────────────────────────────────────────────────────────────

pub async fn start_web_server(state: AppState, mut port: u16, open_browser: bool) {
    let app = create_router(state);
    
    // Robust port binding: try up to 10 ports if AddressInUse
    let mut listener = None;
    for _ in 0..10 {
        let addr = format!("0.0.0.0:{}", port);
        match tokio::net::TcpListener::bind(&addr).await {
            Ok(l) => {
                listener = Some(l);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                tracing::warn!("Port {} is already in use, trying next...", port);
                port += 1;
            }
            Err(e) => {
                tracing::error!("Failed to bind to {}: {}", addr, e);
                return;
            }
        }
    }

    let listener = listener.expect("Could not find an available port to bind");
    info!("🖥️  TanOS Dashboard → http://localhost:{}", port);
    
    if open_browser {
        let url = format!("http://127.0.0.1:{}", port);
        if let Err(e) = open::that(&url) {
            tracing::warn!("Failed to open browser automatically: {}", e);
        }
    }
    
    axum::serve(listener, app).await.expect("Web server crashed");
}
