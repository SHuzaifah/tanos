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

// ─── Router ──────────────────────────────────────────────────────────────

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(serve_dashboard))
        .route("/api/identity", get(get_identity))
        .route("/api/peers", get(get_peers))
        .route("/api/messages/{peer_id}", get(get_messages))
        .route("/api/conversations", get(get_conversations))
        .route("/api/approve", post(approve_peer))
        .route("/api/send", post(send_message))
        .with_state(state)
}

// ─── Handlers ────────────────────────────────────────────────────────────

async fn serve_dashboard() -> Html<&'static str> {
    Html(include_str!("dashboard.html"))
}

async fn get_identity(State(state): State<AppState>) -> Json<IdentityResponse> {
    Json(IdentityResponse {
        tan_id: state.identity.tan_id.clone(),
        friendly_name: state.identity.friendly_name.clone(),
        public_key: hex::encode(state.identity.public_key_bytes()),
    })
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
            friendly_name: state.identity.friendly_name.clone(),
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

// ─── Server ──────────────────────────────────────────────────────────────

pub async fn start_web_server(state: AppState, port: u16, open_browser: bool) {
    let app = create_router(state);
    let addr = format!("0.0.0.0:{}", port);
    info!("🖥️  TanOS Dashboard → http://localhost:{}", port);
    
    if open_browser {
        let url = format!("http://127.0.0.1:{}", port);
        if let Err(e) = open::that(&url) {
            tracing::warn!("Failed to open browser automatically: {}", e);
        }
    }
    
    let listener = tokio::net::TcpListener::bind(&addr).await.expect("Failed to bind");
    axum::serve(listener, app).await.expect("Web server crashed");
}
