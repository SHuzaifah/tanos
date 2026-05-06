use axum::{
    extract::State,
    response::Html,
    routing::{get, post},
    Form, Router,
};
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::oneshot;
use tracing::info;
use anyhow::Result;
use tanos_core::identity::{self, NodeIdentity};
use std::future::IntoFuture;

#[derive(Deserialize)]
struct SetupForm {
    username: String,
}

pub async fn run_setup_gui() -> Result<Arc<NodeIdentity>> {
    let port: u16 = std::env::var("TANOS_PORT")
        .unwrap_or_else(|_| "7700".to_string())
        .parse()
        .unwrap_or(7700);

    let (tx, rx) = oneshot::channel();
    let tx = Arc::new(tokio::sync::Mutex::new(Some(tx)));

    // Pre-generate identity so we can show the ID
    let identity = NodeIdentity::generate(None);
    
    // We pass the pre-generated identity and the oneshot sender to the axum state
    let state = SetupState {
        tx,
        identity: Arc::new(tokio::sync::Mutex::new(Some(identity))),
    };

    let app = Router::new()
        .route("/", get(serve_setup))
        .route("/setup", post(handle_setup))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    
    info!("🚀 Opening setup GUI in browser at http://localhost:{}", port);
    
    let url = format!("http://127.0.0.1:{}", port);
    if let Err(e) = open::that(&url) {
        tracing::warn!("Failed to open browser automatically: {}", e);
    }

    let mut server = Box::pin(axum::serve(listener, app).into_future());
    let identity = tokio::select! {
        res = rx => res.unwrap(),
        _ = &mut server => {
            anyhow::bail!("Setup server stopped unexpectedly");
        }
    };
    
    Ok(Arc::new(identity))
}

#[derive(Clone)]
struct SetupState {
    tx: Arc<tokio::sync::Mutex<Option<oneshot::Sender<NodeIdentity>>>>,
    identity: Arc<tokio::sync::Mutex<Option<NodeIdentity>>>,
}

async fn serve_setup(State(state): State<SetupState>) -> Html<String> {
    let id_lock = state.identity.lock().await;
    let tan_id = id_lock.as_ref().map(|id| id.tan_id.clone()).unwrap_or_default();
    
    let html = format!(r#"
    <!DOCTYPE html>
    <html>
    <head>
        <title>TanOS Setup</title>
        <style>
            body {{ font-family: -apple-system, sans-serif; background: #000; color: #fff; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
            .card {{ background: #111; padding: 30px; border-radius: 12px; border: 1px solid #333; width: 300px; text-align: center; }}
            h1 {{ font-size: 24px; margin-top: 0; }}
            input {{ width: 100%; box-sizing: border-box; padding: 10px; margin: 10px 0 20px; border-radius: 6px; border: 1px solid #444; background: #222; color: #fff; outline: none; }}
            input:focus {{ border-color: #888; }}
            button {{ width: 100%; padding: 12px; border-radius: 6px; border: none; background: #fff; color: #000; font-weight: bold; cursor: pointer; }}
            button:hover {{ opacity: 0.9; }}
            .tan-id {{ font-family: monospace; color: #888; font-size: 14px; margin-bottom: 20px; display: block; letter-spacing: 1px; }}
        </style>
    </head>
    <body>
        <div class="card">
            <h1>Welcome to TanOS</h1>
            <p style="color: #888; font-size: 13px;">Your auto-generated Tan ID:</p>
            <span class="tan-id">{}</span>
            <form action="/setup" method="POST">
                <label style="text-align: left; display: block; font-size: 13px; color: #aaa;">Choose a Username</label>
                <input type="text" name="username" placeholder="e.g. Alice" required autofocus autocomplete="off">
                <button type="submit">Start Node</button>
            </form>
        </div>
    </body>
    </html>
    "#, tan_id);
    
    Html(html)
}

async fn handle_setup(
    State(state): State<SetupState>,
    Form(form): Form<SetupForm>,
) -> Html<&'static str> {
    let mut id_opt = state.identity.lock().await;
    if let Some(mut identity) = id_opt.take() {
        identity.friendly_name = form.username;
        // save it
        if let Err(e) = identity::save_identity(&identity) {
            tracing::error!("Failed to save identity: {}", e);
        }
        
        let mut tx_opt = state.tx.lock().await;
        if let Some(tx) = tx_opt.take() {
            let _ = tx.send(identity);
        }
    }
    
    Html(r#"
    <!DOCTYPE html>
    <html>
    <head>
        <meta http-equiv="refresh" content="1;url=/" />
        <style>body { background: #000; color: #fff; font-family: sans-serif; text-align: center; padding-top: 100px; }</style>
    </head>
    <body>
        <h2>Profile created! Starting node...</h2>
        <script>setTimeout(() => window.location.href='/', 1000);</script>
    </body>
    </html>
    "#)
}
