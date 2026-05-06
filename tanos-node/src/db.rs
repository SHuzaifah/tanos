//! Sovereign local storage — SQLite database for messages, peers, and state.
//!
//! All data stays on-device. Nothing leaves unless explicitly sent over the mesh.

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

/// A persistently-stored chat message.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StoredMessage {
    pub id: i64,
    pub peer_id: String,
    pub text: String,
    pub direction: String,   // "sent" | "received"
    pub timestamp: i64,
}

/// A persistently-stored peer record.
#[derive(Debug, Clone, serde::Serialize)]
pub struct StoredPeer {
    pub tan_id: String,
    pub friendly_name: String,
    pub status: String,        // "pending_us" | "pending_them" | "approved"
    pub first_seen: i64,
}

/// Thread-safe handle to the sovereign database.
pub type Db = Arc<Mutex<SovereignDb>>;

pub struct SovereignDb {
    conn: Connection,
}

impl SovereignDb {
    /// Open (or create) the database at the node's data directory.
    pub fn open(data_dir: &PathBuf) -> Result<Self> {
        std::fs::create_dir_all(data_dir)
            .context("Failed to create data directory")?;

        let db_path = data_dir.join("tanos.db");
        let conn = Connection::open(&db_path)
            .context(format!("Failed to open database at {:?}", db_path))?;

        // Enable WAL mode for better concurrent reads
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS messages (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_id     TEXT NOT NULL,
                text        TEXT NOT NULL,
                direction   TEXT NOT NULL CHECK(direction IN ('sent', 'received')),
                timestamp   INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS peers (
                tan_id          TEXT PRIMARY KEY,
                friendly_name   TEXT NOT NULL DEFAULT '',
                status          TEXT NOT NULL DEFAULT 'pending_them',
                first_seen      INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_messages_peer ON messages(peer_id);
            CREATE INDEX IF NOT EXISTS idx_messages_time ON messages(timestamp);
            "
        )?;

        Ok(Self { conn })
    }

    // ─── Messages ────────────────────────────────────────────────────────

    /// Store a message (sent or received).
    pub fn save_message(&self, peer_id: &str, text: &str, direction: &str) -> Result<i64> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        self.conn.execute(
            "INSERT INTO messages (peer_id, text, direction, timestamp) VALUES (?1, ?2, ?3, ?4)",
            params![peer_id, text, direction, now],
        )?;

        Ok(self.conn.last_insert_rowid())
    }

    /// Get all messages with a specific peer, ordered by time.
    pub fn get_messages_with_peer(&self, peer_id: &str) -> Result<Vec<StoredMessage>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, peer_id, text, direction, timestamp FROM messages WHERE peer_id = ?1 ORDER BY timestamp ASC"
        )?;

        let rows = stmt.query_map(params![peer_id], |row| {
            Ok(StoredMessage {
                id: row.get(0)?,
                peer_id: row.get(1)?,
                text: row.get(2)?,
                direction: row.get(3)?,
                timestamp: row.get(4)?,
            })
        })?;

        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    /// Get all messages after a given ID (for incremental polling).
    #[allow(dead_code)]
    pub fn get_messages_since(&self, since_id: i64) -> Result<Vec<StoredMessage>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, peer_id, text, direction, timestamp FROM messages WHERE id > ?1 ORDER BY timestamp ASC"
        )?;

        let rows = stmt.query_map(params![since_id], |row| {
            Ok(StoredMessage {
                id: row.get(0)?,
                peer_id: row.get(1)?,
                text: row.get(2)?,
                direction: row.get(3)?,
                timestamp: row.get(4)?,
            })
        })?;

        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    /// Get the list of peers the user has chatted with, plus latest message preview.
    pub fn get_conversations(&self) -> Result<Vec<ConversationPreview>> {
        let mut stmt = self.conn.prepare(
            "SELECT m.peer_id, m.text, m.direction, m.timestamp,
                    (SELECT COUNT(*) FROM messages m2 WHERE m2.peer_id = m.peer_id) as msg_count
             FROM messages m
             WHERE m.id IN (
                SELECT MAX(id) FROM messages GROUP BY peer_id
             )
             ORDER BY m.timestamp DESC"
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(ConversationPreview {
                peer_id: row.get(0)?,
                last_message: row.get(1)?,
                last_direction: row.get(2)?,
                last_timestamp: row.get(3)?,
                message_count: row.get(4)?,
            })
        })?;

        Ok(rows.filter_map(|r| r.ok()).collect())
    }

    // ─── Peers ───────────────────────────────────────────────────────────

    /// Upsert a peer (insert or update status/name).
    pub fn upsert_peer(&self, tan_id: &str, friendly_name: &str, status: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO peers (tan_id, friendly_name, status, first_seen)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(tan_id) DO UPDATE SET
                friendly_name = CASE WHEN excluded.friendly_name != '' THEN excluded.friendly_name ELSE peers.friendly_name END,
                status = excluded.status",
            params![
                tan_id,
                friendly_name,
                status,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64,
            ],
        )?;
        Ok(())
    }

    /// Update just the status of a peer.
    #[allow(dead_code)]
    pub fn update_peer_status(&self, tan_id: &str, status: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE peers SET status = ?1 WHERE tan_id = ?2",
            params![status, tan_id],
        )?;
        Ok(())
    }

    /// Get a single peer by TanID.
    pub fn get_peer(&self, tan_id: &str) -> Result<Option<StoredPeer>> {
        let mut stmt = self.conn.prepare(
            "SELECT tan_id, friendly_name, status, first_seen FROM peers WHERE tan_id = ?1"
        )?;
        let mut rows = stmt.query_map(params![tan_id], |row| {
            Ok(StoredPeer {
                tan_id: row.get(0)?,
                friendly_name: row.get(1)?,
                status: row.get(2)?,
                first_seen: row.get(3)?,
            })
        })?;
        Ok(rows.next().and_then(|r| r.ok()))
    }

    /// Get all stored peers.
    #[allow(dead_code)]
    pub fn get_all_peers(&self) -> Result<Vec<StoredPeer>> {
        let mut stmt = self.conn.prepare(
            "SELECT tan_id, friendly_name, status, first_seen FROM peers ORDER BY first_seen DESC"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(StoredPeer {
                tan_id: row.get(0)?,
                friendly_name: row.get(1)?,
                status: row.get(2)?,
                first_seen: row.get(3)?,
            })
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }
}

/// Preview of a conversation for the sidebar.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConversationPreview {
    pub peer_id: String,
    pub last_message: String,
    pub last_direction: String,
    pub last_timestamp: i64,
    pub message_count: i64,
}

/// Create a new database handle.
pub fn open_db(data_dir: &PathBuf) -> Result<Db> {
    let db = SovereignDb::open(data_dir)?;
    Ok(Arc::new(Mutex::new(db)))
}
