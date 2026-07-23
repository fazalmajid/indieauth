use rusqlite::{Connection, OptionalExtension, params};

use crate::util::now_rfc3339;

pub struct SessionRow {
    pub data_json: String,
}

/// Creates a session row, or overwrites it in place if `id` already exists
/// (used to update an owner session's `pending_authorize` without minting a
/// new cookie).
pub fn upsert_session(
    conn: &Connection,
    id: &str,
    kind: &str,
    data_json: &str,
    expires_at: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO sessions (id, kind, data_json, expires_at) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(id) DO UPDATE SET kind = excluded.kind, data_json = excluded.data_json,
                                        expires_at = excluded.expires_at",
        params![id, kind, data_json, expires_at],
    )?;
    Ok(())
}

/// Looks up a session by id, but only if it hasn't expired -- an expired
/// row is treated identically to a missing one everywhere in this codebase.
pub fn get_session(conn: &Connection, id: &str) -> rusqlite::Result<Option<SessionRow>> {
    conn.query_row(
        "SELECT data_json FROM sessions WHERE id = ?1 AND expires_at > ?2",
        params![id, now_rfc3339()],
        |row| Ok(SessionRow { data_json: row.get(0)? }),
    )
    .optional()
}

pub fn delete_session(conn: &Connection, id: &str) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM sessions WHERE id = ?1", params![id])?;
    Ok(())
}

/// Periodic sweep of stale rows (ceremony state and expired owner
/// sessions) -- called from a background interval task, not per-request.
pub fn cleanup_expired_sessions(conn: &Connection) -> rusqlite::Result<usize> {
    conn.execute(
        "DELETE FROM sessions WHERE expires_at <= ?1",
        params![now_rfc3339()],
    )
}
