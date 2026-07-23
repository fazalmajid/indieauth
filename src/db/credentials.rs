use rusqlite::{Connection, params};

use crate::util::now_rfc3339;

pub struct CredentialRow {
    pub credential_id: Vec<u8>,
    pub passkey_json: String,
    pub label: Option<String>,
    pub created_at: String,
    pub last_used_at: Option<String>,
}

pub fn count_credentials(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("SELECT COUNT(*) FROM webauthn_credentials", [], |row| {
        row.get(0)
    })
}

pub fn insert_credential(
    conn: &Connection,
    credential_id: &[u8],
    passkey_json: &str,
    label: Option<&str>,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO webauthn_credentials (credential_id, passkey_json, label, created_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![credential_id, passkey_json, label, now_rfc3339()],
    )?;
    Ok(())
}

/// Every registered key is a valid login credential -- this is the list
/// handed to `start_passkey_authentication` so any of the owner's devices
/// (phone, YubiKey, backup key, ...) can complete the ceremony.
pub fn list_credentials(conn: &Connection) -> rusqlite::Result<Vec<CredentialRow>> {
    let mut stmt = conn.prepare(
        "SELECT credential_id, passkey_json, label, created_at, last_used_at
         FROM webauthn_credentials ORDER BY created_at",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(CredentialRow {
            credential_id: row.get(0)?,
            passkey_json: row.get(1)?,
            label: row.get(2)?,
            created_at: row.get(3)?,
            last_used_at: row.get(4)?,
        })
    })?;
    rows.collect()
}

/// Refuses nothing itself -- the caller (the credentials-management route)
/// is responsible for refusing to delete the last remaining credential, to
/// avoid locking the owner out entirely.
pub fn delete_credential(conn: &Connection, credential_id: &[u8]) -> rusqlite::Result<usize> {
    conn.execute(
        "DELETE FROM webauthn_credentials WHERE credential_id = ?1",
        params![credential_id],
    )
}

pub fn rename_credential(conn: &Connection, credential_id: &[u8], label: Option<&str>) -> rusqlite::Result<usize> {
    conn.execute(
        "UPDATE webauthn_credentials SET label = ?2 WHERE credential_id = ?1",
        params![credential_id, label],
    )
}

/// After a successful authentication, webauthn-rs may return an updated
/// sign-count/backup-state for the credential -- persist it, along with
/// bumping last_used_at, so replay-detection on the sign counter stays
/// accurate across logins.
pub fn update_credential_after_auth(
    conn: &Connection,
    credential_id: &[u8],
    passkey_json: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE webauthn_credentials
         SET passkey_json = ?2, last_used_at = ?3
         WHERE credential_id = ?1",
        params![credential_id, passkey_json, now_rfc3339()],
    )?;
    Ok(())
}
