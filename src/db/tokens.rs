use rusqlite::{Connection, OptionalExtension, params};

use crate::util::now_rfc3339;

pub fn insert_token(
    conn: &Connection,
    token: &str,
    client_id: &str,
    me: &str,
    scope: &str,
    expires_at: Option<&str>,
) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO access_tokens (token, client_id, me, scope, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![token, client_id, me, scope, now_rfc3339(), expires_at],
    )?;
    Ok(())
}

pub struct ActiveToken {
    pub client_id: String,
    pub me: String,
    pub scope: String,
    pub created_at: String,
    pub expires_at: Option<String>,
}

/// Returns `None` for anything invalid, expired, or revoked -- the caller
/// (the introspection endpoint) must render all of those identically as
/// `{"active": false}` with no other fields, per spec, to avoid leaking
/// which condition applied.
pub fn active_token(conn: &Connection, token: &str) -> rusqlite::Result<Option<ActiveToken>> {
    let row = conn
        .query_row(
            "SELECT client_id, me, scope, created_at, expires_at, revoked_at
             FROM access_tokens WHERE token = ?1",
            params![token],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            },
        )
        .optional()?;

    let Some((client_id, me, scope, created_at, expires_at, revoked_at)) = row else {
        return Ok(None);
    };
    if revoked_at.is_some() {
        return Ok(None);
    }
    if let Some(exp) = &expires_at
        && crate::util::is_past(exp)
    {
        return Ok(None);
    }

    Ok(Some(ActiveToken {
        client_id,
        me,
        scope,
        created_at,
        expires_at,
    }))
}

/// Always succeeds whether or not the token existed -- the revocation
/// endpoint must return 200 unconditionally, per spec, to avoid a
/// token-enumeration oracle.
pub fn revoke_token(conn: &Connection, token: &str) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE access_tokens SET revoked_at = ?2 WHERE token = ?1 AND revoked_at IS NULL",
        params![token, now_rfc3339()],
    )?;
    Ok(())
}
