use rusqlite::{Connection, OptionalExtension, params};
use tracing::warn;

use crate::util::now_rfc3339;

pub struct NewCode<'a> {
    pub code: &'a str,
    pub client_id: &'a str,
    pub redirect_uri: &'a str,
    pub me: &'a str,
    pub scope: &'a str,
    pub code_challenge: &'a str,
    pub code_challenge_method: &'a str,
    pub state: Option<&'a str>,
    pub expires_at: &'a str,
}

pub fn insert_code(conn: &Connection, c: NewCode) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO authorization_codes
            (code, client_id, redirect_uri, me, scope, code_challenge,
             code_challenge_method, state, created_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            c.code,
            c.client_id,
            c.redirect_uri,
            c.me,
            c.scope,
            c.code_challenge,
            c.code_challenge_method,
            c.state,
            now_rfc3339(),
            c.expires_at,
        ],
    )?;
    Ok(())
}

pub struct RedeemedCode {
    pub client_id: String,
    pub redirect_uri: String,
    pub me: String,
    pub scope: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
}

/// Claims a code for single use. Because all DB access runs on the one
/// SQLite writer thread (see `db::Db`), the read-then-update below can't
/// race with another redemption of the same code -- no separate SQL-level
/// atomicity trick is needed beyond the `used_at IS NULL` guard, which
/// exists to make double-redemption within this same call impossible if a
/// caller reuses a code from two concurrently-awaited requests.
pub fn redeem_code(conn: &Connection, code: &str) -> rusqlite::Result<Option<RedeemedCode>> {
    let row = conn
        .query_row(
            "SELECT client_id, redirect_uri, me, scope, code_challenge,
                    code_challenge_method, expires_at, used_at
             FROM authorization_codes WHERE code = ?1",
            params![code],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                ))
            },
        )
        .optional()?;

    let Some((client_id, redirect_uri, me, scope, code_challenge, code_challenge_method, expires_at, used_at)) =
        row
    else {
        return Ok(None);
    };

    if used_at.is_some() {
        warn!("authorization code presented for redemption a second time");
        return Ok(None);
    }
    if crate::util::is_past(&expires_at) {
        return Ok(None);
    }

    let updated = conn.execute(
        "UPDATE authorization_codes SET used_at = ?2 WHERE code = ?1 AND used_at IS NULL",
        params![code, now_rfc3339()],
    )?;
    if updated != 1 {
        // Lost a race within this same synchronous call somehow -- treat
        // as already-used rather than trusting the values we just read.
        return Ok(None);
    }

    Ok(Some(RedeemedCode {
        client_id,
        redirect_uri,
        me,
        scope,
        code_challenge,
        code_challenge_method,
    }))
}
