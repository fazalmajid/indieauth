use http::HeaderMap;
use serde::{Deserialize, Serialize};
use time::Duration;
use webauthn_rs::prelude::{PasskeyAuthentication, PasskeyRegistration};

use crate::db::Db;
use crate::idgen::random_token;
use crate::util::rfc3339_after;

/// `__Host-` prefixed cookies are rejected by browsers unless `Secure`,
/// `Path=/`, and no `Domain` attribute are set -- cheap extra hardening
/// against cookie injection from a sibling subdomain, at no cost here
/// since neither cookie needs to be shared across subdomains.
pub const OWNER_COOKIE: &str = "__Host-owner";
pub const CEREMONY_COOKIE: &str = "__Host-ceremony";

const OWNER_TTL_DAYS: i64 = 30;
const CEREMONY_TTL_MINUTES: i64 = 5;

/// Parameters from an in-progress `/auth/authorize` request, held server
/// side between the GET (render consent) and POST (approve/deny) steps so
/// the POST handler never has to trust client-supplied hidden form fields
/// for anything security-relevant.
#[derive(Serialize, Deserialize, Clone)]
pub struct PendingAuthorize {
    pub client_id: String,
    pub redirect_uri: String,
    pub state: Option<String>,
    pub scope: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub me: String,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum SessionData {
    /// An authenticated owner. `pending_authorize` holds the most recent
    /// in-flight authorization request, if any.
    Owner {
        pending_authorize: Option<PendingAuthorize>,
    },
    CeremonyRegistration {
        state: PasskeyRegistration,
    },
    CeremonyAuthentication {
        state: PasskeyAuthentication,
        return_to: Option<String>,
    },
}

impl SessionData {
    fn cookie_name(&self) -> &'static str {
        match self {
            SessionData::Owner { .. } => OWNER_COOKIE,
            SessionData::CeremonyRegistration { .. } | SessionData::CeremonyAuthentication { .. } => {
                CEREMONY_COOKIE
            }
        }
    }

    fn kind_str(&self) -> &'static str {
        match self {
            SessionData::Owner { .. } => "owner",
            SessionData::CeremonyRegistration { .. } | SessionData::CeremonyAuthentication { .. } => {
                "ceremony"
            }
        }
    }
}

/// Persists a new session row and returns the `Set-Cookie` header value to
/// send back. The cookie carries only the opaque session id -- all real
/// state stays server-side in `data_json`.
pub async fn start_session(db: &Db, data: SessionData) -> String {
    let id = random_token(32);
    let cookie_name = data.cookie_name();
    let kind = data.kind_str();
    let ttl = if kind == "owner" {
        Duration::days(OWNER_TTL_DAYS)
    } else {
        Duration::minutes(CEREMONY_TTL_MINUTES)
    };
    let expires_at = rfc3339_after(ttl);
    let data_json = serde_json::to_string(&data).expect("session data always serializes");

    let id_for_db = id.clone();
    db.call(move |conn| crate::db::upsert_session(conn, &id_for_db, kind, &data_json, &expires_at))
        .await
        .expect("failed to create session");

    set_cookie_header(cookie_name, &id, ttl.whole_seconds())
}

/// Overwrites an existing owner session's data in place (used to attach or
/// clear `pending_authorize` without minting a new cookie).
pub async fn update_owner_session(db: &Db, session_id: &str, data: &SessionData) {
    let expires_at = rfc3339_after(Duration::days(OWNER_TTL_DAYS));
    let data_json = serde_json::to_string(data).expect("session data always serializes");
    let id = session_id.to_string();
    db.call(move |conn| crate::db::upsert_session(conn, &id, "owner", &data_json, &expires_at))
        .await
        .ok();
}

pub async fn load_session(db: &Db, id: &str) -> Option<SessionData> {
    let id = id.to_string();
    let row = db.call(move |conn| crate::db::get_session(conn, &id)).await.ok()??;
    serde_json::from_str(&row.data_json).ok()
}

pub async fn end_session(db: &Db, id: &str) {
    let id = id.to_string();
    let _ = db.call(move |conn| crate::db::delete_session(conn, &id)).await;
}

pub fn get_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    for value in headers.get_all(http::header::COOKIE) {
        let raw = value.to_str().ok()?;
        for part in raw.split(';') {
            let part = part.trim();
            if let Some((k, v)) = part.split_once('=')
                && k == name
            {
                return Some(v.to_string());
            }
        }
    }
    None
}

fn set_cookie_header(name: &str, value: &str, max_age_secs: i64) -> String {
    format!("{name}={value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={max_age_secs}")
}

pub fn clear_cookie_header(name: &str) -> String {
    format!("{name}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0")
}
