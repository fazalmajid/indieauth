use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::Request;
use hyper::body::Incoming;
use serde::Deserialize;

use crate::body::read_body;
use crate::csrf::is_same_site;
use crate::error::{Resp, bad_request, forbidden, html, redirect};
use crate::html::{CredentialSummary, credentials_page};
use crate::session::{OWNER_COOKIE, SessionData, get_cookie, load_session};
use crate::state::AppState;

async fn require_owner(req: &Request<Incoming>, state: &AppState) -> bool {
    let Some(session_id) = get_cookie(req.headers(), OWNER_COOKIE) else {
        return false;
    };
    matches!(
        load_session(&state.db, &session_id).await,
        Some(SessionData::Owner { .. })
    )
}

pub async fn page(req: Request<Incoming>, state: &AppState) -> Resp {
    if !require_owner(&req, state).await {
        return redirect("/auth/login?return_to=%2Fauth%2Fcredentials");
    }
    let creds = state.db.call(crate::db::list_credentials).await.unwrap_or_default();
    let encoded_ids: Vec<String> = creds.iter().map(|c| URL_SAFE_NO_PAD.encode(&c.credential_id)).collect();
    let summaries: Vec<CredentialSummary> = creds
        .iter()
        .zip(&encoded_ids)
        .map(|(c, id)| CredentialSummary {
            id_b64: id,
            label: c.label.as_deref(),
            created_at: &c.created_at,
            last_used_at: c.last_used_at.as_deref(),
        })
        .collect();
    html(http::StatusCode::OK, credentials_page(&summaries))
}

#[derive(Deserialize)]
struct DeleteForm {
    credential_id: String,
}

pub async fn delete(req: Request<Incoming>, state: &AppState) -> Resp {
    if !is_same_site(req.method(), req.headers(), &state.config.rp_origin) {
        return forbidden("Cross-site request rejected");
    }
    if !require_owner(&req, state).await {
        return forbidden("Not signed in");
    }

    let Some(body) = read_body(req.into_body()).await else {
        return bad_request("Invalid request");
    };
    let form: DeleteForm = match serde_urlencoded::from_bytes(&body) {
        Ok(f) => f,
        Err(_) => return bad_request("Invalid request"),
    };
    let Ok(credential_id) = URL_SAFE_NO_PAD.decode(&form.credential_id) else {
        return bad_request("Invalid credential id");
    };

    let count = state.db.call(crate::db::count_credentials).await.unwrap_or(0);
    if count <= 1 {
        return bad_request("Can't remove your last passkey -- register a replacement first");
    }
    let _ = state
        .db
        .call(move |conn| crate::db::delete_credential(conn, &credential_id))
        .await;
    redirect("/auth/credentials")
}

#[derive(Deserialize)]
struct RenameForm {
    credential_id: String,
    label: String,
}

pub async fn rename(req: Request<Incoming>, state: &AppState) -> Resp {
    if !is_same_site(req.method(), req.headers(), &state.config.rp_origin) {
        return forbidden("Cross-site request rejected");
    }
    if !require_owner(&req, state).await {
        return forbidden("Not signed in");
    }

    let Some(body) = read_body(req.into_body()).await else {
        return bad_request("Invalid request");
    };
    let form: RenameForm = match serde_urlencoded::from_bytes(&body) {
        Ok(f) => f,
        Err(_) => return bad_request("Invalid request"),
    };
    let Ok(credential_id) = URL_SAFE_NO_PAD.decode(&form.credential_id) else {
        return bad_request("Invalid credential id");
    };
    let label = form.label.trim().to_string();
    let label = if label.is_empty() { None } else { Some(label) };

    let _ = state
        .db
        .call(move |conn| crate::db::rename_credential(conn, &credential_id, label.as_deref()))
        .await;
    redirect("/auth/credentials")
}
