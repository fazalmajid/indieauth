use http::{Request, StatusCode, header};
use hyper::body::Incoming;
use serde::Deserialize;
use subtle::ConstantTimeEq;
use webauthn_rs::prelude::{Passkey, PublicKeyCredential, RegisterPublicKeyCredential};

use crate::body::read_body;
use crate::csrf::is_same_site;
use crate::error::{Resp, bad_request, forbidden, html, redirect, redirect_with_cookie};
use crate::html::{login_page, register_page};
use crate::session::{
    CEREMONY_COOKIE, OWNER_COOKIE, SessionData, clear_cookie_header, end_session, get_cookie, load_session,
    start_session,
};
use crate::state::AppState;

fn append_cookie(mut resp: Resp, set_cookie: &str) -> Resp {
    if let Ok(v) = set_cookie.parse() {
        resp.headers_mut().append(header::SET_COOKIE, v);
    }
    resp
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

fn default_return_to() -> String {
    "/auth/credentials".to_string()
}

#[derive(Deserialize, Default)]
struct RegisterQuery {
    bootstrap: Option<String>,
}

/// The browser only knows what label to use once the user has typed it in
/// (see `static/register.js`), which is after the ceremony has already
/// started -- so unlike the ceremony state itself, the label travels in
/// the finish request's body rather than the ceremony session.
#[derive(Deserialize)]
struct RegisterFinishBody {
    #[serde(flatten)]
    credential: RegisterPublicKeyCredential,
    label: Option<String>,
}

/// `GET /auth/register`. Before any credential exists, this is reachable
/// without a session but requires the one-time bootstrap secret; once at
/// least one credential is registered, it always requires an authenticated
/// owner session, so it can never be re-triggered by an outsider later.
pub async fn register_page_handler(req: Request<Incoming>, state: &AppState) -> Resp {
    let query = req.uri().query().unwrap_or("");
    let q: RegisterQuery = serde_urlencoded::from_str(query).unwrap_or_default();

    let count = state.db.call(crate::db::count_credentials).await.unwrap_or(0);
    if count > 0 {
        let Some(session_id) = get_cookie(req.headers(), OWNER_COOKIE) else {
            return redirect("/auth/login?return_to=%2Fauth%2Fregister");
        };
        if !matches!(
            load_session(&state.db, &session_id).await,
            Some(SessionData::Owner { .. })
        ) {
            return redirect("/auth/login?return_to=%2Fauth%2Fregister");
        }
    } else {
        match (&state.config.bootstrap_secret, &q.bootstrap) {
            (Some(expected), Some(given)) if constant_time_eq(expected, given) => {}
            _ => return forbidden("Bootstrap registration requires a valid one-time secret"),
        }
    }

    let existing = state.db.call(crate::db::list_credentials).await.unwrap_or_default();
    let exclude: Vec<_> = existing
        .iter()
        .map(|c| c.credential_id.clone().into())
        .collect::<Vec<_>>();

    let (ccr, reg_state) = state
        .webauthn
        .webauthn
        .start_passkey_registration(
            state.webauthn.owner_user_id,
            "owner",
            "Owner",
            if exclude.is_empty() { None } else { Some(exclude) },
        )
        .expect("failed to start webauthn registration");

    let set_cookie = start_session(&state.db, SessionData::CeremonyRegistration { state: reg_state }).await;

    let options_json = serde_json::to_string(&ccr.public_key).expect("always serializes");
    append_cookie(html(StatusCode::OK, register_page(&options_json)), &set_cookie)
}

pub async fn register_finish(req: Request<Incoming>, state: &AppState) -> Resp {
    if !is_same_site(req.method(), req.headers(), &state.config.rp_origin) {
        return forbidden("Cross-site request rejected");
    }
    let Some(session_id) = get_cookie(req.headers(), CEREMONY_COOKIE) else {
        return bad_request("No registration in progress");
    };
    let Some(SessionData::CeremonyRegistration { state: reg_state }) = load_session(&state.db, &session_id).await
    else {
        return bad_request("No registration in progress");
    };
    let already_has_owner_session = get_cookie(req.headers(), OWNER_COOKIE).is_some();

    let Some(body) = read_body(req.into_body()).await else {
        return bad_request("Invalid request body");
    };
    let parsed: RegisterFinishBody = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return bad_request("Invalid registration response"),
    };
    let RegisterFinishBody { credential: reg, label } = parsed;

    let passkey = match state.webauthn.webauthn.finish_passkey_registration(&reg, &reg_state) {
        Ok(pk) => pk,
        Err(e) => {
            tracing::warn!(error = %e, "webauthn registration failed");
            return bad_request("Registration failed");
        }
    };

    end_session(&state.db, &session_id).await;

    let credential_id = passkey.cred_id().as_ref().to_vec();
    let passkey_json = serde_json::to_string(&passkey).expect("always serializes");
    let insert_result = state
        .db
        .call(move |conn| crate::db::insert_credential(conn, &credential_id, &passkey_json, label.as_deref()))
        .await;
    if insert_result.is_err() {
        return bad_request("This passkey is already registered");
    }

    // If this was the bootstrap registration (no owner session yet), log
    // the owner in immediately rather than bouncing through a separate
    // sign-in ceremony for the key they just registered.
    if !already_has_owner_session {
        let set_cookie = start_session(
            &state.db,
            SessionData::Owner {
                pending_authorize: None,
            },
        )
        .await;
        return append_cookie(redirect(&default_return_to()), &set_cookie);
    }

    redirect(&default_return_to())
}

#[derive(Deserialize, Default)]
struct LoginQuery {
    return_to: Option<String>,
}

pub async fn login_page_handler(req: Request<Incoming>, state: &AppState) -> Resp {
    let query = req.uri().query().unwrap_or("");
    let q: LoginQuery = serde_urlencoded::from_str(query).unwrap_or_default();

    if let Some(session_id) = get_cookie(req.headers(), OWNER_COOKIE)
        && matches!(
            load_session(&state.db, &session_id).await,
            Some(SessionData::Owner { .. })
        )
    {
        return redirect(q.return_to.as_deref().unwrap_or(&default_return_to()));
    }

    let creds = state.db.call(crate::db::list_credentials).await.unwrap_or_default();
    if creds.is_empty() {
        return bad_request("No passkeys are registered yet.");
    }
    let passkeys: Vec<Passkey> = creds
        .iter()
        .filter_map(|c| serde_json::from_str(&c.passkey_json).ok())
        .collect();

    let (rcr, auth_state) = match state.webauthn.webauthn.start_passkey_authentication(&passkeys) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "failed to start webauthn authentication");
            return bad_request("Could not start sign-in");
        }
    };

    let set_cookie = start_session(
        &state.db,
        SessionData::CeremonyAuthentication {
            state: auth_state,
            return_to: q.return_to,
        },
    )
    .await;

    let options_json = serde_json::to_string(&rcr.public_key).expect("always serializes");
    append_cookie(html(StatusCode::OK, login_page(&options_json)), &set_cookie)
}

pub async fn login_finish(req: Request<Incoming>, state: &AppState) -> Resp {
    if !is_same_site(req.method(), req.headers(), &state.config.rp_origin) {
        return forbidden("Cross-site request rejected");
    }
    let Some(ceremony_id) = get_cookie(req.headers(), CEREMONY_COOKIE) else {
        return bad_request("No sign-in in progress");
    };
    let Some(SessionData::CeremonyAuthentication { state: auth_state, return_to }) =
        load_session(&state.db, &ceremony_id).await
    else {
        return bad_request("No sign-in in progress");
    };

    let Some(body) = read_body(req.into_body()).await else {
        return bad_request("Invalid request body");
    };
    let reg: PublicKeyCredential = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return bad_request("Invalid sign-in response"),
    };

    let result = match state.webauthn.webauthn.finish_passkey_authentication(&reg, &auth_state) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "webauthn authentication failed");
            return forbidden("Sign-in failed");
        }
    };

    end_session(&state.db, &ceremony_id).await;

    // Persist the updated sign counter / backup-state, if any -- most
    // passkeys never need this, but security keys with an activation
    // counter do, and skipping it would weaken replay detection.
    let creds = state.db.call(crate::db::list_credentials).await.unwrap_or_default();
    if let Some(mut passkey) = creds
        .iter()
        .find(|c| c.credential_id.as_slice() == result.cred_id().as_ref())
        .and_then(|c| serde_json::from_str::<Passkey>(&c.passkey_json).ok())
        && passkey.update_credential(&result) == Some(true)
    {
        let credential_id = passkey.cred_id().as_ref().to_vec();
        let passkey_json = serde_json::to_string(&passkey).expect("always serializes");
        let _ = state
            .db
            .call(move |conn| crate::db::update_credential_after_auth(conn, &credential_id, &passkey_json))
            .await;
    }

    let set_cookie = start_session(
        &state.db,
        SessionData::Owner {
            pending_authorize: None,
        },
    )
    .await;

    append_cookie(redirect(return_to.as_deref().unwrap_or(&default_return_to())), &set_cookie)
}

pub async fn logout(req: Request<Incoming>, state: &AppState) -> Resp {
    if !is_same_site(req.method(), req.headers(), &state.config.rp_origin) {
        return forbidden("Cross-site request rejected");
    }
    if let Some(session_id) = get_cookie(req.headers(), OWNER_COOKIE) {
        end_session(&state.db, &session_id).await;
    }
    redirect_with_cookie("/auth/login", &clear_cookie_header(OWNER_COOKIE))
}
