use http::{Request, StatusCode};
use hyper::body::Incoming;
use serde::Deserialize;

use crate::body::read_body;
use crate::client_metadata::{fetch_client_metadata, is_loopback_client_id, parse_profile_url, validate_redirect_uri};
use crate::csrf::is_same_site;
use crate::error::{Resp, bad_request, redirect, redirect_via_js};
use crate::html::{ConsentClient, consent_page};
use crate::idgen::random_token;
use crate::session::{PendingAuthorize, SessionData, get_cookie, load_session, update_owner_session};
use crate::state::AppState;
use crate::util::rfc3339_after;

#[derive(Deserialize)]
struct AuthorizeQuery {
    response_type: Option<String>,
    client_id: String,
    redirect_uri: String,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    #[serde(default)]
    scope: String,
}

/// Builds the error-redirect target URL. Returned as a `Url`, not a
/// `Resp`, because the two call sites need different navigation
/// mechanisms: the GET handler's early errors are triggered by a plain
/// browser navigation, so a real HTTP redirect is fine, but the POST
/// (deny) handler's response is to a form submission, which the site's
/// `form-action` CSP restricts to same-origin -- see `redirect_via_js`.
fn error_redirect_url(redirect_uri: &url::Url, error: &str, state: Option<&str>) -> url::Url {
    let mut url = redirect_uri.clone();
    {
        let mut qp = url.query_pairs_mut();
        qp.append_pair("error", error);
        if let Some(s) = state {
            qp.append_pair("state", s);
        }
    }
    url
}

pub async fn get(req: Request<Incoming>, state: &AppState) -> Resp {
    let query = req.uri().query().unwrap_or("");
    let parsed: AuthorizeQuery = match serde_urlencoded::from_str(query) {
        Ok(q) => q,
        Err(_) => return bad_request("Invalid authorization request: missing required parameters"),
    };

    let Some(client_id) = parse_profile_url(&parsed.client_id) else {
        return bad_request("Invalid client_id");
    };
    let Some(redirect_uri) = parse_profile_url(&parsed.redirect_uri) else {
        return bad_request("Invalid redirect_uri");
    };

    // Per spec: MUST NOT fetch a loopback client_id; there's then no
    // metadata document, so redirect_uri must match client_id's origin
    // exactly (checked inside validate_redirect_uri's same-origin branch).
    let metadata = if is_loopback_client_id(&client_id) {
        Default::default()
    } else {
        fetch_client_metadata(&state.https_client, &client_id).await
    };

    if !validate_redirect_uri(&client_id, &redirect_uri, &metadata) {
        // Fatal, non-redirecting: redirect_uri itself is unvalidated, so
        // redirecting to it would be an open redirect.
        return bad_request("redirect_uri is not registered for this client_id");
    }

    if parsed.response_type.as_deref() != Some("code") {
        let url = error_redirect_url(&redirect_uri, "unsupported_response_type", parsed.state.as_deref());
        return redirect(url.as_str());
    }
    let (Some(code_challenge), Some(method)) = (&parsed.code_challenge, &parsed.code_challenge_method) else {
        let url = error_redirect_url(&redirect_uri, "invalid_request", parsed.state.as_deref());
        return redirect(url.as_str());
    };
    if method != "S256" {
        let url = error_redirect_url(&redirect_uri, "invalid_request", parsed.state.as_deref());
        return redirect(url.as_str());
    }

    let Some(session_id) = get_cookie(req.headers(), crate::session::OWNER_COOKIE) else {
        return redirect_to_login(req.uri().query());
    };
    let Some(SessionData::Owner { .. }) = load_session(&state.db, &session_id).await else {
        return redirect_to_login(req.uri().query());
    };

    let pending = PendingAuthorize {
        client_id: parsed.client_id.clone(),
        redirect_uri: parsed.redirect_uri.clone(),
        state: parsed.state.clone(),
        scope: parsed.scope.clone(),
        code_challenge: code_challenge.clone(),
        code_challenge_method: method.clone(),
        me: state.config.owner_me.clone(),
    };
    update_owner_session(
        &state.db,
        &session_id,
        &SessionData::Owner {
            pending_authorize: Some(pending),
        },
    )
    .await;

    let scopes: Vec<&str> = parsed.scope.split_whitespace().collect();
    let page = consent_page(&ConsentClient {
        client_id: &parsed.client_id,
        client_name: metadata.client_name.as_deref(),
        redirect_uri: &parsed.redirect_uri,
        scopes: &scopes,
        me: &state.config.owner_me,
    });
    crate::error::html(StatusCode::OK, page)
}

fn redirect_to_login(original_query: Option<&str>) -> Resp {
    let return_to = original_query.unwrap_or("");
    let target = format!(
        "/auth/login?return_to={}",
        urlencode(&format!("/auth/authorize?{return_to}"))
    );
    redirect(&target)
}

fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[derive(Deserialize)]
struct Decision {
    decision: String,
}

pub async fn post(req: Request<Incoming>, state: &AppState) -> Resp {
    if !is_same_site(req.method(), req.headers(), &state.config.rp_origin) {
        return crate::error::forbidden("Cross-site request rejected");
    }

    let Some(session_id) = get_cookie(req.headers(), crate::session::OWNER_COOKIE) else {
        return crate::error::forbidden("Not signed in");
    };
    let Some(SessionData::Owner { pending_authorize: Some(pending) }) = load_session(&state.db, &session_id).await
    else {
        return bad_request("No pending authorization request");
    };

    let Some(body) = read_body(req.into_body()).await else {
        return bad_request("Invalid request body");
    };
    let decision: Decision = match serde_urlencoded::from_bytes(&body) {
        Ok(d) => d,
        Err(_) => return bad_request("Invalid request body"),
    };

    // Clear the pending request regardless of outcome -- it's single-use.
    update_owner_session(
        &state.db,
        &session_id,
        &SessionData::Owner { pending_authorize: None },
    )
    .await;

    let Some(redirect_uri) = parse_profile_url(&pending.redirect_uri) else {
        return bad_request("Invalid redirect_uri");
    };

    if decision.decision != "approve" {
        let url = error_redirect_url(&redirect_uri, "access_denied", pending.state.as_deref());
        return redirect_via_js(url.as_str());
    }

    let code = random_token(32);
    let expires_at = rfc3339_after(time::Duration::minutes(10));
    // `NewCode` borrows &str, but the db worker closure must be 'static, so
    // clone everything in and rebuild the borrowing struct inside it.
    let code_owned = code.clone();
    let client_id = pending.client_id.clone();
    let redirect_uri_s = pending.redirect_uri.clone();
    let me = pending.me.clone();
    let scope = pending.scope.clone();
    let code_challenge = pending.code_challenge.clone();
    let code_challenge_method = pending.code_challenge_method.clone();
    let pending_state = pending.state.clone();
    state
        .db
        .call(move |conn| {
            crate::db::insert_code(
                conn,
                crate::db::NewCode {
                    code: &code_owned,
                    client_id: &client_id,
                    redirect_uri: &redirect_uri_s,
                    me: &me,
                    scope: &scope,
                    code_challenge: &code_challenge,
                    code_challenge_method: &code_challenge_method,
                    state: pending_state.as_deref(),
                    expires_at: &expires_at,
                },
            )
        })
        .await
        .expect("failed to store authorization code");

    let mut url = redirect_uri;
    {
        let mut qp = url.query_pairs_mut();
        qp.append_pair("code", &code);
        if let Some(s) = &pending.state {
            qp.append_pair("state", s);
        }
        qp.append_pair("iss", &state.config.issuer);
    }
    redirect_via_js(url.as_str())
}
