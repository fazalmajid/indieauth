use http::{Request, StatusCode};
use hyper::body::Incoming;
use serde::Deserialize;
use time::Duration;

use crate::body::read_body;
use crate::error::{Resp, json, json_error};
use crate::idgen::random_token;
use crate::pkce::verify_s256;
use crate::state::AppState;
use crate::util::rfc3339_after;

#[derive(Deserialize)]
struct TokenRequest {
    grant_type: String,
    code: String,
    client_id: String,
    redirect_uri: String,
    code_verifier: String,
}

const ACCESS_TOKEN_TTL_HOURS: i64 = 1;

pub async fn post(req: Request<Incoming>, state: &AppState) -> Resp {
    let Some(body) = read_body(req.into_body()).await else {
        return json_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let form: TokenRequest = match serde_urlencoded::from_bytes(&body) {
        Ok(f) => f,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    if form.grant_type != "authorization_code" {
        return json_error(StatusCode::BAD_REQUEST, "unsupported_grant_type");
    }

    let code = form.code.clone();
    let redeemed = state.db.call(move |conn| crate::db::redeem_code(conn, &code)).await;
    let Some(redeemed) = redeemed.ok().flatten() else {
        return json_error(StatusCode::BAD_REQUEST, "invalid_grant");
    };

    if redeemed.client_id != form.client_id || redeemed.redirect_uri != form.redirect_uri {
        return json_error(StatusCode::BAD_REQUEST, "invalid_grant");
    }
    if redeemed.code_challenge_method != "S256"
        || !verify_s256(&form.code_verifier, &redeemed.code_challenge)
    {
        return json_error(StatusCode::BAD_REQUEST, "invalid_grant");
    }

    // Per spec: an empty scope means this was a profile-only ("just log
    // me in") request -- no access token may be issued for it.
    if redeemed.scope.trim().is_empty() {
        return json(StatusCode::OK, serde_json::json!({ "me": redeemed.me }));
    }

    let token = random_token(32);
    let expires_at = rfc3339_after(Duration::hours(ACCESS_TOKEN_TTL_HOURS));
    let token_for_db = token.clone();
    let client_id = redeemed.client_id.clone();
    let me = redeemed.me.clone();
    let scope = redeemed.scope.clone();
    let expires_at_for_db = expires_at.clone();
    state
        .db
        .call(move |conn| {
            crate::db::insert_token(conn, &token_for_db, &client_id, &me, &scope, Some(&expires_at_for_db))
        })
        .await
        .expect("failed to store access token");

    json(
        StatusCode::OK,
        serde_json::json!({
            "access_token": token,
            "token_type": "Bearer",
            "scope": redeemed.scope,
            "me": redeemed.me,
            "expires_in": ACCESS_TOKEN_TTL_HOURS * 3600,
        }),
    )
}
