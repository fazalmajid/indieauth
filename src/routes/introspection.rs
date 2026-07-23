use http::{Request, StatusCode};
use hyper::body::Incoming;
use serde::Deserialize;

use crate::body::read_body;
use crate::error::{Resp, json, json_error};
use crate::state::AppState;
use crate::util::parse_rfc3339;

#[derive(Deserialize)]
struct IntrospectRequest {
    token: String,
}

/// Returns `{"active": false}` and nothing else for anything invalid,
/// expired, or revoked -- per spec, the caller must not be able to
/// distinguish which condition applied.
pub async fn post(req: Request<Incoming>, state: &AppState) -> Resp {
    let Some(body) = read_body(req.into_body()).await else {
        return json_error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let form: IntrospectRequest = match serde_urlencoded::from_bytes(&body) {
        Ok(f) => f,
        Err(_) => return json(StatusCode::OK, serde_json::json!({ "active": false })),
    };

    let active = state
        .db
        .call(move |conn| crate::db::active_token(conn, &form.token))
        .await
        .ok()
        .flatten();

    match active {
        Some(t) => {
            let exp = t.expires_at.as_deref().and_then(parse_rfc3339).map(|d| d.unix_timestamp());
            let iat = parse_rfc3339(&t.created_at).map(|d| d.unix_timestamp());
            json(
                StatusCode::OK,
                serde_json::json!({
                    "active": true,
                    "me": t.me,
                    "client_id": t.client_id,
                    "scope": t.scope,
                    "exp": exp,
                    "iat": iat,
                }),
            )
        }
        None => json(StatusCode::OK, serde_json::json!({ "active": false })),
    }
}
