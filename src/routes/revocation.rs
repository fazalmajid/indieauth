use http::{Request, StatusCode};
use hyper::body::Incoming;
use serde::Deserialize;

use crate::body::read_body;
use crate::error::{Resp, json};
use crate::state::AppState;

#[derive(Deserialize)]
struct RevokeRequest {
    token: String,
}

/// Always returns 200, whether or not the token existed -- per spec, to
/// avoid a token-enumeration oracle. No auth is required to revoke a
/// token: giving up a token you hold is not itself a sensitive operation.
pub async fn post(req: Request<Incoming>, state: &AppState) -> Resp {
    if let Some(body) = read_body(req.into_body()).await
        && let Ok(form) = serde_urlencoded::from_bytes::<RevokeRequest>(&body)
    {
        let _ = state.db.call(move |conn| crate::db::revoke_token(conn, &form.token)).await;
    }
    json(StatusCode::OK, serde_json::json!({}))
}
