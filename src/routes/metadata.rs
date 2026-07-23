use http::StatusCode;

use crate::error::{Resp, json};
use crate::state::AppState;

pub fn get(state: &AppState) -> Resp {
    let issuer = &state.config.issuer;
    json(
        StatusCode::OK,
        serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/auth/authorize"),
            "token_endpoint": format!("{issuer}/auth/token"),
            "introspection_endpoint": format!("{issuer}/auth/introspection"),
            "revocation_endpoint": format!("{issuer}/auth/revocation"),
            "code_challenge_methods_supported": ["S256"],
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "scopes_supported": ["profile", "email", "create", "update", "delete", "media"],
            "authorization_response_iss_parameter_supported": true,
        }),
    )
}
