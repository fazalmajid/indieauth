//! Response-building helpers. Routing is a hand-written match, not a
//! framework, so there's no `IntoResponse` trait to hook into -- handlers
//! just call these directly and return the `Resp` they produce.

use bytes::Bytes;
use http::{Response, StatusCode, header};
use http_body_util::Full;

pub type Body = Full<Bytes>;
pub type Resp = Response<Body>;

pub fn html(status: StatusCode, body: String) -> Resp {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(Full::new(Bytes::from(body)))
        .expect("valid response")
}

/// Serves a compiled-in static asset. Sites that set
/// `X-Content-Type-Options: nosniff` mean the browser refuses to execute
/// the script at all if this Content-Type isn't a recognized JavaScript
/// MIME type -- `text/javascript` is the current standard one.
pub fn javascript(body: &'static str) -> Resp {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/javascript; charset=utf-8")
        .header(header::CACHE_CONTROL, "public, max-age=3600")
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .expect("valid response")
}

pub fn json(status: StatusCode, value: serde_json::Value) -> Resp {
    let body = serde_json::to_vec(&value).expect("value always serializes");
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Full::new(Bytes::from(body)))
        .expect("valid response")
}

/// Same as `redirect`, but navigates via a same-origin HTML/JS page instead
/// of an HTTP 3xx -- use this for responses to the consent form's POST
/// specifically, since `form-action` CSP blocks a direct cross-origin
/// redirect there (see `html::redirect_page`).
pub fn redirect_via_js(location: &str) -> Resp {
    html(StatusCode::OK, crate::html::redirect_page(location))
}

/// Redirects to an arbitrary caller-supplied `location`. Callers must only
/// pass a `redirect_uri` that has already been validated against the
/// client_id document -- this function does not itself guard against
/// open-redirect, by design (some error paths must render an error page
/// instead of redirecting at all; see `client_metadata`).
pub fn redirect(location: &str) -> Resp {
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, location)
        .body(Full::new(Bytes::new()))
        .expect("valid response")
}

pub fn redirect_with_cookie(location: &str, set_cookie: &str) -> Resp {
    Response::builder()
        .status(StatusCode::FOUND)
        .header(header::LOCATION, location)
        .header(header::SET_COOKIE, set_cookie)
        .body(Full::new(Bytes::new()))
        .expect("valid response")
}

pub fn not_found() -> Resp {
    html(StatusCode::NOT_FOUND, crate::html::error_page("Not found"))
}

pub fn bad_request(msg: &str) -> Resp {
    html(StatusCode::BAD_REQUEST, crate::html::error_page(msg))
}

pub fn forbidden(msg: &str) -> Resp {
    html(StatusCode::FORBIDDEN, crate::html::error_page(msg))
}

pub fn json_error(status: StatusCode, error: &str) -> Resp {
    json(status, serde_json::json!({ "error": error }))
}
