use bytes::Bytes;
use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;

/// Generous enough for a consent-approval form post or a WebAuthn ceremony
/// JSON blob, small enough to bound memory from a hostile client.
pub const MAX_REQUEST_BODY: usize = 64 * 1024;

pub async fn read_body(body: Incoming) -> Option<Bytes> {
    Limited::new(body, MAX_REQUEST_BODY)
        .collect()
        .await
        .ok()
        .map(|c| c.to_bytes())
}
