//! Fetching and validating the `client_id` per the IndieAuth spec: the
//! current spec's preferred mechanism is a JSON "OAuth Client ID Metadata
//! Document" at the client_id URL itself. Legacy HTML/h-app parsing is
//! deliberately not implemented (see the plan's "Open flags" note) --
//! clients that only support that older mechanism won't validate here.

use std::net::IpAddr;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde::Deserialize;
use url::Url;

pub type HttpsClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

pub fn build_https_client() -> HttpsClient {
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_only()
        .enable_http1()
        .build();
    Client::builder(TokioExecutor::new()).build(connector)
}

/// Validates the shape of a `client_id` (or `redirect_uri`/`me`) per the
/// spec's URL profile: http(s) only, no userinfo, no fragment, no
/// dot-segments in the path.
pub fn parse_profile_url(raw: &str) -> Option<Url> {
    let url = Url::parse(raw).ok()?;
    if url.scheme() != "http" && url.scheme() != "https" {
        return None;
    }
    if !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    if url.fragment().is_some() {
        return None;
    }
    url.host_str()?;
    if let Some(segments) = url.path_segments()
        && segments.clone().any(|s| s == "." || s == "..")
    {
        return None;
    }
    Some(url)
}

/// Per spec: `client_id` values pointing at the loopback addresses
/// `127.0.0.1`/`[::1]` are permitted (for local client development), but
/// the authorization endpoint "MUST NOT" fetch them. In that case there is
/// no metadata document to consult, so `redirect_uri` must match
/// `client_id`'s origin exactly.
pub fn is_loopback_client_id(url: &Url) -> bool {
    matches!(url.host_str(), Some("127.0.0.1") | Some("[::1]") | Some("::1"))
}

fn is_disallowed_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_documentation()
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local(),
    }
}

#[derive(Deserialize, Default)]
struct ClientIdDocument {
    client_id: Option<String>,
    client_name: Option<String>,
    #[serde(default)]
    redirect_uris: Vec<String>,
}

#[derive(Default, Clone)]
pub struct ClientMetadata {
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
}

const MAX_BODY_BYTES: usize = 1024 * 1024;
const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Fetches and parses the client_id metadata document. Returns default
/// (empty) metadata on any failure -- a fetch failure is not fatal by
/// itself; it only becomes a fatal error at the call site if `redirect_uri`
/// also fails the same-origin check, since then there is nothing left to
/// validate it against.
pub async fn fetch_client_metadata(client: &HttpsClient, client_id: &Url) -> ClientMetadata {
    if is_loopback_client_id(client_id) {
        return ClientMetadata::default();
    }

    let Some(host) = client_id.host_str() else {
        return ClientMetadata::default();
    };
    let port = client_id.port_or_known_default().unwrap_or(443);
    match tokio::net::lookup_host((host, port)).await {
        Ok(addrs) => {
            let addrs: Vec<_> = addrs.collect();
            if addrs.is_empty() || addrs.iter().any(|a| is_disallowed_ip(a.ip())) {
                tracing::warn!(%client_id, "client_id resolves to a disallowed IP; refusing to fetch");
                return ClientMetadata::default();
            }
        }
        Err(_) => return ClientMetadata::default(),
    }

    let req = match http::Request::get(client_id.as_str())
        .header(http::header::ACCEPT, "application/json")
        .body(Full::new(Bytes::new()))
    {
        Ok(r) => r,
        Err(_) => return ClientMetadata::default(),
    };

    let fetch = async {
        let resp = client.request(req).await.ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let body = resp.into_body().collect().await.ok()?.to_bytes();
        if body.len() > MAX_BODY_BYTES {
            return None;
        }
        serde_json::from_slice::<ClientIdDocument>(&body).ok()
    };

    match tokio::time::timeout(FETCH_TIMEOUT, fetch).await {
        // Per spec: the server must verify the document's declared
        // client_id matches the URL it was fetched from. A mismatch is
        // treated the same as a fetch failure (empty metadata), not a
        // fatal error -- redirect_uri can still be validated via the
        // same-origin fallback.
        Ok(Some(doc)) if doc.client_id.as_deref() == Some(client_id.as_str()) => ClientMetadata {
            client_name: doc.client_name,
            redirect_uris: doc.redirect_uris,
        },
        _ => ClientMetadata::default(),
    }
}

fn same_origin(a: &Url, b: &Url) -> bool {
    a.scheme() == b.scheme() && a.host_str() == b.host_str() && a.port_or_known_default() == b.port_or_known_default()
}

/// Redirect_uri must either share client_id's origin, or exactly match one
/// of the URIs the client published in its metadata document.
pub fn validate_redirect_uri(client_id: &Url, redirect_uri: &Url, metadata: &ClientMetadata) -> bool {
    if same_origin(client_id, redirect_uri) {
        return true;
    }
    metadata
        .redirect_uris
        .iter()
        .any(|u| u.as_str() == redirect_uri.as_str())
}
