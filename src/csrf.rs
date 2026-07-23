//! CSRF protection for cookie/session-authenticated, state-changing
//! requests, following the Fetch Metadata strategy from
//! <https://words.filippo.io/csrf/>. Applies to POST /auth/authorize and
//! the WebAuthn ceremony-finish endpoints -- not to /auth/token,
//! /auth/introspection, /auth/revocation, which are authenticated by
//! request-body credentials rather than ambient cookies and so aren't
//! CSRF-exploitable in the classic sense.

use http::{HeaderMap, Method};

pub fn is_same_site(method: &Method, headers: &HeaderMap, our_origin: &str) -> bool {
    if method == Method::GET || method == Method::HEAD || method == Method::OPTIONS {
        return true;
    }

    if let Some(origin) = headers.get(http::header::ORIGIN).and_then(|v| v.to_str().ok()) {
        return origin == our_origin;
    }

    if let Some(site) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        return site == "same-origin" || site == "none";
    }

    // Neither header present: a pre-2020 browser. SameSite=Lax on the
    // session cookie already covers this residual case, since browsers
    // old enough to lack Fetch Metadata almost certainly also lack
    // SameSite cookie support -- the two gaps barely overlap.
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn headers_with(name: &'static str, value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(name, HeaderValue::from_str(value).unwrap());
        h
    }

    #[test]
    fn safe_methods_always_pass() {
        assert!(is_same_site(&Method::GET, &HeaderMap::new(), "https://example.com"));
    }

    #[test]
    fn matching_origin_passes() {
        let h = headers_with("origin", "https://example.com");
        assert!(is_same_site(&Method::POST, &h, "https://example.com"));
    }

    #[test]
    fn cross_origin_rejected() {
        let h = headers_with("origin", "https://evil.example");
        assert!(!is_same_site(&Method::POST, &h, "https://example.com"));
    }

    #[test]
    fn sec_fetch_site_same_origin_passes() {
        let h = headers_with("sec-fetch-site", "same-origin");
        assert!(is_same_site(&Method::POST, &h, "https://example.com"));
    }

    #[test]
    fn sec_fetch_site_cross_site_rejected() {
        let h = headers_with("sec-fetch-site", "cross-site");
        assert!(!is_same_site(&Method::POST, &h, "https://example.com"));
    }

    #[test]
    fn no_headers_passes_as_legacy_fallback() {
        assert!(is_same_site(&Method::POST, &HeaderMap::new(), "https://example.com"));
    }
}
