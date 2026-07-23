use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

pub fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

pub fn to_rfc3339(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).expect("valid timestamp")
}

pub fn now_rfc3339() -> String {
    to_rfc3339(now())
}

pub fn rfc3339_after(d: Duration) -> String {
    to_rfc3339(now() + d)
}

/// Parses an RFC3339 timestamp previously produced by this module. Returns
/// `None` on malformed input rather than panicking -- callers treat that the
/// same as "expired" so a corrupt row can't wedge a request.
pub fn parse_rfc3339(s: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(s, &Rfc3339).ok()
}

pub fn is_past(rfc3339: &str) -> bool {
    match parse_rfc3339(rfc3339) {
        Some(t) => t <= now(),
        None => true,
    }
}
