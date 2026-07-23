use sha2::{Digest, Sha256};
use webauthn_rs::prelude::*;

/// Wraps the configured `Webauthn` instance plus the single owner's stable
/// user handle. There is exactly one owner; `owner_user_id` is derived
/// deterministically from `rp_id` (rather than randomly generated and
/// stored) so there's no extra bootstrap state to persist.
pub struct WebauthnState {
    pub webauthn: Webauthn,
    pub owner_user_id: Uuid,
}

impl WebauthnState {
    pub fn new(rp_id: &str, rp_origin: &str) -> Self {
        let origin = Url::parse(rp_origin).expect("RP_ORIGIN must be a valid URL");
        let webauthn = WebauthnBuilder::new(rp_id, &origin)
            .expect("rp_id must be an effective domain of rp_origin")
            .rp_name(rp_id)
            .build()
            .expect("invalid webauthn configuration");
        let owner_user_id = deterministic_owner_id(rp_id);
        WebauthnState {
            webauthn,
            owner_user_id,
        }
    }
}

/// Derives a stable UUID from `rp_id` without needing the `uuid` crate's
/// `v5` feature (which webauthn-rs doesn't otherwise enable): the first 16
/// bytes of SHA-256(rp_id), which we already depend on for PKCE.
fn deterministic_owner_id(rp_id: &str) -> Uuid {
    let digest = Sha256::digest(rp_id.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    Uuid::from_bytes(bytes)
}
