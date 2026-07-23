use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;

/// Generates a random, URL-safe, unpadded base64 token of `num_bytes` bytes
/// of entropy. Used for authorization codes, access tokens, and session
/// ids -- anywhere we need an opaque, unguessable identifier.
pub fn random_token(num_bytes: usize) -> String {
    let mut bytes = vec![0u8; num_bytes];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
