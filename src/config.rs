use std::env;

/// Where to listen. A same-host daemontools deployment uses a unix
/// socket; a reverse proxy running on a *different* host (e.g. proxying
/// over a LAN) needs a TCP address instead, since unix sockets can't be
/// reached over the network.
pub enum BindAddr {
    Unix(String),
    Tcp(String),
}

pub struct Config {
    /// Path to the SQLite database file.
    pub database_path: String,
    /// WebAuthn relying party id -- the registrable domain, e.g. "example.com".
    pub rp_id: String,
    /// WebAuthn relying party origin, e.g. "https://example.com".
    pub rp_origin: String,
    /// IndieAuth issuer identifier, published in server metadata and the
    /// `iss` param on authorization responses. Same as rp_origin in the
    /// common case, kept separate since the spec treats them distinctly.
    pub issuer: String,
    /// The canonical profile URL ("me") this server issues on
    /// successful login, e.g. "https://example.com/".
    pub owner_me: String,
    /// Display name returned in the `profile` object when a token request
    /// includes the `profile` scope (e.g. so IndieWeb sites can show
    /// "Fazal Majid" instead of the bare profile URL). Omitted from the
    /// response if unset.
    pub owner_name: Option<String>,
    /// Photo/avatar URL returned in the `profile` object under the same
    /// conditions -- e.g. a Gravatar URL. Omitted if unset.
    pub owner_photo_url: Option<String>,
    /// Where to listen -- a unix socket path or a TCP address, from
    /// `BIND_ADDR` (a `unix:` prefix selects the unix-socket variant).
    pub bind_addr: BindAddr,
    /// One-time bootstrap secret required to register the very first
    /// WebAuthn credential (before any owner exists). Should be unset /
    /// removed from the env after first use.
    pub bootstrap_secret: Option<String>,
}

fn require(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("missing required env var {name}"))
}

impl Config {
    pub fn from_env() -> Self {
        let bind_addr = require("BIND_ADDR");
        let bind_addr = match bind_addr.strip_prefix("unix:") {
            Some(path) => BindAddr::Unix(path.to_string()),
            None => BindAddr::Tcp(bind_addr),
        };
        Config {
            database_path: require("DATABASE_PATH"),
            rp_id: require("RP_ID"),
            rp_origin: require("RP_ORIGIN"),
            issuer: require("ISSUER_URL"),
            owner_me: require("OWNER_ME_URL"),
            owner_name: env::var("OWNER_NAME").ok(),
            owner_photo_url: env::var("OWNER_PHOTO_URL").ok(),
            bind_addr,
            bootstrap_secret: env::var("BOOTSTRAP_SECRET").ok(),
        }
    }
}
