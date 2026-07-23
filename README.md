# indieauth

A minimal-dependency [IndieAuth](https://indieauth.spec.indieweb.org/)
server for a single-user personal website: sign in to third-party
IndieWeb apps with your own domain, backed by WebAuthn/passkeys instead
of a password.

- No axum, no tower, no sqlx -- `tokio` + `hyper` directly, `rusqlite` on
  a single-writer thread, hand-rolled routing (there are only a handful
  of routes).
- WebAuthn passkey login, multiple credentials per owner (phone, YubiKey,
  backup key, ...), with a page to view/rename/remove them.
- Full IndieAuth server: authorization, token, introspection, revocation,
  and metadata endpoints, PKCE mandatory (S256 only), scoped access
  tokens for third-party clients (e.g. Micropub), not just identity login.
- `client_id` metadata document discovery with SSRF guards.
- CSRF protection via the [Fetch Metadata
  strategy](https://words.filippo.io/csrf/), not tokens.
- WebAuthn ceremony JS is served as external files with data passed via
  inert JSON, not inline `<script>` -- works under a strict
  Content-Security-Policy (no `'unsafe-inline'`, restrictive
  `form-action`).
- OpenSSL is vendored (statically linked in) rather than dynamically
  linked against whatever OpenSSL happens to be on the machine -- see
  "Why vendored OpenSSL" below.

## Requirements

- Rust (recent stable; developed against 1.97).
- A C compiler and `perl` -- needed to build `rusqlite`'s bundled SQLite
  and the vendored OpenSSL.

## Build

```
cargo build --release
```

or, if you'd rather not remember that:

```
make release
```

The binary is `target/release/indieauth`.

## Configure

Everything is configured via environment variables (no config file):

| Variable          | Example                        | Notes |
|--------------------|--------------------------------|-------|
| `DATABASE_PATH`    | `/var/lib/indieauth/indieauth.db` | SQLite file; created if missing. |
| `RP_ID`            | `example.com`                  | WebAuthn relying party id -- your registrable domain. |
| `RP_ORIGIN`        | `https://example.com`          | WebAuthn origin. Must share a registrable domain with `RP_ID`. |
| `ISSUER_URL`       | `https://example.com`          | IndieAuth issuer, published in metadata and the `iss` param. |
| `OWNER_ME_URL`     | `https://example.com/`         | The profile URL ("me") this server asserts on login. |
| `BIND_ADDR`        | `unix:/var/run/indieauth/indieauth.sock` or `0.0.0.0:8787` | `unix:`-prefixed for a socket, otherwise a TCP address. |
| `BOOTSTRAP_SECRET` | *(unset by default)*           | One-time secret to register your first passkey -- see below. |

## Run

```
DATABASE_PATH=./indieauth.db \
RP_ID=example.com \
RP_ORIGIN=https://example.com \
ISSUER_URL=https://example.com \
OWNER_ME_URL=https://example.com/ \
BIND_ADDR=127.0.0.1:8787 \
BOOTSTRAP_SECRET=$(openssl rand -base64 24) \
./target/release/indieauth
```

Then visit `https://example.com/auth/register?bootstrap=<the secret>`
through your reverse proxy (see below) to register your first passkey.
Once at least one credential exists, `/auth/register` requires an
authenticated owner session and the bootstrap secret stops mattering --
remove it from the environment.

## Reverse proxy

indieauth expects to sit behind a TLS-terminating reverse proxy on the
same site. It only needs two things proxied to it: the `/auth/` prefix
and the metadata well-known path. An nginx example:

```nginx
# ^~ matters if your site has a regex location for static-asset extensions
# (e.g. `location ~* \.(js|css|...)$ { ... }`, common for cache headers) --
# regex locations otherwise take priority over a plain prefix match and
# will 404 requests for /auth/static/*.js|css instead of proxying them.
location ^~ /auth/ {
    proxy_pass          http://unix:/var/run/indieauth/indieauth.sock:;
    proxy_set_header     Host $host;
    proxy_set_header     X-Forwarded-Proto https;
    proxy_set_header     X-Forwarded-For $proxy_add_x_forwarded_for;
}
location = /.well-known/oauth-authorization-server {
    proxy_pass          http://unix:/var/run/indieauth/indieauth.sock:;
    proxy_set_header     Host $host;
    proxy_set_header     X-Forwarded-Proto https;
}
```

(Use a TCP `proxy_pass` target instead if indieauth runs on a different
host than the reverse proxy, with `BIND_ADDR` set to a TCP address to
match.)

Your site's homepage also needs to advertise discovery, so IndieAuth
clients can find these endpoints from just your profile URL:

```html
<link rel="indieauth-metadata" href="https://example.com/.well-known/oauth-authorization-server">
<link rel="authorization_endpoint" href="https://example.com/auth/authorize">
<link rel="token_endpoint" href="https://example.com/auth/token">
```

The first is the current spec's preferred mechanism; the other two are a
legacy fallback for older clients, cheap to include alongside it.

## Deploying under daemontools

See [`daemontools/README.md`](daemontools/README.md) for a same-host
service example (djb daemontools' own `envdir`/`setuidgid`/`multilog`,
not runit's `chpst`), including the one-time bootstrap-secret procedure.

## Endpoints

| Method | Path | |
|---|---|---|
| GET  | `/.well-known/oauth-authorization-server` | Server metadata |
| GET/POST | `/auth/authorize` | Authorization + consent |
| POST | `/auth/token` | Code exchange (PKCE required) |
| POST | `/auth/introspection` | Token verification |
| POST | `/auth/revocation` | Token revocation |
| GET  | `/auth/register`, POST `/auth/register/finish` | Add a passkey |
| GET  | `/auth/login`, POST `/auth/login/finish` | Sign in with a passkey |
| POST | `/auth/logout` | End the owner session |
| GET  | `/auth/credentials`, POST `/auth/credentials/{rename,delete}` | Manage passkeys |

## Why vendored OpenSSL

`webauthn-rs-core` (a dependency, used for the WebAuthn ceremonies)
unconditionally depends on the `openssl` crate. Rather than dynamically
linking against whatever OpenSSL is installed on the build/deploy
machine, `Cargo.toml` enables `openssl`'s `vendored` feature directly,
which unifies that feature across the whole dependency graph and builds
a pinned, known-good OpenSSL from source instead. This sidesteps a real
failure mode: a custom or very new OpenSSL build can be ABI-incompatible
with the `openssl-sys` bindings in ways that link and start fine but
crash on first use (in our case, a deprecated low-level `SHA256_Init`
call that a newer OpenSSL had apparently dropped). The resulting binary
has no runtime `libssl`/`libcrypto` dependency at all.

## License

AGPL-3.0 -- see [`LICENSE`](LICENSE).
