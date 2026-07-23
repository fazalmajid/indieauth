# daemontools service example

A same-host deployment: indieauth binds a unix socket, and nginx (running
on the same box) reverse-proxies to it. If your reverse proxy runs on a
different host, set `BIND_ADDR` to a TCP address instead (e.g.
`0.0.0.0:8787`) -- see `src/config.rs`.

This uses djb daemontools' own tools (`envdir`, `setuidgid`, `multilog`),
not runit's `chpst`.

## Layout

```
indieauth/
  run          # starts the service
  env/         # one file per env var, envdir-style
  log/
    run        # log capture via multilog
```

## Install

1. Build the release binary and install it:

   ```
   make release
   install -m 755 target/release/indieauth /usr/local/bin/indieauth
   ```

   `openssl` (the Rust crate used by `webauthn-rs-core`) builds with its
   `vendored` feature, compiling and statically linking a known-good
   OpenSSL from source rather than depending on whatever OpenSSL happens
   to be installed on the machine. This needs a C compiler and `perl` on
   the build machine (which you already need for `rusqlite`'s bundled
   SQLite), but means the resulting binary has no runtime OpenSSL
   dependency at all -- confirmed via `ldd`, no `libssl`/`libcrypto` in
   the output. This matters in practice: a custom/very new OpenSSL build
   (e.g. an early 4.x) can be ABI-incompatible with the `openssl-sys`
   bindings in ways that compile fine but crash at runtime with a NULL
   function-pointer call -- vendoring sidesteps that entirely.

2. Create dedicated users (no login shell needed):

   ```
   adduser -D -H -s /sbin/nologin indieauth
   adduser -D -H -s /sbin/nologin indieauth-log
   ```

3. Edit `indieauth/env/*` to match your actual domain (the checked-in
   values are placeholders -- `example.com`). `DATABASE_PATH`'s
   directory, the socket's directory, and the log directory are all
   created (and chowned) automatically by `run`/`log/run` on every
   start, so no manual `mkdir`/`chown` step is needed for those.

   Optionally add `env/OWNER_NAME` and `env/OWNER_PHOTO_URL` (not checked
   in, since there's no sensible placeholder) if you want IndieWeb sites
   requesting the `profile` scope to show your name/photo instead of the
   bare profile URL -- see the main README's config table.

4. Copy or symlink this `indieauth/` directory into wherever your
   `svscan` watches (commonly `/service/` for a stock djb daemontools
   install; adjust to your setup):

   ```
   cp -r daemontools/indieauth /service/indieauth
   ```

   `svscan` picks it up automatically; `supervise` starts `run`, and
   (since a sibling `log/` directory exists) pipes its stdout/stderr into
   `log/run`'s `multilog`.

## First-run bootstrap

Before any WebAuthn credential exists, `/auth/register` needs a one-time
bootstrap secret (see `src/routes/login.rs`). This is deliberately *not*
checked into `env/`:

1. Generate one and add it temporarily:

   ```
   echo -n "$(openssl rand -base64 24)" > /service/indieauth/env/BOOTSTRAP_SECRET
   svc -t /service/indieauth
   ```

2. Visit `https://<your-domain>/auth/register?bootstrap=<the secret>` and
   register your first passkey.

3. Remove the file and restart so the endpoint can never be triggered
   again by an outsider:

   ```
   rm /service/indieauth/env/BOOTSTRAP_SECRET
   svc -t /service/indieauth
   ```

## nginx

See the project root for a worked example of the reverse-proxy config
(`/auth/` and `/.well-known/oauth-authorization-server` proxied to
indieauth's socket or TCP address, plus the discovery `<link>` tags for
your site's homepage) -- that part is site-specific and not included
here.
