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
   cargo build --release
   install -m 755 target/release/indieauth /usr/local/bin/indieauth
   ```

   If your OpenSSL is in a nonstandard location, set `OPENSSL_DIR`
   (and possibly `RUSTFLAGS="-C link-arg=-Wl,-rpath,<path>/lib"`) when
   building.

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
