-- Multiple credentials supported from day one: one owner, many authenticators
-- (phone, YubiKey, backup key, ...).
CREATE TABLE webauthn_credentials (
    id             INTEGER PRIMARY KEY,
    credential_id  BLOB NOT NULL UNIQUE,
    passkey_json   TEXT NOT NULL,
    label          TEXT,
    created_at     TEXT NOT NULL,
    last_used_at   TEXT
);

-- Backs both WebAuthn ceremony state (kind = 'ceremony') and the
-- authenticated-owner session (kind = 'owner'). The cookie only ever
-- carries this opaque, high-entropy id -- never signed/encrypted, since
-- all real state stays server-side.
CREATE TABLE sessions (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    data_json   TEXT NOT NULL,
    expires_at  TEXT NOT NULL
);

CREATE TABLE authorization_codes (
    code                   TEXT PRIMARY KEY,
    client_id              TEXT NOT NULL,
    redirect_uri           TEXT NOT NULL,
    me                     TEXT NOT NULL,
    scope                  TEXT NOT NULL DEFAULT '',
    code_challenge         TEXT NOT NULL,
    code_challenge_method  TEXT NOT NULL,
    state                  TEXT,
    created_at             TEXT NOT NULL,
    expires_at             TEXT NOT NULL,
    used_at                TEXT
);

CREATE TABLE access_tokens (
    token        TEXT PRIMARY KEY,
    client_id    TEXT NOT NULL,
    me           TEXT NOT NULL,
    scope        TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL,
    expires_at   TEXT,
    revoked_at   TEXT
);

CREATE INDEX idx_access_tokens_active ON access_tokens(revoked_at, expires_at);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);
