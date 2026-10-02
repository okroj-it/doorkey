-- Passkey-authenticated admin.
--
-- No passwords anywhere. A WebAuthn resident key cannot be guessed, cannot be
-- phished onto a lookalike origin, and never leaves the authenticator — which
-- is the only reason a second authenticated surface on this service is
-- defensible at all.

CREATE TABLE IF NOT EXISTS admin_credentials (
    id            BIGSERIAL   PRIMARY KEY,
    label         TEXT        NOT NULL,
    -- base64url, as WebAuthn presents it
    credential_id TEXT        NOT NULL UNIQUE,
    public_key    BYTEA       NOT NULL,
    counter       BIGINT      NOT NULL DEFAULT 0,
    transports    JSONB,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ
);

-- Single-use, short-lived enrolment links minted by the CLI. This is the only
-- way a passkey is ever added, so shell access to the container is the root of trust.
CREATE TABLE IF NOT EXISTS admin_enrollments (
    token      TEXT        PRIMARY KEY,
    label      TEXT        NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ
);

-- Admin sign-ins and code changes, kept beside the door attempts.
CREATE TABLE IF NOT EXISTS admin_events (
    id      BIGSERIAL   PRIMARY KEY,
    ts      TIMESTAMPTZ NOT NULL DEFAULT now(),
    event   TEXT        NOT NULL,
    detail  TEXT,
    src_ip  TEXT
);

CREATE INDEX IF NOT EXISTS idx_admin_events_ts ON admin_events (ts DESC);
