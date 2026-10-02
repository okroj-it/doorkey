-- doorkey schema for SQLite: the end state of db/001-004 for Postgres.
--
-- Differences from the Postgres schema, and why:
--   - INTEGER PRIMARY KEY instead of (BIG)SERIAL; BLOB for bytes; TEXT for
--     JSON (db-values.ts parses it back).
--   - Timestamps are ISO-8601 UTC text with milliseconds, the format
--     Date.toISOString() writes, so text comparison orders them correctly.
--     Not CURRENT_TIMESTAMP: that format has a space for the T.
--   - Booleans are INTEGER 0/1 (db-values.ts turns them back).
--   - The two regex CHECKs become GLOB checks: SQLite has no regex.
--
-- Migrations after this one are applied by PRAGMA user_version (see
-- migrate() in src/db.ts). Foreign keys only work with PRAGMA foreign_keys,
-- which migrate() turns on.

CREATE TABLE codes (
    id            INTEGER PRIMARY KEY,
    label         TEXT    NOT NULL,
    code_hash     BLOB    NOT NULL UNIQUE,
    active        INTEGER NOT NULL DEFAULT 1,
    valid_from    TEXT,
    valid_until   TEXT,
    schedule      TEXT,
    max_uses      INTEGER,
    use_count     INTEGER NOT NULL DEFAULT 0,
    failed_streak INTEGER NOT NULL DEFAULT 0,
    locked_until  TEXT,
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_used_at  TEXT
);

CREATE TABLE attempts (
    id         INTEGER PRIMARY KEY,
    ts         TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    code_id    INTEGER REFERENCES codes (id) ON DELETE SET NULL,
    result     TEXT    NOT NULL,
    src_ip     TEXT,
    user_agent TEXT
);

CREATE INDEX idx_attempts_ts     ON attempts (ts DESC);
CREATE INDEX idx_attempts_result ON attempts (result, ts DESC);

CREATE TABLE system_state (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);

INSERT INTO system_state (k, v) VALUES ('failed_streak', '0')
    ON CONFLICT (k) DO NOTHING;

CREATE TABLE admin_credentials (
    id            INTEGER PRIMARY KEY,
    label         TEXT    NOT NULL,
    credential_id TEXT    NOT NULL UNIQUE,
    public_key    BLOB    NOT NULL,
    counter       INTEGER NOT NULL DEFAULT 0,
    transports    TEXT,
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_used_at  TEXT
);

CREATE TABLE admin_enrollments (
    token      TEXT PRIMARY KEY,
    label      TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at    TEXT
);

CREATE TABLE admin_events (
    id     INTEGER PRIMARY KEY,
    ts     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    event  TEXT    NOT NULL,
    detail TEXT,
    src_ip TEXT
);

CREATE INDEX idx_admin_events_ts ON admin_events (ts DESC);

CREATE TABLE action_users (
    id         INTEGER PRIMARY KEY,
    name       TEXT    NOT NULL UNIQUE,
    active     INTEGER NOT NULL DEFAULT 1,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE action_credentials (
    id            INTEGER PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES action_users (id) ON DELETE CASCADE,
    label         TEXT    NOT NULL,
    credential_id TEXT    NOT NULL UNIQUE,
    public_key    BLOB    NOT NULL,
    counter       INTEGER NOT NULL DEFAULT 0,
    transports    TEXT,
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_used_at  TEXT
);

CREATE INDEX action_credentials_user_idx ON action_credentials (user_id);

CREATE TABLE action_enrollments (
    token      TEXT    PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES action_users (id) ON DELETE CASCADE,
    label      TEXT    NOT NULL,
    expires_at TEXT    NOT NULL,
    used_at    TEXT
);

CREATE TABLE roles (
    id   INTEGER PRIMARY KEY,
    name TEXT    NOT NULL UNIQUE
);

CREATE TABLE user_roles (
    user_id INTEGER NOT NULL REFERENCES action_users (id) ON DELETE CASCADE,
    role_id INTEGER NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE actions (
    id            INTEGER PRIMARY KEY,
    -- ^[a-z0-9][a-z0-9-]{0,62}$
    slug          TEXT    NOT NULL UNIQUE CHECK (
                      length(slug) BETWEEN 1 AND 63
                      AND substr(slug, 1, 1) GLOB '[a-z0-9]'
                      AND slug NOT GLOB '*[^a-z0-9-]*'),
    label         TEXT    NOT NULL,
    -- ^script\.[a-z0-9_]+$
    script_entity TEXT    NOT NULL CHECK (
                      script_entity GLOB 'script.?*'
                      AND substr(script_entity, 8) NOT GLOB '*[^a-z0-9_]*'),
    require_sun   INTEGER NOT NULL DEFAULT 0,
    home_only     INTEGER NOT NULL DEFAULT 0,
    token_hash    BLOB,
    active        INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_run_at   TEXT
);

CREATE TABLE action_roles (
    action_id INTEGER NOT NULL REFERENCES actions (id) ON DELETE CASCADE,
    role_id   INTEGER NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    PRIMARY KEY (action_id, role_id)
);

-- A DNA tag opens the door (action_id NULL) or one action. RESTRICT: deleting
-- an action must never quietly turn its tag into a door key.
CREATE TABLE tags (
    id           INTEGER PRIMARY KEY,
    uid          BLOB    NOT NULL UNIQUE,
    label        TEXT    NOT NULL,
    active       INTEGER NOT NULL DEFAULT 1,
    mac_key_enc  BLOB    NOT NULL,
    last_counter INTEGER NOT NULL DEFAULT -1,
    action_id    INTEGER REFERENCES actions (id) ON DELETE RESTRICT,
    created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_used_at TEXT
);

CREATE INDEX tags_uid_idx ON tags (uid);

CREATE TABLE action_events (
    id         INTEGER PRIMARY KEY,
    ts         TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    action_id  INTEGER REFERENCES actions (id) ON DELETE SET NULL,
    user_id    INTEGER REFERENCES action_users (id) ON DELETE SET NULL,
    result     TEXT    NOT NULL,
    via        TEXT,
    tag_id     INTEGER REFERENCES tags (id) ON DELETE SET NULL,
    src_ip     TEXT,
    user_agent TEXT
);

CREATE INDEX action_events_ts_idx ON action_events (ts DESC);
