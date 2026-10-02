-- doorkey schema.
--
-- `attempts` is the audit log and the source of truth for what happened.
-- The counters on `codes` and in `system_state` are deliberately denormalised
-- so a lockout decision costs two indexed reads rather than an aggregate over
-- the whole history.

CREATE TABLE IF NOT EXISTS codes (
    id            BIGSERIAL    PRIMARY KEY,
    label         TEXT         NOT NULL,
    -- HMAC-SHA256(pepper, code). Indexed, so identifying a code is one lookup
    -- and takes the same time whether or not it exists.
    code_hash     BYTEA        NOT NULL UNIQUE,
    active        BOOLEAN      NOT NULL DEFAULT TRUE,
    valid_from    TIMESTAMPTZ,
    valid_until   TIMESTAMPTZ,
    -- [{"dow":[2],"from":"09:00","to":"12:00"}] in Europe/Warsaw. NULL = any time.
    schedule      JSONB,
    max_uses      INTEGER,
    use_count     INTEGER      NOT NULL DEFAULT 0,
    failed_streak INTEGER      NOT NULL DEFAULT 0,
    locked_until  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_used_at  TIMESTAMPTZ
);

-- result values:
--   granted
--   bad_code          code not recognised
--   inactive          revoked
--   expired           outside valid_from/valid_until
--   out_of_schedule   recognised, wrong day/time
--   exhausted         max_uses reached
--   code_locked       that code is in its own lockout
--   system_locked     global lockout active; attempt not counted
CREATE TABLE IF NOT EXISTS attempts (
    id         BIGSERIAL    PRIMARY KEY,
    ts         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    code_id    BIGINT       REFERENCES codes(id) ON DELETE SET NULL,
    result     TEXT         NOT NULL,
    -- From CF-Connecting-IP. Spoofable by anyone reaching the origin directly,
    -- so this is for the audit trail only and never drives a decision.
    src_ip     TEXT,
    user_agent TEXT
);

CREATE INDEX IF NOT EXISTS idx_attempts_ts     ON attempts (ts DESC);
CREATE INDEX IF NOT EXISTS idx_attempts_result ON attempts (result, ts DESC);

CREATE TABLE IF NOT EXISTS system_state (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);

-- failed_streak   consecutive failures since the last grant
-- locked_until    ISO8601; global lockout expiry
-- last_granted_at ISO8601
INSERT INTO system_state (k, v) VALUES ('failed_streak', '0')
    ON CONFLICT (k) DO NOTHING;
