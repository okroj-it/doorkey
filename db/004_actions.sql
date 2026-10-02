-- Tap-gated Home Assistant actions.
--
-- A tag tap opens /a/<slug>; a passkey with user verification (fingerprint)
-- then runs that action's allowlisted script. Who may run what is role-based.
--
-- Action users and their passkeys are deliberately separate from admin
-- passkeys: an action passkey cannot sign in to /admin, and an admin passkey
-- cannot run an action. Both live on the same RP id, so they are told apart
-- by which table they are in, not by the authenticator.

create table if not exists action_users (
    id          serial      primary key,
    name        text        not null unique,
    active      boolean     not null default true,
    created_at  timestamptz not null default now()
);

create table if not exists action_credentials (
    id            bigserial   primary key,
    user_id       integer     not null references action_users (id) on delete cascade,
    label         text        not null,
    -- base64url, as WebAuthn presents it
    credential_id text        not null unique,
    public_key    bytea       not null,
    counter       bigint      not null default 0,
    transports    jsonb,
    created_at    timestamptz not null default now(),
    last_used_at  timestamptz
);

create index if not exists action_credentials_user_idx on action_credentials (user_id);

-- Single-use enrolment links minted by the CLI, like admin_enrollments.
create table if not exists action_enrollments (
    token       text        primary key,
    user_id     integer     not null references action_users (id) on delete cascade,
    label       text        not null,   -- the device, e.g. "pixel"
    expires_at  timestamptz not null,
    used_at     timestamptz
);

create table if not exists roles (
    id    serial primary key,
    name  text   not null unique
);

create table if not exists user_roles (
    user_id  integer not null references action_users (id) on delete cascade,
    role_id  integer not null references roles (id) on delete cascade,
    primary key (user_id, role_id)
);

create table if not exists actions (
    id            serial      primary key,
    -- the /a/<slug> in the tag URL
    slug          text        not null unique check (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    label         text        not null,
    -- The only thing an action can do is turn on this one script. The entity
    -- never comes from the browser.
    script_entity text        not null check (script_entity ~ '^script\.[a-z0-9_]+$'),
    -- Only a linked NTAG 424 DNA tap opens it; plain-tag tokens are refused.
    require_sun   boolean     not null default false,
    -- Only from DOORKEY_HOME_CIDRS. Approximates presence for plain tags.
    home_only     boolean     not null default false,
    -- HMAC(pepper) of the plain-tag token in ?t=. Null: no plain tag.
    token_hash    bytea,
    active        boolean     not null default true,
    created_at    timestamptz not null default now(),
    last_run_at   timestamptz
);

create table if not exists action_roles (
    action_id  integer not null references actions (id) on delete cascade,
    role_id    integer not null references roles (id) on delete cascade,
    primary key (action_id, role_id)
);

-- A DNA tag either opens the door (null) or one action. RESTRICT, not SET
-- NULL: deleting an action must never quietly turn its tag into a door key.
alter table tags
    add column if not exists action_id integer references actions (id) on delete restrict;

create table if not exists action_events (
    id          bigserial   primary key,
    ts          timestamptz not null default now(),
    action_id   integer     references actions (id) on delete set null,
    user_id     integer     references action_users (id) on delete set null,
    -- ran | not_allowed | bad_passkey | not_home | inactive | ha_error
    result      text        not null,
    -- sun | token
    via         text,
    tag_id      integer     references tags (id) on delete set null,
    src_ip      text,
    user_agent  text
);

create index if not exists action_events_ts_idx on action_events (ts desc);
