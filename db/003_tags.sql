-- NTAG 424 DNA tags for DOORKEY_TAP_MODE=sun.
--
-- Key material is stored WRAPPED, never in the clear: the provisioning tool
-- derives each tag's keys from an offline master (kept in a password manager)
-- and encrypts them with a KEK that lives only in the environment. A stolen
-- database dump is therefore useless on its own.
--
-- The service never sees the offline master, so it can verify taps but cannot
-- reconfigure a tag.
create table if not exists tags (
    id            serial primary key,
    uid           bytea       not null unique,   -- 7-byte NTAG 424 UID
    label         text        not null,
    active        boolean     not null default true,

    -- AES-GCM wrapped K3 (SDMFileRead): nonce || ct || tag.
    --
    -- K2 (SDMMetaRead) is deliberately NOT here: it is shared across tags and
    -- held in DOORKEY_TAG_META_KEY. That is what lets one decrypt recover the
    -- UID and turn tag lookup into an index hit instead of a scan. Sharing it
    -- risks only confidentiality of UID and counter - forging a tap needs K3,
    -- which is per-tag, and reconfiguring one needs K0, which never leaves the
    -- offline master.
    mac_key_enc   bytea       not null,

    -- Highest SDM read counter accepted so far. A tap must strictly exceed it;
    -- that is what makes a captured URL useless on replay.
    last_counter  integer     not null default -1,

    created_at    timestamptz not null default now(),
    last_used_at  timestamptz
);

create index if not exists tags_uid_idx on tags (uid);
