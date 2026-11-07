-- The door as an action: a tap plus fingerprint that unlocks the front door
-- instead of running a script. At most one, and it has no script; a script
-- action always has one. Which is which is fixed at creation.
--
-- Re-run on every start like the rest: the constraint is dropped and added
-- again so this file stays idempotent.

alter table actions add column if not exists kind text not null default 'script';
alter table actions alter column script_entity drop not null;
alter table actions drop constraint if exists actions_kind_check;
alter table actions add constraint actions_kind_check
    check (kind in ('script', 'door') and (kind = 'door') = (script_entity is null));
create unique index if not exists actions_one_door on actions (kind) where kind = 'door';
