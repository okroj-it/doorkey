-- The door as an action, as db/005_door_action.sql for Postgres.
--
-- SQLite cannot drop NOT NULL in place, and rebuilding the table would fire
-- the foreign keys pointing at it (roles cascade, tags restrict). Swapping the
-- column does not: add a nullable copy, move the data, drop the old one.

ALTER TABLE actions ADD COLUMN script_new TEXT CHECK (
    script_new GLOB 'script.?*'
    AND substr(script_new, 8) NOT GLOB '*[^a-z0-9_]*');
UPDATE actions SET script_new = script_entity;
ALTER TABLE actions DROP COLUMN script_entity;
ALTER TABLE actions RENAME COLUMN script_new TO script_entity;

ALTER TABLE actions ADD COLUMN kind TEXT NOT NULL DEFAULT 'script' CHECK (
    kind IN ('script', 'door') AND (kind = 'door') = (script_entity IS NULL));
CREATE UNIQUE INDEX actions_one_door ON actions (kind) WHERE kind = 'door';
