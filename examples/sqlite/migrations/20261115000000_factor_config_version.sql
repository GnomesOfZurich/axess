-- A factor configuration is replaced by a compare-and-swap: "write this
-- configuration if the row still is the one I loaded". The store decides
-- "still is" on the configuration as a value, which it has to read first,
-- so the write that follows needs a guard that fails when the row changed
-- in between. `version` is that guard: the swap writes
-- `WHERE id = ? AND version = ?` with the version it read.
--
-- The guard is only sound if every write of `config_json` moves the
-- version, whoever makes it: the store's own statements, the seed, a
-- statement added later, a console session. A trigger keeps that true for
-- all of them, where a `version = version + 1` written into each statement
-- holds only for the statements that remember it.
ALTER TABLE factor_configs ADD COLUMN version INTEGER NOT NULL DEFAULT 0;

CREATE TRIGGER factor_configs_version_moves
AFTER UPDATE OF config_json ON factor_configs
FOR EACH ROW
BEGIN
    UPDATE factor_configs SET version = OLD.version + 1 WHERE id = NEW.id;
END;
