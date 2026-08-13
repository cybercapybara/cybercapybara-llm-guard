-- Migration 000: shared touch_updated_at() trigger function
--
-- A single, reusable trigger function that any table with an `updated_at
-- TIMESTAMPTZ` column can attach to so the column is bumped to now() on every
-- UPDATE. scripts/new-migration.sh emits `CREATE TRIGGER ... EXECUTE FUNCTION
-- touch_updated_at()` in its table skeleton, so the function must exist before
-- any scaffolded migration runs — hence version 000, ahead of everything else.
--
-- NOTE: MigrationRunner wraps each file in ONE transaction (under an advisory
-- lock) and records schema_migrations in that same transaction. Do NOT add
-- BEGIN/COMMIT here — an embedded COMMIT ends the runner's transaction early,
-- drops the lock mid-DDL, and breaks the atomic version bookkeeping.

CREATE OR REPLACE FUNCTION touch_updated_at() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
