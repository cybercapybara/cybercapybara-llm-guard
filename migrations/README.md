# Migrations

Drop numbered `.sql` files here — `MigrationRunner` picks them up on boot,
applies any that aren't already in `schema_migrations`, and records what it
did. Naming: `NNN_description.sql` (e.g. `001_widgets.sql`).

`docs/CONVENTIONS.md` has the migration conventions in context.

## What ships today

- `000_updated_at_trigger.sql` — the shared `touch_updated_at()` trigger
  function. Domain-neutral infrastructure: `scripts/new-migration.sh` wires
  every scaffolded table to it, so it has to be applied first. Don't delete it.

## Generating a new migration

```bash
./scripts/new-migration.sh add_widgets
# ==> Created migrations/001_add_widgets.sql
```

The script picks the next free `NNN`, slugifies the description, and writes a
commented table skeleton (id / name / created_at / updated_at plus a
`touch_updated_at` trigger). It deliberately emits **no** `BEGIN`/`COMMIT` —
the runner wraps each file in one advisory-locked transaction together with the
`schema_migrations` bookkeeping, and an embedded `COMMIT` would break that.

## Ops

- `./llm_guard --verify-migrations` — list pending files without
  applying (useful as a CI gate; exits 1 if any are pending).
- `./llm_guard --run-migrations` — apply pending migrations and exit
  (CLI-flag form of `RUN_MIGRATIONS_ONLY=1`; equivalent to `make migrate-local`
  for the native binary).
- `DB_MIGRATIONS_ENABLED=false` — skip running migrations on app boot
  (set this when an init container is responsible instead).
- `RUN_MIGRATIONS_ONLY=1 ./llm_guard` — env-var equivalent of
  `--run-migrations`, convenient for Helm init-containers.
- `make migrate` (Docker) / `make migrate-local` (native) — wrappers around
  the above.

## Ignored

Anything outside the top level of this directory is skipped by the runner,
so an `archive/` subfolder won't be auto-applied on boot.
