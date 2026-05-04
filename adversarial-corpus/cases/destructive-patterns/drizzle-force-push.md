# drizzle-kit push --force (OACB-DB-001)

**Pattern:** `drizzle-kit push --force`
**OWASP ASI:** ASI02 Tool Misuse & Exploitation
**Rule:** OACB-DB-001

## Attack

The Drizzle ORM migration incident demonstrated that an autonomous agent executing `drizzle-kit push --force` against a production database can drop or truncate tables without interactive confirmation. The `--force` flag bypasses the interactive confirmation prompt that normally requires a human to type `yes`.

## Real incident

A developer reported that an AI coding agent ran `drizzle-kit push --force` against a production Postgres instance, dropping tables with live user data. The `--force` flag was added by the agent because the migration involved a schema conflict that would otherwise require manual resolution.

## OACB coverage

| Command | Rule ID | Outcome |
|---------|---------|---------|
| `drizzle-kit push --force` | OACB-DB-001 | exit 2 at baseline+ |
| `drizzle-kit push` (no --force) | — | exit 0 (allowed) |

**Expected:** exit 2, stderr contains `OACB-DB-001`
