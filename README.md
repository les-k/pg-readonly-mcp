# pg-readonly-mcp

> **In plain terms:** this lets an AI look at your database and do nothing else.
> Not because it was told not to write — the database login it uses is physically
> incapable of writing. The official version of this tool had a published flaw
> that let a "delete everything" command slip past its safety check; this one is
> tested against that exact attack.

A read-only Postgres MCP server that parses SQL rather than pattern-matching
it — because the alternative has already failed in public, once, in a way
that is worth being specific about.

## The bypass this exists to close

Anthropic's reference Postgres MCP server enforced "read-only" by wrapping
each query in a read-only **transaction**. It also accepted semicolon-
delimited multi-statement input. That combination is exploitable:

```sql
SELECT 1; COMMIT; DROP SCHEMA public CASCADE;
```

The `COMMIT` ends the read-only transaction early. Everything after it runs
at full session privilege. [Datadog Security Labs disclosed this in
2026](https://securitylabs.datadoghq.com/articles/mcp-vulnerability-case-study-SQL-injection-in-the-postgresql-mcp-server/);
the server was deprecated and archived — and the vulnerable package was still
pulling **21,000 weekly downloads** after that.

A read-only transaction is a property of *how* a query runs. It says nothing
about *what the query is*, which is exactly why it was possible to talk your
way out of it. This server checks the second thing instead.

## Two independent layers

Either one alone would have stopped the disclosed bypass. Both exist because
a flaw in one should not be the only thing standing between an agent and a
write.

**1. The SQL is parsed, not scanned.** [`guard.py`](src/pg_readonly_mcp/guard.py)
uses [`sqlglot`](https://github.com/tobymao/sqlglot) to build a real syntax
tree and applies three checks:

- **Exactly one statement.** `sqlglot.parse` splits on statement-terminating
  semicolons the way a driver would, so the payload above becomes three
  statements and is refused before any of them reach a connection.
- **The outer statement is a read shape** — `SELECT`, `UNION`, `INTERSECT`,
  `EXCEPT`, or a CTE built from those. `DROP TABLE users` is refused here.
- **No write anywhere in the tree**, walked in full. This is the check the
  other two cannot replace: Postgres allows a CTE to carry a data-modifying
  statement, so `WITH x AS (DELETE FROM t RETURNING *) SELECT * FROM x` is,
  at the outer level, a `SELECT`. A check that only looks at the outer shape
  misses this completely. Walking every node finds the `DELETE` regardless of
  how many levels down it sits.

An unrecognised statement shape — anything `sqlglot` has no specific rule
for — is refused by the same rule as everything else. Unfamiliar is not the
same as safe.

**2. The connection itself cannot write, independent of what it is asked to
run.** [`check_connection_is_readonly`](src/pg_readonly_mcp/server.py) refuses
to start if the connected role is a superuser, can create databases or
roles, can bypass row-level security, or holds any grant beyond `SELECT` on
any table it can see. Not exhaustive — Postgres privilege can also arrive
through ownership, `PUBLIC` grants, or RLS policies this check does not
enumerate — but it catches the two ways a misconfiguration most commonly
shows up, stated here rather than implied.

## What it does not protect against

- **A privileged connection string handed to it anyway.** The startup check
  catches the common shapes of over-privilege; it is not an exhaustive
  privilege audit, and it says so above rather than implying otherwise.
- **Resource exhaustion within the limits.** A query that legally returns
  1,000 rows of very wide data, or that is legitimately expensive to plan,
  still costs what it costs. Row caps and a statement timeout bound the
  damage; they do not make an expensive read free.
- **What the agent does with the data once it has it.** This is a query
  gate, not a data-loss-prevention tool. Read access to a table is read
  access to whatever is in it.
- **A parser disagreement.** `sqlglot` and Postgres's own parser are two
  independent implementations of the same grammar. It is not proven that
  they agree on every edge case Postgres accepts — a genuine, if narrow,
  gap in a project whose whole premise is not trusting a single layer.
  Layer two exists partly because of this: even if a parser differential let
  something unintended through the guard, the connection underneath still
  cannot write.

## Scanner results

Run against [`agent-audit`](https://pypi.org/project/agent-audit/) 0.19.2 on
18 August 2026: 15 findings, 11 auto-suppressed, **4 actionable** — 1 BLOCK,
3 WARN.

**The BLOCK finding is the most interesting one, and worth reading in
full.** `server.py:156`, confidence 1.0: `cur.execute(sql)` — flagged as SQL
injection via unparameterized execution. That line is real. It is also the
single most defended line in this codebase: by the time `sql` reaches it,
`validate_readonly()` has already parsed it, confirmed it is exactly one
statement, confirmed that statement is a read shape, and walked every node
in it checking for a write. The scanner has no way to see any of that — it
is a single-file pattern match, and the validation happens in a different
function, in a different module, several lines earlier. It correctly
identifies the *shape* that is dangerous in general and cannot see that the
shape has already been checked.

**It also could not have been satisfied by doing what it suggests.**
Parameterized queries protect *values* substituted into a fixed query
shape — `WHERE id = %s`. They do not apply here, because the query's
*structure* is the input this tool exists to accept. There is no
values-only parameterization scheme for "run whichever read-only SQL the
caller asks for." The fix for this class of tool is validating the
structure, which is what the rest of this file is for.

**The WARN on `query()`'s definition** (`AGENT-034`, "no input validation in
the function body") is the same blind spot from a different angle: the
function's first line calls `validate_readonly(sql)` inside a `try`/`except`.
A call to an imported function is not a pattern the scanner credits as
validation.

**The two WARNs on hardcoded credentials** are in `tests/conftest.py`: the
default admin DSN (`postgres:postgres@localhost:5432/postgres`, the standard
local/CI Postgres default) and the literal password used for roles the test
suite creates and drops within the same test. Both are correctly identified
as credential-shaped strings; neither is a credential that guards anything —
one points at a throwaway local database, the other lives for the duration
of a single test.

The remaining 11 findings — all `AGENT-041`, all in test fixtures that build
`CREATE SCHEMA` / `GRANT` / `DROP ROLE` statements from `uuid.uuid4()`-derived
names — were already auto-suppressed by the scanner itself.

A pattern scanner is a smoke detector, not a judge. Publishing what it finds
and why is worth more than a clean number would be on its own.

## Install

```bash
pip install -e .
```

## Configure

Requires a connection string, given either as `--dsn` or via
`PG_READONLY_MCP_DSN` — the environment variable exists so a password need
not appear on a command line or in a client config file that might be
committed by accident:

```json
{
  "mcpServers": {
    "pg-readonly-mcp": {
      "command": "pg-readonly-mcp",
      "env": { "PG_READONLY_MCP_DSN": "postgresql://readonly_role:...@host:5432/db" }
    }
  }
}
```

**The role in that connection string needs to hold nothing beyond `SELECT`.**
The server checks this itself and refuses to start otherwise — see
`check_connection_is_readonly` above.

## The tool

One tool, deliberately. A server whose entire value proposition is "we
refuse everything except reads" does not need a second surface to also get
that right.

| Tool | What it does |
|---|---|
| `query` | Runs one SELECT-shaped statement. Parsed and walked before it touches the connection. Capped at `--max-rows` (default 1000) and `--timeout-ms` (default 5000) |

## Tests

**37 tests. 25 need no database and run anywhere — they are
[`guard.py`](src/pg_readonly_mcp/guard.py)'s whole test suite, pure string in,
decision out.** The other 12 need a live Postgres and are integration tests
by design: the point of `check_connection_is_readonly` is what it does
against real role attributes and real grants, and a mocked connection would
pass regardless of what the server actually does against a real one.

```bash
pytest -q --cov=pg_readonly_mcp
```

**CI runs against a real `postgres:16` service container and fails the
build if the database-backed tests report as skipped there** — the same
rule `sweep-mcp` applies to its symlink tests, for the same reason: a test
that quietly does nothing is worse than no test.

Among the 12: a live reproduction of the exact Datadog payload, driven
through the actual MCP tool call rather than through `guard.py` directly —
and an assertion that the target schema still exists afterward, not just
that an exception was raised. Also covered: a write hidden inside a CTE
through the same call path, the row cap, the statement timeout, that a
cancelled query leaves the connection usable for the next one, and that a
role with `CREATEDB` and zero table grants is refused on the role attribute
alone.

Coverage on CI, against a real Postgres: **78%, `guard.py` at 100%.** The gap
in `server.py` is the generic `psycopg.Error` catch-all — nothing in the
suite deliberately provokes a database error that isn't a cancellation — and
`main()`'s argparse and transport wiring, which the suite exercises through
`build_server` directly instead; the transport is the part least worth
mocking and least likely to be where a real mistake hides.

**The first version of this pushed did not pass.** Two bugs surfaced only
once a real Postgres service container ran the suite for the first time,
and neither was visible from the code alone: `SET statement_timeout = %s`
reached Postgres as `SET statement_timeout = $1` and failed to parse, because
`SET` is a utility statement and does not accept a bind parameter the way a
`SELECT` does — every real call to the tool would have failed identically.
Separately, the test fixtures tried to `DROP ROLE` a role that still held
live grants, which Postgres refuses; `DROP OWNED BY` has to run first. Both
are fixed, and the run since is the one these numbers describe. Left in
because a suite that only ever reports success is a suite nobody has watched
fail.

## Layout

```
src/pg_readonly_mcp/
  guard.py    parses and walks the tree. Opens no connection. 135 lines.
  server.py   the MCP tool, the connection check, the timeout and row cap.
tests/
  test_guard.py    25 tests - no database, run anywhere
  test_server.py   12 tests - live Postgres required, CI-enforced
```

`guard.py` knows nothing about MCP or psycopg. If a query is ever refused
for a reason that lives in `server.py` instead, that is a bug — the judgement
belongs one layer down, where it can be tested with a string and nothing
else.

## Licence

MIT.
