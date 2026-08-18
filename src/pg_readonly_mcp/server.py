"""The MCP surface: one guarded tool over a Postgres connection.

This layer translates and does connection management, and nothing else. The
decision about whether a piece of SQL is safe to run is made entirely in
:mod:`pg_readonly_mcp.guard`, which knows nothing about MCP or psycopg and can
be tested with plain strings. If this file appears to be deciding whether a
query is safe, that is a bug -- it belongs one layer down.

**Two independent layers, deliberately not one.** The guard refuses anything
that is not a parsed SELECT before a connection is ever touched. Separately,
the connection this server uses is checked at startup and refused if it holds
any privilege beyond SELECT. Either layer alone would have stopped the
disclosed Postgres MCP bypass (https://securitylabs.datadoghq.com/articles/
mcp-vulnerability-case-study-SQL-injection-in-the-postgresql-mcp-server/) --
that one relied on a read-only *transaction* being the only control, with
full-privilege credentials underneath it. Two independent controls mean a
flaw in either one is not by itself enough.

The `SET`/timeout statements this module issues to the connection are
server-controlled integers, never the agent's SQL text, so they sit outside
what the guard needs to check -- confusing the two would be exactly the kind
of self-inflicted gap this server exists to avoid.
"""

from __future__ import annotations

import argparse
import os
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

import psycopg
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from .guard import Denied, validate_readonly

__all__ = ["build_server", "check_connection_is_readonly", "main"]

DEFAULT_MAX_ROWS = 1000
DEFAULT_TIMEOUT_MS = 5000


def check_connection_is_readonly(conn: psycopg.Connection) -> None:
    """Refuse to proceed if the connected role can do more than SELECT.

    This is defense in depth, not the primary control -- the primary control
    is that the guard never lets a write reach a connection at all. This
    exists for the case where it did anyway: a role attribute or a table
    grant that lets the *connection itself* write is a second, independent
    reason the write would still fail.

    Not exhaustive. Postgres privilege can arrive through row-level security
    policies, ownership, or PUBLIC grants on objects this query never
    enumerates, and this checks the two ways a misconfiguration most commonly
    shows up: a role attribute that grants sweeping power outright, and an
    explicit non-SELECT grant on a table this role can see. Stated here
    rather than implied, because a defense-in-depth check that is quietly
    assumed to be complete is worse than one that says plainly what it does
    not cover.
    """
    with conn.cursor() as cur:
        cur.execute(
            "SELECT rolsuper, rolcreatedb, rolcreaterole, rolreplication, rolbypassrls "
            "FROM pg_roles WHERE rolname = current_user"
        )
        row = cur.fetchone()
        if row and any(row):
            flags = ["rolsuper", "rolcreatedb", "rolcreaterole", "rolreplication", "rolbypassrls"]
            active = [name for name, value in zip(flags, row, strict=True) if value]
            raise Denied(
                f"current_user has role attribute(s) {active} -- connect as a role with none "
                "of these, since any one of them is a write path the SQL guard cannot see"
            )

        cur.execute(
            "SELECT DISTINCT table_schema, table_name, privilege_type "
            "FROM information_schema.role_table_grants "
            "WHERE grantee = current_user AND privilege_type != 'SELECT'"
        )
        extra = cur.fetchall()
        if extra:
            named = [f"{schema}.{table}:{priv}" for schema, table, priv in extra[:5]]
            more = f" and {len(extra) - 5} more" if len(extra) > 5 else ""
            raise Denied(
                f"current_user holds non-SELECT grants: {named}{more} -- connect as a role "
                "with SELECT-only access, since a grant here is a write path the SQL guard "
                "cannot see"
            )


@dataclass
class State:
    conn: psycopg.Connection
    max_rows: int
    timeout_ms: int


def build_server(
    conn: psycopg.Connection,
    *,
    max_rows: int = DEFAULT_MAX_ROWS,
    timeout_ms: int = DEFAULT_TIMEOUT_MS,
    version: str = "0.1.0",
) -> MCPServer:
    """Wire the query tool onto an already-open, already-checked connection.

    Exposed separately from :func:`main` so tests can drive the tool against a
    real connection without a transport.
    """
    check_connection_is_readonly(conn)

    state = State(conn=conn, max_rows=max_rows, timeout_ms=timeout_ms)

    server = MCPServer(
        name="pg-readonly-mcp",
        version=version,
        instructions=(
            "Runs read-only SQL against a Postgres database. Every statement is parsed "
            "before it runs; anything that is not a single SELECT-shaped statement is "
            "refused, including a write hidden inside a CTE. The underlying connection "
            "additionally holds no privilege beyond SELECT, as a second, independent check."
        ),
    )

    @server.tool(
        name="query",
        description=(
            "Run one read-only SQL statement and return its rows. Must be exactly one "
            "SELECT-shaped statement (SELECT, UNION, INTERSECT, EXCEPT, or a CTE built "
            "from those) -- anything else, including a write nested inside a WITH clause, "
            f"is refused before it reaches the database. Capped at {max_rows} rows and "
            f"{timeout_ms}ms; a query that would exceed either is stopped, not truncated "
            "silently -- the response says so."
        ),
        annotations=ToolAnnotations(
            title="Run a read-only SQL query",
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
    )
    def query(sql: str) -> dict[str, Any]:
        try:
            validate_readonly(sql)
        except Denied as exc:
            raise Denied(f"refused: {exc}") from exc

        # The integer here is server-controlled, never the agent's SQL text --
        # this SET is not something the guard needs to see. It is also not
        # something psycopg can parameterize: SET is a utility statement, not
        # DML, and Postgres's grammar for it does not accept a bind parameter
        # in the value position -- `SET statement_timeout = %s` reaches the
        # server as `SET statement_timeout = $1` and fails to parse. The int()
        # cast is what keeps direct interpolation safe here: state.timeout_ms
        # is a plain int from the constructor, never a string built from
        # anything the caller sent.
        with state.conn.cursor() as cur:
            cur.execute(f"SET statement_timeout = {int(state.timeout_ms)}")
            try:
                cur.execute(sql)
            except psycopg.errors.QueryCanceled as exc:
                state.conn.rollback()
                raise Denied(f"query exceeded {state.timeout_ms}ms and was cancelled") from exc
            except psycopg.Error as exc:
                state.conn.rollback()
                raise Denied(f"database refused the query: {exc}") from exc

            columns = [desc.name for desc in cur.description] if cur.description else []
            rows = cur.fetchmany(state.max_rows + 1)
            state.conn.rollback()  # never leave a transaction open between calls

        truncated = len(rows) > state.max_rows
        if truncated:
            rows = rows[: state.max_rows]

        return {
            "columns": columns,
            "rows": [list(row) for row in rows],
            "row_count": len(rows),
            "truncated": truncated,
        }

    return server


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pg-readonly-mcp",
        description="MCP server exposing read-only SQL over a parsed, not pattern-matched, guard.",
    )
    parser.add_argument(
        "--dsn",
        default=None,
        help=(
            "Postgres connection string. Falls back to the PG_READONLY_MCP_DSN "
            "environment variable if not given, so a password need not appear on the "
            "command line. Required one way or the other."
        ),
    )
    parser.add_argument("--max-rows", type=int, default=DEFAULT_MAX_ROWS)
    parser.add_argument("--timeout-ms", type=int, default=DEFAULT_TIMEOUT_MS)
    args = parser.parse_args(argv)

    dsn = args.dsn or os.environ.get("PG_READONLY_MCP_DSN")
    if not dsn:
        parser.error(
            "no connection string given: pass --dsn or set PG_READONLY_MCP_DSN. "
            "This server will not default to a local, ambient connection."
        )

    conn = psycopg.connect(dsn, autocommit=False)
    conn.read_only = True  # a third, driver-level statement of intent

    try:
        server = build_server(conn, max_rows=args.max_rows, timeout_ms=args.timeout_ms)
    except Denied as exc:
        conn.close()
        parser.error(str(exc))
        return 2

    server.run(transport="stdio")
    return 0
