"""Integration tests against a real Postgres.

Every test here needs a live connection and skips, with a stated reason, if
one is not reachable -- see ``postgres_available`` in conftest.py. There is
no mock standing in for a database anywhere in this file, because the entire
point of what is being tested is what actually happens against a real one:
a mocked connection would return whatever it was told to and prove nothing
about the real role-attribute and grant checks a genuine Postgres enforces.

CI runs these against a real Postgres service container. This sandbox has
no Postgres installed, so these run for the first time on the runner.
"""

from __future__ import annotations

import asyncio
import json

import psycopg
import pytest
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from pg_readonly_mcp.guard import Denied
from pg_readonly_mcp.server import build_server, check_connection_is_readonly


def call(server: MCPServer, name: str, arguments: dict) -> dict:
    result = asyncio.run(server.call_tool(name, arguments))
    text = "".join(block.text for block in result.content if getattr(block, "text", None))
    return json.loads(text)


def denial(server: MCPServer, name: str, arguments: dict) -> str:
    with pytest.raises(ToolError) as caught:
        asyncio.run(server.call_tool(name, arguments))
    return str(caught.value)


# --------------------------------------------------- the connection-level check


def test_refuses_a_superuser_connection(admin_conn: psycopg.Connection):
    """The admin fixture connects as postgres, which is a superuser by definition."""
    with pytest.raises(Denied, match="rolsuper"):
        check_connection_is_readonly(admin_conn)


def test_refuses_a_role_with_createdb_and_no_table_grants_at_all(
    createdb_conn: psycopg.Connection,
):
    """The role attribute alone is enough to refuse, before any grant is even checked."""
    with pytest.raises(Denied, match="rolcreatedb"):
        check_connection_is_readonly(createdb_conn)


def test_refuses_a_role_with_a_write_grant(writable_conn: psycopg.Connection):
    with pytest.raises(Denied, match="INSERT"):
        check_connection_is_readonly(writable_conn)


def test_accepts_a_select_only_role(readonly_conn: psycopg.Connection):
    check_connection_is_readonly(readonly_conn)  # must not raise


def test_build_server_refuses_to_start_on_a_writable_connection(writable_conn):
    """The same refusal, exercised through the path a real deployment would take."""
    with pytest.raises(Denied, match="INSERT"):
        build_server(writable_conn)


# ------------------------------------------------------------------------- query


def test_query_returns_rows(readonly_conn, scratch_schema):
    server = build_server(readonly_conn)
    sql = f"SELECT label FROM {scratch_schema}.widgets ORDER BY id"
    payload = call(server, "query", {"sql": sql})

    assert payload["columns"] == ["label"]
    assert payload["rows"] == [["a"], ["b"], ["c"]]
    assert payload["row_count"] == 3
    assert payload["truncated"] is False


def test_query_refuses_the_disclosed_bypass_and_the_schema_survives(
    admin_conn, readonly_conn, scratch_schema
):
    """The same payload as test_guard.py, driven through the actual MCP tool call.

    guard.py already proves the text is refused in isolation. This proves the
    refusal is actually wired into the tool an agent would call, and that the
    schema it targets is still there afterward -- the same "assert it still
    exists" shape as sweep-mcp's swapped-symlink test, applied here to a
    schema instead of a directory.
    """
    server = build_server(readonly_conn)

    reason = denial(
        server,
        "query",
        {"sql": f"SELECT 1; COMMIT; DROP SCHEMA {scratch_schema} CASCADE;"},
    )
    assert "expected exactly one statement" in reason

    with admin_conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM information_schema.schemata WHERE schema_name = %s",
            (scratch_schema,),
        )
        assert cur.fetchone() is not None, "the guard must not have let the DROP through"


def test_query_refuses_a_write_hidden_in_a_cte_through_the_tool(readonly_conn, scratch_schema):
    server = build_server(readonly_conn)
    reason = denial(
        server,
        "query",
        {
            "sql": (
                f"WITH x AS (DELETE FROM {scratch_schema}.widgets RETURNING *) "
                "SELECT * FROM x"
            )
        },
    )
    assert "Delete found inside the statement" in reason


def test_query_enforces_the_row_limit(readonly_conn, scratch_schema, admin_conn):
    with admin_conn.cursor() as cur:
        cur.execute(
            f"INSERT INTO {scratch_schema}.widgets (label) "
            "SELECT 'extra-' || n FROM generate_series(1, 20) AS n"
        )

    server = build_server(readonly_conn, max_rows=5)
    payload = call(server, "query", {"sql": f"SELECT * FROM {scratch_schema}.widgets"})

    assert payload["row_count"] == 5
    assert payload["truncated"] is True


def test_query_enforces_the_statement_timeout(readonly_conn):
    server = build_server(readonly_conn, timeout_ms=200)
    reason = denial(server, "query", {"sql": "SELECT pg_sleep(5)"})
    assert "exceeded" in reason
    assert "200" in reason


def test_query_is_usable_again_after_a_timeout(readonly_conn):
    """A cancelled query must not leave the connection's transaction wedged."""
    server = build_server(readonly_conn, timeout_ms=200)
    denial(server, "query", {"sql": "SELECT pg_sleep(5)"})

    payload = call(server, "query", {"sql": "SELECT 1 AS ok"})
    assert payload["rows"] == [[1]]


def test_query_refuses_a_plain_write_before_touching_the_database(readonly_conn, scratch_schema):
    server = build_server(readonly_conn)
    reason = denial(
        server, "query", {"sql": f"DELETE FROM {scratch_schema}.widgets"}
    )
    assert "Delete is not a read" in reason

    payload = call(server, "query", {"sql": f"SELECT count(*) FROM {scratch_schema}.widgets"})
    assert payload["rows"] == [[3]], "the delete must never have reached the database"
