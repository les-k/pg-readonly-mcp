"""Fixtures for tests that need a real Postgres.

None of guard.py's tests need any of this -- they are pure string-in,
decision-out and run without a database anywhere. Everything here exists for
server.py's tests, which are deliberately integration tests against a live
connection: the entire point of ``check_connection_is_readonly`` is what it
does against real role attributes and real grants, and a mocked connection
would pass regardless of what the server actually does against one.

Every fixture here skips loudly, with a stated reason, if no Postgres is
reachable -- the same rule ``sweep-mcp``'s symlink fixtures follow, and for
the same reason: a database test that quietly does nothing is worse than no
database test.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator

import psycopg
import pytest

ADMIN_DSN = os.environ.get(
    "PG_READONLY_MCP_TEST_ADMIN_DSN",
    "postgresql://postgres:postgres@localhost:5432/postgres",
)


def _host_and_db() -> str:
    """The host:port/db portion of ADMIN_DSN, so a role's own DSN can reuse it."""
    return ADMIN_DSN.rsplit("@", 1)[-1]


def _dsn_for(role: str, password: str = "test") -> str:
    return f"postgresql://{role}:{password}@{_host_and_db()}"


def _postgres_reachable() -> bool:
    try:
        with psycopg.connect(ADMIN_DSN, connect_timeout=2):
            return True
    except psycopg.OperationalError:
        return False


@pytest.fixture(scope="session")
def postgres_available() -> bool:
    return _postgres_reachable()


@pytest.fixture
def admin_conn(postgres_available: bool) -> Iterator[psycopg.Connection]:
    if not postgres_available:
        pytest.skip(
            f"no Postgres reachable at {ADMIN_DSN!r} -- set "
            "PG_READONLY_MCP_TEST_ADMIN_DSN, or run this suite where a Postgres "
            "service container is available (CI does this; this sandbox does not)"
        )
    conn = psycopg.connect(ADMIN_DSN, autocommit=True)
    try:
        yield conn
    finally:
        conn.close()


@pytest.fixture
def scratch_schema(admin_conn: psycopg.Connection) -> Iterator[str]:
    """A uniquely named schema with one small table, dropped after the test."""
    name = f"test_{uuid.uuid4().hex[:12]}"
    with admin_conn.cursor() as cur:
        cur.execute(f"CREATE SCHEMA {name}")
        cur.execute(f"CREATE TABLE {name}.widgets (id serial PRIMARY KEY, label text NOT NULL)")
        cur.execute(f"INSERT INTO {name}.widgets (label) VALUES ('a'), ('b'), ('c')")
    try:
        yield name
    finally:
        with admin_conn.cursor() as cur:
            cur.execute(f"DROP SCHEMA {name} CASCADE")


def _new_role(admin_conn: psycopg.Connection, *, extra_attrs: str = "") -> str:
    role = f"t_{uuid.uuid4().hex[:12]}"
    with admin_conn.cursor() as cur:
        cur.execute(f"CREATE ROLE {role} LOGIN PASSWORD 'test' {extra_attrs}")
    return role


def _drop_role(admin_conn: psycopg.Connection, role: str) -> None:
    """Drop a role created by these fixtures.

    A role that was ever GRANTed anything cannot be dropped directly --
    Postgres refuses with "cannot be dropped because some objects depend on
    it", because the role's own privileges count as dependent objects.
    ``DROP OWNED BY`` revokes every grant made *to* the role and drops
    anything it owns, and has to run first.
    """
    with admin_conn.cursor() as cur:
        cur.execute(f"DROP OWNED BY {role}")
        cur.execute(f"DROP ROLE {role}")


@pytest.fixture
def readonly_role(admin_conn: psycopg.Connection, scratch_schema: str) -> Iterator[str]:
    """A role granted only SELECT on the scratch schema -- what this server should accept."""
    role = _new_role(admin_conn)
    with admin_conn.cursor() as cur:
        cur.execute(f"GRANT USAGE ON SCHEMA {scratch_schema} TO {role}")
        cur.execute(f"GRANT SELECT ON ALL TABLES IN SCHEMA {scratch_schema} TO {role}")
    try:
        yield role
    finally:
        _drop_role(admin_conn, role)


@pytest.fixture
def writable_role(admin_conn: psycopg.Connection, scratch_schema: str) -> Iterator[str]:
    """A role granted SELECT and INSERT -- what check_connection_is_readonly should refuse."""
    role = _new_role(admin_conn)
    with admin_conn.cursor() as cur:
        cur.execute(f"GRANT USAGE ON SCHEMA {scratch_schema} TO {role}")
        cur.execute(f"GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA {scratch_schema} TO {role}")
    try:
        yield role
    finally:
        _drop_role(admin_conn, role)


@pytest.fixture
def createdb_role(admin_conn: psycopg.Connection) -> Iterator[str]:
    """No table grants at all -- the role attribute alone should be enough to refuse it."""
    role = _new_role(admin_conn, extra_attrs="CREATEDB")
    try:
        yield role
    finally:
        _drop_role(admin_conn, role)


@pytest.fixture
def readonly_conn(readonly_role: str) -> Iterator[psycopg.Connection]:
    conn = psycopg.connect(_dsn_for(readonly_role), autocommit=False)
    try:
        yield conn
    finally:
        conn.close()


@pytest.fixture
def writable_conn(writable_role: str) -> Iterator[psycopg.Connection]:
    conn = psycopg.connect(_dsn_for(writable_role), autocommit=False)
    try:
        yield conn
    finally:
        conn.close()


@pytest.fixture
def createdb_conn(createdb_role: str) -> Iterator[psycopg.Connection]:
    conn = psycopg.connect(_dsn_for(createdb_role), autocommit=False)
    try:
        yield conn
    finally:
        conn.close()
