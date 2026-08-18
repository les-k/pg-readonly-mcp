"""Pure tests for the SQL guard. No database anywhere in this file.

Every case here is a plain string in, a decision out. That is deliberate: the
guard's whole job is to decide from the text alone, before any connection
exists, so its tests should be able to prove that without needing one either.
"""

from __future__ import annotations

import pytest

from pg_readonly_mcp.guard import Denied, validate_readonly


def allows(sql: str) -> None:
    validate_readonly(sql)  # must not raise


def denies(sql: str, *, match: str) -> None:
    with pytest.raises(Denied, match=match):
        validate_readonly(sql)


# ---------------------------------------------------------------- the reads


def test_allows_a_plain_select():
    allows("SELECT * FROM users")


def test_allows_a_select_with_a_trailing_semicolon():
    allows("SELECT * FROM users;")


def test_allows_union():
    allows("SELECT id FROM users UNION SELECT id FROM admins")


def test_allows_intersect():
    allows("SELECT id FROM users INTERSECT SELECT id FROM admins")


def test_allows_except():
    allows("SELECT id FROM users EXCEPT SELECT id FROM admins")


def test_allows_a_read_only_cte():
    allows(
        "WITH recent AS (SELECT * FROM orders WHERE created > now() - interval '1 day') "
        "SELECT * FROM recent"
    )


def test_allows_a_comment_that_looks_like_a_second_statement():
    """The text after -- is a comment, not a second statement; the parser knows this."""
    allows("SELECT 1 -- ; DROP TABLE x")


# --------------------------------------------------------- the named attack


def test_denies_the_disclosed_postgres_mcp_bypass():
    """https://securitylabs.datadoghq.com/articles/mcp-vulnerability-case-study-SQL-injection-in-the-postgresql-mcp-server/

    The reference Postgres MCP server wrapped queries in a read-only
    *transaction*. This payload ends that transaction early with COMMIT and
    runs the DROP afterward at full privilege. It never gets that far here,
    because it is three statements and this guard only ever allows one.
    """
    denies(
        "SELECT 1; COMMIT; DROP SCHEMA public CASCADE;",
        match="expected exactly one statement, found 3",
    )


def test_denies_a_write_hidden_inside_a_cte():
    """Postgres allows a CTE to carry a data-modifying statement.

    At the outer level this is a SELECT -- a check that only looks at the
    outer statement shape would let it through. The guard is denied by the
    DELETE nested inside, found by walking the whole tree.
    """
    denies(
        "WITH x AS (DELETE FROM t RETURNING *) SELECT * FROM x",
        match="Delete found inside the statement",
    )


def test_denies_an_update_hidden_inside_a_cte():
    denies(
        "WITH x AS (UPDATE t SET flag = true RETURNING *) SELECT * FROM x",
        match="Update found inside the statement",
    )


def test_denies_an_insert_hidden_inside_a_cte():
    denies(
        "WITH x AS (INSERT INTO t (n) VALUES (1) RETURNING *) SELECT * FROM x",
        match="Insert found inside the statement",
    )


# ----------------------------------------------------- plain, undisguised writes


@pytest.mark.parametrize(
    ("sql", "kind"),
    [
        ("DROP TABLE users", "Drop"),
        ("DELETE FROM users", "Delete"),
        ("UPDATE users SET admin = true", "Update"),
        ("INSERT INTO users (name) VALUES ('x')", "Insert"),
        ("ALTER TABLE users ADD COLUMN x INT", "Alter"),
        ("CREATE TABLE x (id INT)", "Create"),
        ("TRUNCATE users", "TruncateTable"),
        ("GRANT SELECT ON users TO PUBLIC", "Grant"),
    ],
)
def test_denies_plain_writes_and_ddl(sql: str, kind: str):
    denies(sql, match=f"{kind} is not a read")


# --------------------------------------------------- session and transaction control


def test_denies_set():
    """SET could alter session state -- including the timeout this server itself sets."""
    denies("SET statement_timeout = 0", match="Set is not a read")


def test_denies_commit_alone():
    denies("COMMIT", match="Commit is not a read")


def test_denies_an_unrecognised_statement_shape():
    """Whatever this is, sqlglot has no specific rule for it -- refused, not guessed at."""
    denies("VACUUM users", match="not a read")


# -------------------------------------------------------------------- malformed input


def test_denies_empty_query():
    denies("", match="empty query")


def test_denies_unparseable_garbage():
    denies("SELECT FROM WHERE ;;; garbage((()", match="could not parse")


def test_denies_a_second_statement_even_when_the_first_is_a_select():
    denies("SELECT 1; SELECT 2;", match="found 2")
