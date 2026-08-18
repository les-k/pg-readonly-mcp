"""The part that says no.

Everything this server refuses lives here, and none of it opens a database
connection -- the whole judgement is made by parsing the SQL text, so it can
be tested with plain strings, without a database, a client, or an agent in
the loop.

This module exists because of a disclosed, specific failure: the reference
Postgres MCP server enforced "read-only" by wrapping each query in a
read-only *transaction*, then accepted semicolon-delimited multi-statement
input. ``SELECT 1; COMMIT; DROP SCHEMA public CASCADE;`` ends the read-only
transaction with the COMMIT and runs the DROP at full session privilege.
See https://securitylabs.datadoghq.com/articles/mcp-vulnerability-case-study-SQL-injection-in-the-postgresql-mcp-server/

A transaction wrapper is a runtime property of *how a query is executed*. It
says nothing about what the query *is*, which is why it was possible to talk
your way out of it. This module checks the second thing instead: it parses
the text into a real syntax tree and refuses to let anything but a read
reach a connection at all, so there is no transaction boundary left to
escape from.
"""

from __future__ import annotations

import sqlglot
from sqlglot import exp

__all__ = ["Denied", "validate_readonly"]


class Denied(Exception):
    """A query was refused.

    Carries the reason as prose because the caller is a language model, and
    "denied" alone gives it nothing to correct.
    """


# Every node type that means a write, a schema change, a transaction-control
# statement, a session-state change, or a session command outright -- plus
# Command, sqlglot's catch-all for a statement shape it has no specific rule
# for. An unrecognised statement is refused for the same reason an unlinkable
# path is refused elsewhere: guessing that something unfamiliar is safe is
# how a guard gets bypassed by a shape nobody thought to name.
_FORBIDDEN: tuple[type[exp.Expression], ...] = (
    exp.Insert,
    exp.Update,
    exp.Delete,
    exp.Drop,
    exp.Create,
    exp.Alter,
    exp.TruncateTable,
    exp.Commit,
    exp.Rollback,
    exp.Transaction,
    exp.Grant,
    exp.Merge,
    exp.Set,
    exp.Copy,
    exp.Execute,
    exp.Cache,
    exp.Uncache,
    exp.Refresh,
    exp.Comment,
    exp.Use,
    exp.Analyze,
    exp.LoadData,
    exp.Command,
)

# The only shapes a statement is allowed to take at the outer level.
_READ_SHAPES: tuple[type[exp.Expression], ...] = (
    exp.Select,
    exp.Union,
    exp.Intersect,
    exp.Except,
)


def validate_readonly(sql: str) -> exp.Expression:
    """Parse ``sql`` and confirm it is exactly one read-only statement.

    Returns the parsed statement, so a caller executes what was actually
    validated rather than re-parsing the same text a second time on a
    separate path that could in principle disagree with this one.

    Three checks, in the order that matches what each one is for:

    1. **Exactly one statement.** ``sqlglot.parse`` splits on
       statement-terminating semicolons the way a database driver would, so
       the disclosed bypass payload above becomes three statements and is
       refused before any of them reach a connection -- there is no
       transaction for a second statement to ride in after, because there is
       no route to a second statement at all.

    2. **The outer statement is a read shape.** Rejects ``DROP TABLE users``
       outright, before looking any deeper.

    3. **No forbidden node anywhere in the tree.** This is the check that (2)
       alone cannot do. ``WITH x AS (DELETE FROM t RETURNING *) SELECT * FROM
       x`` is, at the outer level, a Select -- Postgres allows a CTE to carry
       a data-modifying statement, and a check that only looks at the outer
       shape misses this completely. Walking every node closes it: the
       DELETE is still a DELETE however many levels down it sits, and it is
       found regardless of nesting.
    """
    try:
        parsed = [stmt for stmt in sqlglot.parse(sql, read="postgres") if stmt is not None]
    except Exception as exc:  # sqlglot's own ParseError and its subclasses
        raise Denied(f"could not parse as SQL, refusing to guess what it means: {exc}") from exc

    if not parsed:
        raise Denied("empty query")

    if len(parsed) > 1:
        raise Denied(
            f"expected exactly one statement, found {len(parsed)} -- this is the exact shape "
            "of the disclosed bypass, where a later statement rides in after the first"
        )

    statement = parsed[0]

    if not isinstance(statement, _READ_SHAPES):
        raise Denied(
            f"{type(statement).__name__} is not a read; only SELECT-shaped queries run here"
        )

    for node in statement.find_all(exp.Expression):
        if isinstance(node, _FORBIDDEN):
            raise Denied(
                f"{type(node).__name__} found inside the statement -- refused even though the "
                "outer statement is a SELECT, because a write nested in a CTE is still a write"
            )

    return statement
