"""A read-only Postgres MCP server that parses SQL rather than pattern-matching it."""

from __future__ import annotations

from .guard import Denied, validate_readonly

__version__ = "0.1.1"

__all__ = ["Denied", "validate_readonly", "__version__"]
