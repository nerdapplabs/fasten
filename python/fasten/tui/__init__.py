"""
fasten TUI — bundled terminal UI for the audit + log reader.

Companion to the `fasten` CLI. Same idea as `fasten tail` but with a live
multi-pane view: audit rows on top, syslog and API-log streams below,
filter row at the bottom.

  - SSH-friendly. Runs over slow links / on industrial Linux hosts where
    no GUI is permitted.
  - Talks to any fasten-mounted service via the same `/api/v1/logs/*`
    routes the CLI uses — local SQLite, an upstream aggregator, or fasten Cloud.
  - Optional install: `pip install fasten[tui]` pulls in `rich`.

v0.1 polls every `--interval` seconds. Real SSE / long-poll lands in v0.2
once the upstream reader exposes a streaming endpoint.

Usage:
    fasten tui                                  # default endpoint
    fasten tui --url http://edge:9000/api/v1/logs
    fasten tui --request-id a1b2c3d4            # follow one trail
    fasten tui --stream audit --interval 1.0
"""
from __future__ import annotations

from .app import run

__all__ = ["run"]
