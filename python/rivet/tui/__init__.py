"""
rivet TUI — bundled terminal UI for the audit + log reader.

Companion to the `rivet` CLI. Same idea as `rivet tail` but with a live
multi-pane view: audit rows on top, syslog and API-log streams below,
filter row at the bottom.

  - SSH-friendly. Runs over slow links / on industrial Linux hosts where
    no GUI is permitted.
  - Talks to any rivet-mounted service via the same `/api/v1/logs/*`
    routes the CLI uses — local SQLite, edge-manager, or rivet Cloud.
  - Optional install: `pip install rivet[tui]` pulls in `rich`.

v0.1 polls every `--interval` seconds. Real SSE / long-poll lands in v0.2
once the upstream reader exposes a streaming endpoint.

Usage:
    rivet tui                                  # default endpoint
    rivet tui --url http://edge:9000/api/v1/logs
    rivet tui --request-id a1b2c3d4            # follow one trail
    rivet tui --stream audit --interval 1.0
"""
from __future__ import annotations

from .app import run

__all__ = ["run"]
