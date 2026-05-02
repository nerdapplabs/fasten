"""
Transport — where log lines fan out.

Bundled:
  - stdout       (default; docker log driver captures + rotates)

Future:
  - filerotate   (nginx-style per-service files, SIGUSR1 reopen)
"""
from __future__ import annotations

from .stdout import StdoutTransport

__all__ = ["StdoutTransport"]
