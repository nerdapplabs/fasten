"""Terminal UI for the reader: like `fasten tail`, with audit rows on top
and the sys and api streams below. Polls the same /api/v1/logs routes every
``--interval`` seconds. Needs ``pip install fasten[tui]``.

    fasten tui                                  # default endpoint
    fasten tui --url http://edge:9000/api/v1/logs
    fasten tui --request-id a1b2c3d4            # follow one trail
    fasten tui --stream audit --interval 1.0
"""
from __future__ import annotations

from .app import run

__all__ = ["run"]
