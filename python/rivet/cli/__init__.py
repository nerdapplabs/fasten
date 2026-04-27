"""
CLI helpers (debug utilities, not a product):
  - rivet dump    — print registered codes + meta (feeds CI consistency gate)
  - rivet tail    — stream /logs/* from a local/remote rivet-mounted service
  - rivet doctor  — verify init config + store + correlation wiring
  - rivet tui     — multi-pane live feed (requires rivet[tui])
"""
from __future__ import annotations

import argparse
import sys

from ..codes import dump as dump_codes


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="rivet")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("dump", help="print id,domain,severity sorted")

    p_doctor = sub.add_parser("doctor", help="verify init config + store + correlation wiring")
    p_doctor.add_argument("--json", action="store_true", help="emit results as JSON")

    p_tail = sub.add_parser("tail", help="stream /logs/* from a rivet-mounted service")
    p_tail.add_argument("--url", default="http://localhost:9000/api/v1/logs")
    p_tail.add_argument("--stream", choices=["audit", "sys", "api"], default="audit")
    p_tail.add_argument("--request-id", default=None, help="filter by request_id")
    p_tail.add_argument("--interval", type=float, default=2.0, help="poll interval (sec)")
    p_tail.add_argument("--json", action="store_true", help="emit rows as NDJSON")
    p_tail.add_argument("--key", default=None, help="X-Rivet-Key value (overrides RIVET_READER_KEY)")

    p_tui = sub.add_parser("tui", help="multi-pane live audit/sys/api feed")
    p_tui.add_argument("--url", default="http://localhost:9000/api/v1/logs")
    p_tui.add_argument("--stream", choices=["audit", "sys", "api"], default="audit",
                       help="primary pane")
    p_tui.add_argument("--request-id", default=None, help="filter by request_id")
    p_tui.add_argument("--interval", type=float, default=2.0, help="poll interval (sec)")

    args = p.parse_args(argv)
    if args.cmd == "dump":
        print(dump_codes())
        return 0
    if args.cmd == "doctor":
        from ._doctor import run as doctor_run
        return doctor_run(as_json=args.json)
    if args.cmd == "tail":
        from ._tail import run as tail_run
        return tail_run(
            url=args.url,
            stream=args.stream,
            request_id=args.request_id,
            interval=args.interval,
            as_json=args.json,
            api_key=args.key,
        )
    if args.cmd == "tui":
        from ..tui import run as tui_run
        return tui_run(
            url=args.url,
            stream=args.stream,
            request_id=args.request_id,
            interval=args.interval,
        )
    return 1


if __name__ == "__main__":
    sys.exit(main())
