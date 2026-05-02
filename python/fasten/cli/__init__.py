"""
CLI helpers (debug utilities, not a product):
  - fasten dump    — print registered codes + meta (feeds CI consistency gate)
  - fasten tail    — stream /logs/* from a local/remote fasten-mounted service
  - fasten doctor  — verify init config + store + correlation wiring
  - fasten tui     — multi-pane live feed (requires fasten[tui])
  - fasten codes typegen — emit IDE / type-checker stubs from a yaml catalog
"""
from __future__ import annotations

import argparse
import sys

from ..codes import dump as dump_codes


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="fasten")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("dump", help="print id,domain,severity sorted")

    p_doctor = sub.add_parser("doctor", help="verify init config + store + correlation wiring")
    p_doctor.add_argument("--json", action="store_true", help="emit results as JSON")

    p_tail = sub.add_parser("tail", help="stream /logs/* from a fasten-mounted service")
    p_tail.add_argument("--url", default="http://localhost:9000/api/v1/logs")
    p_tail.add_argument("--stream", choices=["audit", "sys", "api"], default="audit")
    p_tail.add_argument("--request-id", default=None, help="filter by request_id")
    p_tail.add_argument("--interval", type=float, default=2.0, help="poll interval (sec)")
    p_tail.add_argument("--json", action="store_true", help="emit rows as NDJSON")
    p_tail.add_argument("--key", default=None, help="X-Fasten-Key value (overrides FASTEN_READER_KEY)")

    # `fasten codes typegen <yaml> --lang <lang>`
    p_codes = sub.add_parser("codes", help="catalog tools (typegen, ...)")
    codes_sub = p_codes.add_subparsers(dest="codes_cmd", required=True)
    p_typegen = codes_sub.add_parser(
        "typegen",
        help="emit IDE/type-checker stubs from a yaml catalog "
             "(.pyi / .d.ts / .go / .rs)",
    )
    p_typegen.add_argument("yaml", help="path to a *.codes.yaml file")
    p_typegen.add_argument(
        "--lang",
        choices=["python", "py", "ts", "typescript", "go", "rust", "rs"],
        required=True,
        help="target language for the stub",
    )
    p_typegen.add_argument(
        "-o", "--out",
        default=None,
        help="write to file (default: stdout). '-' is also stdout.",
    )

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
    if args.cmd == "codes":
        if args.codes_cmd == "typegen":
            from ._typegen import run as typegen_run
            return typegen_run(
                yaml_path=args.yaml,
                lang=args.lang,
                out=args.out,
            )
        return 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
