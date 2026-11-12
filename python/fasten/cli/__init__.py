"""Debugging CLI.

  fasten dump            print the codes in --catalog files as id,domain,severity
  fasten tail            poll /logs/* from a service with the reader mounted
  fasten doctor          check config, stores and correlation
  fasten tui             multi-pane live view (needs fasten-sdk[tui])
  fasten codes typegen   write type stubs for a yaml catalog
"""
from __future__ import annotations

import argparse
import sys

from ..codes import dump as dump_codes


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="fasten")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_dump = sub.add_parser("dump", help="print id,domain,severity sorted")
    p_dump.add_argument("--catalog", action="append", default=[], metavar="PATH",
                        help="load a *.codes.yaml catalog first (repeatable)")

    p_doctor = sub.add_parser("doctor", help="verify init config + store + correlation wiring")
    p_doctor.add_argument("--json", action="store_true", help="emit results as JSON")

    p_tail = sub.add_parser("tail", help="stream /logs/* from a fasten-mounted service")
    p_tail.add_argument("--url", default="http://localhost:9000/api/v1/logs")
    p_tail.add_argument("--stream", choices=["audit", "sys", "api"], default="audit")
    p_tail.add_argument("--request-id", default=None, help="filter by request_id")
    p_tail.add_argument("--interval", type=float, default=2.0, help="poll interval (sec)")
    p_tail.add_argument("--json", action="store_true", help="emit rows as NDJSON")
    p_tail.add_argument("--token", default=None,
                        help="bearer token for the reader (overrides FASTEN_READER_TOKEN)")

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
    p_tui.add_argument("--token", default=None,
                       help="bearer token for the reader (overrides FASTEN_READER_TOKEN)")

    args = p.parse_args(argv)
    if args.cmd == "dump":
        from ..codes import load as load_catalog
        for path in args.catalog:
            load_catalog(path)
        out = dump_codes()
        if not out:
            sys.stderr.write("fasten dump: no codes registered; pass --catalog PATH\n")
            return 1
        print(out)
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
            token=args.token,
        )
    if args.cmd == "tui":
        from ..tui import run as tui_run
        return tui_run(
            url=args.url,
            stream=args.stream,
            request_id=args.request_id,
            interval=args.interval,
            token=args.token,
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
