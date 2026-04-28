"""
Rich-based multi-pane live feed.

Layout:
    ┌─ fasten · audit · http://… ─────────────────────────────────────┐
    │ AUDIT (primary pane) — code · actor · target · request_id       │
    ├──────────────────────────────────┬──────────────────────────────┤
    │ SYS  (compact)                   │ API  (compact)               │
    └─ ctrl-c quit · primary=audit · interval=2.0s ───────────────────┘

The primary pane shows full rows; the other two stay compact. A
`--request-id` filter carries across all three panes — that's the whole
point of fasten.

v0.1 is a polling read-only view (Rich keeps the dep tree minimal). All
controls are CLI flags; non-blocking keystrokes (stream toggle, filter
prompt, drill-down) land in v0.2 once we move to Textual.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


DEFAULT_URL = "http://localhost:9000/api/v1/logs"
STREAMS = ("audit", "sys", "api")


def _fetch(base_url: str, stream: str, request_id: str | None, limit: int) -> list[dict[str, Any]]:
    """GET /logs/{stream}?... — returns rows, or [] on connection error."""
    params: dict[str, str] = {"limit": str(limit)}
    if request_id:
        params["request_id"] = request_id
    url = f"{base_url.rstrip('/')}/{stream}?{urllib.parse.urlencode(params)}"
    try:
        with urllib.request.urlopen(url, timeout=2.0) as resp:
            payload = json.loads(resp.read())
        rows = payload.get("rows") or []
        return rows if isinstance(rows, list) else []
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return []


def _render_audit(rows: list[dict[str, Any]], primary: bool) -> Any:
    from rich.table import Table

    title = "AUDIT" + (" · primary" if primary else "")
    t = Table(title=title, expand=True, show_lines=False, padding=(0, 1))
    t.add_column("ts", style="dim", no_wrap=True, width=12)
    t.add_column("code", style="bold")
    t.add_column("actor", style="cyan")
    t.add_column("target", style="dim")
    t.add_column("req", style="dim", no_wrap=True, width=10)
    for r in rows[: 25 if primary else 6]:
        ts = str(r.get("timestamp") or r.get("ts") or "")[-12:-3] or "—"
        t.add_row(
            ts,
            str(r.get("code") or "—"),
            str(r.get("actor") or "—"),
            str(r.get("target") or "—"),
            str(r.get("request_id") or "—")[:10],
        )
    if not rows:
        t.add_row("—", "(no rows)", "", "", "")
    return t


def _render_log(rows: list[dict[str, Any]], label: str, primary: bool) -> Any:
    from rich.table import Table

    title = f"{label.upper()}" + (" · primary" if primary else "")
    t = Table(title=title, expand=True, show_lines=False, padding=(0, 1))
    t.add_column("ts", style="dim", no_wrap=True, width=12)
    t.add_column("level" if label == "sys" else "method", no_wrap=True, width=6)
    t.add_column("message" if label == "sys" else "path")
    t.add_column("req", style="dim", no_wrap=True, width=10)
    cap = 25 if primary else 6
    for r in rows[:cap]:
        ts = str(r.get("timestamp") or r.get("ts") or "")[-12:-3] or "—"
        if label == "sys":
            t.add_row(
                ts,
                str(r.get("level") or "info"),
                str(r.get("message") or r.get("msg") or "—"),
                str(r.get("request_id") or "—")[:10],
            )
        else:
            t.add_row(
                ts,
                str(r.get("method") or "GET"),
                str(r.get("path") or "—"),
                str(r.get("request_id") or "—")[:10],
            )
    if not rows:
        t.add_row("—", "—", "(no rows)", "")
    return t


def _build_view(
    base_url: str,
    primary: str,
    request_id: str | None,
    interval: float,
) -> Any:
    from rich.layout import Layout
    from rich.panel import Panel

    audit_rows = _fetch(base_url, "audit", request_id, 50)
    sys_rows = _fetch(base_url, "sys", request_id, 50)
    api_rows = _fetch(base_url, "api", request_id, 50)

    layout = Layout()
    layout.split_column(
        Layout(name="header", size=1),
        Layout(name="body"),
        Layout(name="footer", size=1),
    )

    title = f"fasten tui · {base_url}"
    if request_id:
        title += f"  ·  req={request_id}"
    layout["header"].update(Panel.fit(title, style="bold blue", border_style="dim"))

    if primary == "audit":
        layout["body"].split_column(
            Layout(_render_audit(audit_rows, True), ratio=3),
            Layout(name="bottom", ratio=2),
        )
        layout["body"]["bottom"].split_row(
            Layout(_render_log(sys_rows, "sys", False)),
            Layout(_render_log(api_rows, "api", False)),
        )
    elif primary == "sys":
        layout["body"].split_column(
            Layout(_render_log(sys_rows, "sys", True), ratio=3),
            Layout(name="bottom", ratio=2),
        )
        layout["body"]["bottom"].split_row(
            Layout(_render_audit(audit_rows, False)),
            Layout(_render_log(api_rows, "api", False)),
        )
    else:
        layout["body"].split_column(
            Layout(_render_log(api_rows, "api", True), ratio=3),
            Layout(name="bottom", ratio=2),
        )
        layout["body"]["bottom"].split_row(
            Layout(_render_audit(audit_rows, False)),
            Layout(_render_log(sys_rows, "sys", False)),
        )

    hint = (
        f"ctrl-c quit · primary={primary} · interval={interval:.1f}s · "
        f"audit:{len(audit_rows)} sys:{len(sys_rows)} api:{len(api_rows)}"
    )
    layout["footer"].update(Panel.fit(hint, style="dim", border_style="dim"))
    return layout


def run(
    url: str = DEFAULT_URL,
    stream: str = "audit",
    request_id: str | None = None,
    interval: float = 2.0,
) -> int:
    try:
        from rich.console import Console
        from rich.live import Live
    except ImportError:
        sys.stderr.write(
            "fasten TUI requires the `rich` package — install via `pip install fasten[tui]`\n"
        )
        return 2

    if stream not in STREAMS:
        sys.stderr.write(f"unknown stream {stream!r} — choose from {STREAMS}\n")
        return 2

    console = Console()
    try:
        with Live(
            _build_view(url, stream, request_id, interval),
            refresh_per_second=4,
            screen=True,
            console=console,
        ) as live:
            while True:
                time.sleep(interval)
                live.update(_build_view(url, stream, request_id, interval))
    except KeyboardInterrupt:
        return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="fasten-tui", description="fasten bundled TUI")
    p.add_argument("--url", default=DEFAULT_URL, help="reader base URL")
    p.add_argument("--stream", choices=STREAMS, default="audit", help="primary pane")
    p.add_argument("--request-id", default=None, help="filter by request_id")
    p.add_argument("--interval", type=float, default=2.0, help="poll interval (sec)")
    args = p.parse_args(argv)
    return run(
        url=args.url,
        stream=args.stream,
        request_id=args.request_id,
        interval=args.interval,
    )
