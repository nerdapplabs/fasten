"""
Rich-based multi-pane live feed with interactive controls.

Layout:
    ┌─ fasten tui · http://… · req=<id|all> ─────────────────────────────┐
    │ AUDIT (primary pane) — code · actor · target · request_id           │
    ├──────────────────────────────────┬──────────────────────────────────┤
    │ SYS  (compact)                   │ API  (compact)                   │
    └─ [L] live ● · [/] filter · [tab] pane · [q] quit ─────────────────┘

Interactive controls (no mouse needed; works over SSH):
  L / space  — toggle live polling on/off  (default: on)
  /          — open request_id picker (fuzzy search over recent IDs;
               Esc or blank = clear filter; pre-selects current filter)
  Tab        — rotate primary pane: audit → sys → api → audit
  q / Ctrl-C — quit

request_id picker UX:
  - Fetches ≤200 recent audit rows, extracts unique request_ids.
  - Type to filter (prefix/substring); ↑ ↓ to move cursor; Enter to select.
  - Esc or empty Enter → clear filter (watch all streams).
  - If --request-id <id> is given via arg, that ID is pre-selected in the
    picker (user can still change it from inside the live view).
"""
from __future__ import annotations

import argparse
import json
import queue
import select
import sys
import termios
import threading
import time
import tty
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


DEFAULT_URL = "http://localhost:9000/api/v1/logs"
STREAMS = ("audit", "sys", "api")


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _fetch(base_url: str, stream: str, request_id: str | None, limit: int) -> list[dict[str, Any]]:
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


def _fetch_recent_ids(base_url: str, limit: int = 200) -> list[str]:
    rows = _fetch(base_url, "audit", None, limit)
    seen: dict[str, None] = {}
    for r in rows:
        rid = r.get("request_id")
        if rid and isinstance(rid, str):
            seen[rid] = None
    return list(seen.keys())


# ── Terminal key reader (background thread) ───────────────────────────────────

def _key_reader(key_q: "queue.Queue[bytes]", stop: threading.Event) -> None:
    """Read raw keypresses and push them to key_q.  Runs in a daemon thread."""
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        while not stop.is_set():
            r, _, _ = select.select([sys.stdin], [], [], 0.05)
            if r:
                ch = sys.stdin.buffer.read1(4)  # type: ignore[attr-defined]
                if ch:
                    key_q.put(ch)
    except Exception:
        pass
    finally:
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
        except Exception:
            pass


# ── Interactive request_id picker ─────────────────────────────────────────────

def _run_picker(
    base_url: str,
    current: str | None,
    all_ids: list[str] | None = None,
) -> str | None:
    """
    Blocking picker: suspends Live output, runs a search widget, returns selected ID or None.
    all_ids: supply cached list or None to re-fetch.
    """
    try:
        from rich.console import Console
        from rich.live import Live
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text
    except ImportError:
        return current

    console = Console()
    if all_ids is None:
        console.print("[dim]fetching request IDs…[/]", end="\r")
        all_ids = _fetch_recent_ids(base_url)

    if not all_ids:
        console.print("[dim]No audit rows available — filter cleared.[/]")
        time.sleep(0.6)
        return None

    # Pre-populate query with the current filter so user can refine it.
    query = current or ""
    # Find cursor position in filtered list.
    def _filtered() -> list[str]:
        q = query.lower()
        return [r for r in all_ids if q in r.lower()] if q else list(all_ids)

    filtered = _filtered()
    cursor = 0
    if current and current in filtered:
        cursor = filtered.index(current)

    def _render(q: str, cur: int, fil: list[str]) -> Panel:
        t = Table(show_header=False, expand=True, show_lines=False, padding=(0, 1), box=None)
        t.add_column("", width=2)
        t.add_column("request_id")
        for i, rid in enumerate(fil[:22]):
            style = "bold cyan" if i == cur else ""
            marker = "▶" if i == cur else " "
            t.add_row(marker, Text(rid, style=style))
        if not fil:
            t.add_row("", Text("(no matches)", style="dim"))
        cursor_block = "▌"
        return Panel(
            t,
            title=(
                f"[bold blue]request_id filter[/]  [bold]{q}[/][blink]{cursor_block}[/blink]  "
                f"[dim]{len(fil)}/{len(all_ids)} matches[/]"
            ),
            subtitle="[dim]↑↓ move · type to search · Enter select · Esc clear filter[/]",
            border_style="blue",
        )

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    selected: str | None = current
    escaped = False

    try:
        tty.setraw(fd)
        with Live(_render(query, cursor, filtered), console=console,
                  refresh_per_second=20, screen=False) as live:
            while True:
                r, _, _ = select.select([sys.stdin], [], [], 0.05)
                if not r:
                    continue
                ch = sys.stdin.buffer.read1(4)  # type: ignore[attr-defined]
                if not ch:
                    continue

                if ch in (b"\x1b", b"\x03"):      # Esc / Ctrl-C → clear filter
                    selected = None
                    escaped = True
                    break
                elif ch == b"\r":                   # Enter → commit selection
                    fil = _filtered()
                    selected = fil[cursor] if fil else None
                    break
                elif ch == b"\x1b[A":               # Up
                    cursor = max(0, cursor - 1)
                elif ch == b"\x1b[B":               # Down
                    fil = _filtered()
                    cursor = min(len(fil) - 1, max(0, cursor + 1))
                elif ch == b"\x7f":                 # Backspace
                    query = query[:-1]
                    cursor = 0
                elif len(ch) == 1 and 0x20 <= ch[0] < 0x7f:
                    query += ch.decode()
                    cursor = 0

                filtered = _filtered()
                live.update(_render(query, cursor, filtered))
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)

    if escaped:
        console.print("[dim]Filter cleared — watching all streams.[/]")
    elif selected:
        console.print(f"[bold cyan]filter:[/] {selected}")
    else:
        console.print("[dim]No selection — watching all streams.[/]")
    time.sleep(0.25)
    return selected


# ── Renderers ─────────────────────────────────────────────────────────────────

def _render_audit(rows: list[dict[str, Any]], primary: bool) -> Any:
    from rich.table import Table

    t = Table(title="AUDIT" + (" · primary" if primary else ""),
              expand=True, show_lines=False, padding=(0, 1))
    t.add_column("ts",     style="dim",  no_wrap=True, width=12)
    t.add_column("code",   style="bold")
    t.add_column("actor",  style="cyan")
    t.add_column("target", style="dim")
    t.add_column("req",    style="dim",  no_wrap=True, width=10)
    for r in rows[: 25 if primary else 6]:
        ts = str(r.get("timestamp") or "")[-12:-3] or "—"
        t.add_row(ts,
                  str(r.get("code")   or "—"),
                  str(r.get("actor")  or "—"),
                  str(r.get("target") or "—"),
                  str(r.get("request_id") or "—")[:10])
    if not rows:
        t.add_row("—", "(no rows)", "", "", "")
    return t


def _render_log(rows: list[dict[str, Any]], label: str, primary: bool) -> Any:
    from rich.table import Table

    t = Table(title=f"{label.upper()}" + (" · primary" if primary else ""),
              expand=True, show_lines=False, padding=(0, 1))
    t.add_column("ts",    style="dim", no_wrap=True, width=12)
    t.add_column("level" if label == "sys" else "method", no_wrap=True, width=6)
    t.add_column("message" if label == "sys" else "path")
    t.add_column("req",   style="dim", no_wrap=True, width=10)
    for r in rows[: 25 if primary else 6]:
        ts = str(r.get("timestamp") or "")[-12:-3] or "—"
        if label == "sys":
            t.add_row(ts, str(r.get("level") or "info"),
                      str(r.get("message") or r.get("msg") or "—"),
                      str(r.get("request_id") or "—")[:10])
        else:
            t.add_row(ts, str(r.get("method") or "GET"),
                      str(r.get("path") or "—"),
                      str(r.get("request_id") or "—")[:10])
    if not rows:
        t.add_row("—", "—", "(no rows)", "")
    return t


def _build_view(
    base_url: str,
    primary: str,
    request_id: str | None,
    interval: float,
    live: bool,
    audit_rows: list[dict],
    sys_rows:   list[dict],
    api_rows:   list[dict],
) -> Any:
    from rich.layout import Layout
    from rich.panel import Panel

    title = f"[bold blue]fasten tui[/] · {base_url}"
    rid_label = f"[cyan]{request_id}[/]" if request_id else "[dim]all[/]"
    title += f"  req={rid_label}"

    layout = Layout()
    layout.split_column(
        Layout(name="header", size=1),
        Layout(name="body"),
        Layout(name="footer", size=1),
    )
    layout["header"].update(Panel.fit(title, border_style="blue"))

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
            Layout(_render_log(api_rows,  "api", False)),
        )
    else:
        layout["body"].split_column(
            Layout(_render_log(api_rows, "api", True), ratio=3),
            Layout(name="bottom", ratio=2),
        )
        layout["body"]["bottom"].split_row(
            Layout(_render_audit(audit_rows, False)),
            Layout(_render_log(sys_rows,  "sys", False)),
        )

    live_icon  = "[bold green]●[/] live" if live else "[dim]○ paused[/]"
    rid_hint   = request_id or "all"
    footer_txt = (
        f"[L] {live_icon}  [/] [dim]·[/]  "
        f"[bold][/][/] filter=[bold]{rid_hint}[/]  [dim]·[/]  "
        f"[dim][tab] pane={primary} · [q] quit · "
        f"audit:{len(audit_rows)} sys:{len(sys_rows)} api:{len(api_rows)} "
        f"· Δ{interval:.1f}s[/]"
    )
    layout["footer"].update(Panel.fit(footer_txt, border_style="dim"))
    return layout


# ── Main loop ─────────────────────────────────────────────────────────────────

def run(
    url: str = DEFAULT_URL,
    stream: str = "audit",
    request_id: str | None = None,
    interval: float = 2.0,
    no_pick: bool = False,
) -> int:
    try:
        from rich.console import Console
        from rich.live import Live
    except ImportError:
        sys.stderr.write(
            "fasten TUI requires `rich` — install via `pip install fasten[tui]`\n"
        )
        return 2

    if stream not in STREAMS:
        sys.stderr.write(f"unknown stream {stream!r} — choose from {STREAMS}\n")
        return 2

    if not sys.stdin.isatty():
        no_pick = True  # non-interactive (piped, CI)

    # On first launch with no --request-id: show picker.
    # If --request-id given: skip picker (but user can press / to change it).
    if request_id is None and not no_pick:
        try:
            request_id = _run_picker(url, current=None)
        except Exception:
            pass

    # Cache of recent IDs for the in-session picker (refreshed each time / is pressed).
    _cached_ids: list[str] | None = None

    # Initial data fetch.
    audit_rows = _fetch(url, "audit", request_id, 50)
    sys_rows   = _fetch(url, "sys",   request_id, 50)
    api_rows   = _fetch(url, "api",   request_id, 50)

    live_on   = True
    primary   = stream
    last_poll = time.monotonic()

    key_q: "queue.Queue[bytes]" = queue.Queue()
    stop_flag = threading.Event()
    key_thread = threading.Thread(
        target=_key_reader, args=(key_q, stop_flag), daemon=True
    )

    console = Console()
    try:
        key_thread.start()
        with Live(
            _build_view(url, primary, request_id, interval, live_on,
                        audit_rows, sys_rows, api_rows),
            refresh_per_second=4,
            screen=True,
            console=console,
        ) as live_ctx:
            while True:
                # Process all pending keypresses.
                try:
                    while True:
                        ch = key_q.get_nowait()

                        if ch in (b"q", b"\x03"):   # q or Ctrl-C
                            return 0

                        elif ch in (b"l", b"L", b" "):  # toggle live
                            live_on = not live_on

                        elif ch == b"/":            # open picker
                            # Suspend Live, run picker, resume.
                            live_ctx.stop()
                            try:
                                _cached_ids = _fetch_recent_ids(url)
                                request_id = _run_picker(
                                    url, current=request_id, all_ids=_cached_ids
                                )
                                # Force immediate refresh after picker.
                                audit_rows = _fetch(url, "audit", request_id, 50)
                                sys_rows   = _fetch(url, "sys",   request_id, 50)
                                api_rows   = _fetch(url, "api",   request_id, 50)
                                last_poll  = time.monotonic()
                            finally:
                                live_ctx.start()

                        elif ch == b"\t":            # rotate primary pane
                            idx = STREAMS.index(primary)
                            primary = STREAMS[(idx + 1) % len(STREAMS)]

                except queue.Empty:
                    pass

                # Poll on interval when live is on.
                now = time.monotonic()
                if live_on and (now - last_poll) >= interval:
                    audit_rows = _fetch(url, "audit", request_id, 50)
                    sys_rows   = _fetch(url, "sys",   request_id, 50)
                    api_rows   = _fetch(url, "api",   request_id, 50)
                    last_poll  = now

                live_ctx.update(
                    _build_view(url, primary, request_id, interval, live_on,
                                audit_rows, sys_rows, api_rows)
                )
                time.sleep(0.05)

    except KeyboardInterrupt:
        return 0
    finally:
        stop_flag.set()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="fasten-tui", description="fasten three-pane TUI")
    p.add_argument("--url",        default=DEFAULT_URL,  help="reader base URL")
    p.add_argument("--stream",     choices=STREAMS,      default="audit",
                   help="initial primary pane")
    p.add_argument("--request-id", default=None,
                   help="pre-select a request_id filter (still changeable with /)")
    p.add_argument("--interval",   type=float,  default=2.0,
                   help="poll interval in seconds")
    p.add_argument("--no-pick",    action="store_true",
                   help="skip the initial request_id picker; watch all streams")
    args = p.parse_args(argv)
    return run(
        url=args.url,
        stream=args.stream,
        request_id=args.request_id,
        interval=args.interval,
        no_pick=args.no_pick,
    )
