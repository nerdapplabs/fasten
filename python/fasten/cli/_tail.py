"""
`fasten tail` — polling client for /api/v1/logs/{audit,sys,api}.

Polls the reader every `--interval` seconds, dedupes by timestamp,
prints only new rows. Honours FASTEN_READER_KEY (sends as X-Fasten-Key
once P0-4 ships; harmless to send today). `--json` emits NDJSON.

SSE / long-poll path lands once the reader exposes /stream — out of
scope here.
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any


def _fetch(
    base_url: str,
    stream: str,
    request_id: str | None,
    since_iso: str | None,
    limit: int,
    api_key: str | None,
) -> list[dict[str, Any]]:
    params: dict[str, str] = {"limit": str(limit)}
    if request_id:
        params["request_id"] = request_id
    if since_iso:
        params["since"] = since_iso
    url = f"{base_url.rstrip('/')}/{stream}?{urllib.parse.urlencode(params)}"

    req = urllib.request.Request(url)
    if api_key:
        req.add_header("X-Fasten-Key", api_key)
    try:
        with urllib.request.urlopen(req, timeout=5.0) as resp:
            payload = json.loads(resp.read())
    except (urllib.error.URLError, TimeoutError) as e:
        sys.stderr.write(f"fasten tail: reader unreachable ({e})\n")
        return []
    except json.JSONDecodeError as e:
        sys.stderr.write(f"fasten tail: bad JSON from reader ({e})\n")
        return []
    rows = payload.get("rows") or []
    return rows if isinstance(rows, list) else []


def _row_ts(row: dict[str, Any]) -> str:
    ts = row.get("timestamp") or row.get("ts") or ""
    return str(ts)


def _format_audit(row: dict[str, Any]) -> str:
    return (
        f"{_row_ts(row):26s}  "
        f"{str(row.get('code', '—')):26s}  "
        f"actor={row.get('actor', '—')}  "
        f"target={row.get('target', '—')}  "
        f"req={str(row.get('request_id', '—'))[:12]}"
    )


def _format_sys(row: dict[str, Any]) -> str:
    return (
        f"{_row_ts(row):26s}  "
        f"[{str(row.get('level', 'info')):5s}]  "
        f"{row.get('message') or row.get('event', '—')}  "
        f"req={str(row.get('request_id', '—'))[:12]}"
    )


def _format_api(row: dict[str, Any]) -> str:
    return (
        f"{_row_ts(row):26s}  "
        f"{str(row.get('method', 'GET')):4s}  "
        f"{row.get('path', '—')}  "
        f"req={str(row.get('request_id', '—'))[:12]}"
    )


_FORMATTERS = {"audit": _format_audit, "sys": _format_sys, "api": _format_api}


def run(
    url: str,
    stream: str,
    request_id: str | None = None,
    interval: float = 2.0,
    as_json: bool = False,
    api_key: str | None = None,
) -> int:
    if stream not in _FORMATTERS:
        sys.stderr.write(f"unknown stream {stream!r} — choose audit / sys / api\n")
        return 2

    api_key = api_key or os.environ.get("FASTEN_READER_KEY")

    # Start window: 5 min back, so first poll picks up recent context.
    last_seen = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    seen_ids: set[str] = set()

    fmt = _FORMATTERS[stream]

    try:
        while True:
            rows = _fetch(url, stream, request_id, last_seen, limit=100, api_key=api_key)

            # Dedupe by id when present, else by (timestamp, code) tuple.
            new_rows = []
            for r in rows:
                key = r.get("id") or f"{_row_ts(r)}|{r.get('code', '')}|{r.get('event', '')}"
                if key in seen_ids:
                    continue
                seen_ids.add(key)
                new_rows.append(r)

            # Bound the dedupe set.
            if len(seen_ids) > 5000:
                seen_ids = set(list(seen_ids)[-2500:])

            new_rows.sort(key=_row_ts)
            for r in new_rows:
                if as_json:
                    sys.stdout.write(json.dumps(r) + "\n")
                else:
                    sys.stdout.write(fmt(r) + "\n")
                ts = _row_ts(r)
                if ts and ts > last_seen:
                    last_seen = ts
            sys.stdout.flush()

            time.sleep(interval)
    except KeyboardInterrupt:
        return 0
