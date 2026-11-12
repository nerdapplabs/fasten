#!/usr/bin/env python3
"""Compare built distributions with the files PyPI already has for the version.

Exits 0 when no file in <dist dir> is on PyPI yet, or when every file that is
there has the same sha256. Exits 1 when a file with the same name has
different bytes, which means the tag was rebuilt from other code.

Usage: scripts/release/pypi-check.py <dist dir>
PYPI_URL overrides https://pypi.org/pypi (for the tests).
"""
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <dist dir>", file=sys.stderr)
        return 2
    dist = sys.argv[1]
    files = sorted(f for f in os.listdir(dist) if f.endswith((".whl", ".tar.gz")))
    if not files:
        print(f"::error::no distributions in {dist}", file=sys.stderr)
        return 1

    # name-version-... for wheels and sdists alike.
    project, version = files[0].split("-")[:2]
    project = re.sub(r"[-_.]+", "-", project).lower()
    base = os.environ.get("PYPI_URL", "https://pypi.org/pypi")
    try:
        with urllib.request.urlopen(f"{base}/{project}/{version}/json", timeout=30) as r:
            published = {u["filename"]: u["digests"]["sha256"] for u in json.load(r)["urls"]}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print(f"{project} {version} is not on PyPI")
            return 0
        raise

    bad = 0
    for f in files:
        if f not in published:
            print(f"{f}: not on PyPI yet")
            continue
        with open(os.path.join(dist, f), "rb") as fh:
            local = hashlib.sha256(fh.read()).hexdigest()
        if local == published[f]:
            print(f"{f}: already on PyPI with the same sha256")
        else:
            print(f"::error::{f} on PyPI has sha256 {published[f]}, this build has {local}", file=sys.stderr)
            bad = 1
    return bad


if __name__ == "__main__":
    sys.exit(main())
