#!/usr/bin/env python3
"""Compare built wheels with the files PyPI already has for the version.

Exits 0 when the version is not on PyPI, or when every file PyPI has for it
is in <dist dir> with the same sha256 (built files not on PyPI yet are fine:
a re-run after a partial upload).
Exits 3 when the version is on PyPI and this build cannot be published as
it: a file differs, PyPI has a file this build does not, the version is
yanked, or its files were deleted. RELEASE_CHECK_LEVEL=warning reports
these as warnings (dry runs).
Exits 1 when PyPI cannot be read or answers with something unexpected, when
<dist dir> has no wheels, or when it has an sdist (the release publishes
wheels only).

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


DIFFERS = 3


def error(msg: str) -> int:
    print(f"::error::{msg}", file=sys.stderr)
    return 1


def differs(msg: str) -> int:
    level = os.environ.get("RELEASE_CHECK_LEVEL", "error")
    print(f"::{level}::{msg}", file=sys.stderr)
    return DIFFERS


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <dist dir>", file=sys.stderr)
        return 2
    dist = sys.argv[1]
    sdists = [f for f in os.listdir(dist) if f.endswith(".tar.gz")]
    if sdists:
        return error(f"{', '.join(sdists)}: only wheels are checked and published")
    files = sorted(f for f in os.listdir(dist) if f.endswith(".whl"))
    if not files:
        return error(f"no wheels in {dist}")

    # Wheel names are name-version-tags.whl.
    project, version = files[0].split("-")[:2]
    project = re.sub(r"[-_.]+", "-", project).lower()
    url = f"{os.environ.get('PYPI_URL', 'https://pypi.org/pypi')}/{project}/{version}/json"
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            urls = json.load(r)["urls"]
            published = {u["filename"]: u["digests"]["sha256"] for u in urls}
            yanked = any(u.get("yanked") for u in urls)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            print(f"{project} {version} is not on PyPI")
            return 0
        return error(f"{url}: {e}")
    except (urllib.error.URLError, TimeoutError) as e:
        return error(f"{url}: {e}")
    except (ValueError, KeyError, TypeError) as e:
        return error(f"{url}: unexpected response: {e!r}")

    if not published:
        return differs(f"{project} {version} is on PyPI with no files (deleted); bump the version")
    if yanked:
        return differs(f"{project} {version} is yanked on PyPI; bump the version")
    bad = 0
    for f in sorted(set(published) - set(files)):
        bad = differs(f"{f} is on PyPI for {version} but not in this build")
    for f in files:
        if f not in published:
            print(f"{f}: not on PyPI yet")
            continue
        with open(os.path.join(dist, f), "rb") as fh:
            local = hashlib.sha256(fh.read()).hexdigest()
        if local == published[f]:
            print(f"{f}: already on PyPI with the same sha256")
        else:
            bad = differs(f"{f} on PyPI has sha256 {published[f]}, this build has {local}")
    return bad


if __name__ == "__main__":
    sys.exit(main())
