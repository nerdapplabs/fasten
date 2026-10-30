#!/usr/bin/env python3
"""Flag workflow steps that read a repo-root file under a subdirectory default.

Jobs such as fasten-rust.yml set `defaults.run.working-directory`, so a step
that reads rust-toolchain.toml (at the repo root) must set its own
working-directory or it fails with "No such file or directory".

Exit 0 clean, 1 with findings on stdout.
"""
import glob
import sys

import yaml

# Only files that are read from the repo root. Directory names like "spec/"
# would also match valid relative paths such as "../spec/".
ROOT_FILES = ("rust-toolchain.toml",)


def main() -> int:
    findings = []
    for path in sorted(glob.glob(".github/workflows/*.yml")):
        try:
            doc = yaml.safe_load(open(path))
        except Exception as e:
            findings.append(f"{path}: unparseable ({e})")
            continue
        if not isinstance(doc, dict):
            continue
        for job_name, job in (doc.get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue
            default = ((job.get("defaults") or {}).get("run") or {}).get(
                "working-directory")
            if not default:
                continue
            for step in job.get("steps") or []:
                if not isinstance(step, dict):
                    continue
                run = step.get("run") or ""
                # An explicit per-step working-directory overrides the default.
                if not run or step.get("working-directory") is not None:
                    continue
                name = step.get("name", "?")
                for root_file in ROOT_FILES:
                    if root_file in run:
                        findings.append(
                            f"{path} :: job {job_name} :: step {name!r} reads "
                            f"{root_file} but inherits "
                            f"working-directory: {default}")
                        break

    for f in findings:
        print(f)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
