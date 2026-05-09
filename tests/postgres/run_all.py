"""Run all P1-16 Postgres fleet-scale scenarios and emit a results JSON.

Usage:
    cd fasten/tests/postgres
    docker compose up -d --wait
    python run_all.py [--dsn postgresql://fasten:fasten@localhost:5432/fasten_test]
    # Results written to results/run_<timestamp>.json
    # Compared to baseline.json; exits non-zero if any scenario regresses >2x.
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

SCENARIOS = [
    ("concurrent_writers_single",   "_harness.concurrent_writers",   {"workers": 4, "tenants": 1, "rows_per_s": 10, "duration_s": 15, "table": "fasten_pw_single"}),
    ("concurrent_writers_multitenant", "_harness.concurrent_writers", {"workers": 4, "tenants": 4, "rows_per_s": 10, "duration_s": 15, "table": "fasten_pw_mt"}),
    ("vacuum_concurrency",           "_harness.vacuum_concurrency",   {"writers": 4, "rows_per_s": 20, "vacuum_interval_s": 5.0, "duration_s": 20, "table": "fasten_vacuum"}),
    ("stale_conn_recovery_idle",     "_harness.stale_conn_recovery",  {"mode": "idle", "idle_s": 12, "table": "fasten_idle"}),
]


def run_all(dsn: str) -> dict:
    results = {"dsn_host": dsn.split("@")[-1], "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"), "scenarios": {}}
    passed_all = True

    for name, module_path, kwargs in SCENARIOS:
        print(f"\n{'='*60}\nScenario: {name}\n{'='*60}")
        mod = __import__(module_path, fromlist=["run"])
        result = mod.run(dsn=dsn, **kwargs)
        results["scenarios"][name] = result
        if not result.get("passed", False):
            passed_all = False
            print(f"  FAILED: {name}")

    results["passed_all"] = passed_all
    return results


def compare_to_baseline(results: dict, baseline_path: Path) -> bool:
    if not baseline_path.exists():
        print("No baseline.json found — writing current results as baseline.")
        baseline_path.write_text(json.dumps(results, indent=2))
        return True

    baseline = json.loads(baseline_path.read_text())
    regressions = []
    for name, current in results["scenarios"].items():
        base = baseline.get("scenarios", {}).get(name, {})
        for metric in ("p99_ms", "p99_ms_max"):
            if metric in current and metric in base:
                if current[metric] > base[metric] * 2:
                    regressions.append(f"{name}.{metric}: {current[metric]:.1f} > 2x {base[metric]:.1f}")
    if regressions:
        print("\nREGRESSIONS DETECTED:")
        for r in regressions:
            print(f"  {r}")
        return False
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--dsn", default="postgresql://fasten:fasten@localhost:5432/fasten_test")
    parser.add_argument("--update-baseline", action="store_true")
    args = parser.parse_args()

    results = run_all(args.dsn)

    results_dir = Path(__file__).parent / "results"
    results_dir.mkdir(exist_ok=True)
    run_file = results_dir / f"run_{time.strftime('%Y%m%d_%H%M%S')}.json"
    run_file.write_text(json.dumps(results, indent=2))
    print(f"\nResults written to {run_file}")

    baseline = Path(__file__).parent / "baseline.json"
    if args.update_baseline:
        baseline.write_text(json.dumps(results, indent=2))
        print("Baseline updated.")

    ok = results["passed_all"] and compare_to_baseline(results, baseline)
    sys.exit(0 if ok else 1)
