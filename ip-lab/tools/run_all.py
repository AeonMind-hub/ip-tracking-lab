#!/usr/bin/env python3
"""
One command to see the whole lab run end to end (selftest + dataset + dossiers +
case file + passive checks). Everything here is local + public read-only lookups.

  python3 tools/run_all.py
"""
from __future__ import annotations

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run(title: str, *cmd: str, timeout: int = 300) -> None:
    print(f"\n\n{'=' * 78}\n### {title}\n{'=' * 78}")
    r = subprocess.run(list(cmd), cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
    out = (r.stdout or "") + (("\n[stderr]\n" + r.stderr) if r.stderr.strip() else "")
    lines = out.splitlines()
    print("\n".join(lines[:60]))
    if len(lines) > 60:
        print(f"... ({len(lines) - 60} more lines)")
    print(f"[exit {r.returncode}]")


def main() -> None:
    py = sys.executable
    run("0 · selftest (must be all PASS)", py, "tools/selftest.py")
    run("1 · regenerate the fictional incident dataset", py, "tools/gen_dataset.py")
    run("2 · dossier: log -> per-address analysis + traceability ceiling", py, "tools/dossier.py", "data/target_access.log", "--xff", "--only-sus", "--min-hits", "5")
    run("3 · case file: the write-up with disclaimers", py, "tools/casefile.py", "data/target_access.log", "--min-hits", "5", "--title", "RUN-ALL / inbound traffic triage")
    run("4 · IPv6 roll-up: what a truncating retention policy costs you", py, "tools/dossier.py", "data/target_access.log", "--v6-rollup", "--only-sus", "--no-net", "--min-hits", "5")
    run("5 · canary consent gates", py, "tools/canary.py", "selftest")
    run("6 · web attack surface A/B — every class must fire on vuln and be blocked on hard",
        py, "tools/webcheck.py")
    run("7 · the tracking / device / phishing tools (self-contained, no sockets)",
        py, "tools/eyeball.py", "--selftest")
    run("7b · phish detector: planted corpus + classification", py, "tools/phish.py", "corpus")
    run("7c · netinv: LAN audit gates", py, "tools/netinv.py", "--selftest")
    print("\nStage 6 spawned two shop.py instances by itself. To drive them by hand:")
    print("  python3 apps/shop.py --port 8099                  # vulnerable")
    print("  python3 apps/shop.py --port 8098 --mode hard        # fixed")
    print("  curl -s 'http://127.0.0.1:8099/search?q=%27%20OR%201%3D1--'   # always-true SQLi")
    print("  curl -s 'http://127.0.0.1:8099/file?name=../../../../../etc/passwd' | head -1")
    print("\nModule 4 (header forgery against a live local target) is interactive:")
    print("  python3 apps/app.py --port 8080 --mode naive")
    print("  python3 tools/probe.py --naive 8080 --debug-vars")
    print("  python3 tools/dossier.py out/target_access_sim.log --xff --no-net")
    print("\nDone. Open notes/01-pipeline.md and work the six exercises in README.md.")


if __name__ == "__main__":
    try:                            # Windows console/encoding shim; no-op elsewhere
        import sys as _sys, os as _os
        _sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "lab"))
        import win
        win.ready()
    except ImportError:
        pass
    main()
