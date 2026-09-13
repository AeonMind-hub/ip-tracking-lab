#!/usr/bin/env python3
"""Ship a fix as a git bundle, so the other machine just pulls.

  python3 tools/sync.py status                  what is dirty, what is tracked
  python3 tools/sync.py bundle [--m "msg"]       commit everything, write ../lab.bundle, verify
  python3 tools/sync.py bundle --incremental     only the commits after the last one you published
  python3 tools/sync.py check                    verify an existing bundle + print the pull command

Why this exists: hand-editing a copied tree is how you lose work. A bundle is a git repo in one
file, so `git pull <bundle> main` fast-forwards the clone, keeps local commits and local edits,
and needs no account, no token and no network. `HEAD main` in the create call is not decoration -
a bundle containing only a branch ref clones as an empty `master` (see SYNC.md §6).

Nothing here is destructive: `git commit` and `git bundle create` only add. Refusing to run when
the repository has no commits is the one hard stop, because an empty bundle would look like a
successful sync and deliver nothing.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))          # the ip-lab dir
TOP = os.path.dirname(ROOT)                                                   # the repo root
BUNDLE = os.path.join(TOP, "lab.bundle")


def git(*args: str, check: bool = True) -> tuple[int, str]:
    """Run git in the repo root. Returns (returncode, stdout+stderr)."""
    r = subprocess.run(["git", *args], cwd=TOP, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    out = (r.stdout or "") + (("\n" + r.stderr) if r.stderr.strip() else "")
    out = out.strip()
    if check and r.returncode != 0:
        print(f"[sync] git {' '.join(args)} -> exit {r.returncode}\n{out}", file=sys.stderr)
    return r.returncode, out


def have_git() -> bool:
    return subprocess.run(["git", "--version"], capture_output=True).returncode == 0


def size_mb(path: str) -> str:
    return f"{os.path.getsize(path) / 1024:.0f} KiB" if os.path.exists(path) else "missing"


def pull_command(inc_from: str = "") -> str:
    base = "cd C:\\lab\\ip-tracking-lab; git pull C:\\lab\\lab.bundle main"
    return base + (f"      # from {inc_from}" if inc_from else "")


def status() -> int:
    if not have_git():
        print("[sync] no git on PATH - nothing to report")
        return 2
    _rc, _gitdir = git("rev-parse", "--git-dir", check=False)
    if _rc:
        print("[sync] this tree is not a git clone (a plain copy from a zip?) - see SYNC.md §1 "
              "to turn it into one. Nothing to publish from here.")
        return 2
    _rc, tracked = git("ls-files", check=False)
    _rc, dirty = git("status", "--porcelain", check=False)
    _rc, head = git("log", "--oneline", "-1", check=False)
    _rc, ahead = git("rev-list", "--count", "main", check=False)
    print(f"repo root : {TOP}")
    print(f"HEAD      : {head or '(no commits yet)'}")
    print(f"tracked   : {len([l for l in tracked.splitlines() if l.strip()])} files")
    print(f"commits   : {ahead.strip() or '?'}")
    print(f"uncommitted: {len([l for l in dirty.splitlines() if l.strip()])} path(s)")
    for line in dirty.splitlines()[:12]:
        print(f"   {line}")
    print(f"bundle    : {size_mb(BUNDLE)}"
          + (" (verify: git bundle verify lab.bundle)" if os.path.exists(BUNDLE) else ""))
    return 0


def bundle(incremental: bool, message: str) -> int:
    if not have_git():
        print("[sync] git is not installed here; a plain zip still works, see SYNC.md §1", file=sys.stderr)
        return 2
    _rc, dirty = git("status", "--porcelain", check=False)
    if dirty.strip() and message:
        git("add", "-A", "--", ".")
        rc, out = git("commit", "-m", message)
        if rc:
            print("[sync] commit failed; nothing published", file=sys.stderr)
            return rc
        print(f"[sync] committed ({len(dirty.splitlines())} path(s) staged)")
    elif dirty.strip():
        print(f"[sync] {len(dirty.splitlines())} uncommitted path(s); bundle will contain only "
              "what is already committed. Pass --m to commit first.", file=sys.stderr)

    _rc, head = git("rev-parse", "HEAD", check=False)
    if not head.strip():
        print("[sync] repository has no commits yet - refusing to write an empty bundle", file=sys.stderr)
        return 1
    base = ""
    if incremental:
        _rc, prev = git("rev-list", "--skip=1", "-n", "1", "HEAD", check=False)
        base = prev.strip()
        if not base:
            print("[sync] only one commit exists; a delta is meaningless - writing a complete bundle")
    # an incremental bundle is only pullable by someone who already has `base`, which is why
    # `status` prints the recipient's exact command instead of assuming they know it
    # tags travel with the bundle: a recipient should be able to `git describe` what they cloned,
    # and "HEAD main" alone silently ships a repo that cannot name its own release
    _rc, tags = git("tag", "--list", check=False)
    want_tags = [f"refs/tags/{t}" for t in tags.split() if t.strip()]
    spec = ([f"{base}..main"] if base else ["HEAD", "main"]) + ([] if base else want_tags)
    if base:
        print(f"[sync] incremental: this bundle only applies to a clone that already has "
              f"{base[:8]}\n"
              f"       if their pull says \"lacks these prerequisite commits\", re-run without "
              "--incremental\n       (a complete bundle is a few hundred KiB - that is the safe default)")
    if os.path.exists(BUNDLE):
        os.unlink(BUNDLE)
    rc, out = git("bundle", "create", BUNDLE, *spec, check=False)
    if rc:
        print("[sync] bundle create failed\n" + out, file=sys.stderr)
        return rc
    rc, vout = git("bundle", "verify", BUNDLE, check=False)
    print(f"[sync] wrote {os.path.relpath(BUNDLE, TOP)}  ({size_mb(BUNDLE)})"
          + (f"  incremental from {base[:8]}" if base else "  complete history"))
    for line in vout.splitlines()[-2:]:
        print(f"[sync] verify: {line}")
    if rc:
        print("[sync] VERIFY FAILED - do not hand this file over", file=sys.stderr)
        return 1
    print("[sync] recipient runs:\n        " + pull_command(base[:8] if base else ""))
    return 0


def push_to_origin() -> int:
    """Push `main` and the tags to the `origin` remote, then prove the remote moved.

    Kept out of `bundle`'s happy path on purpose: writing the file and shipping it are different
    decisions, and a failed push must never look like a publish that succeeded. The remote URL
    holds no credential - git gets one from whatever the machine already has (GIT_ASKPASS here,
    GCM's browser sign-in on Windows), so nothing sensitive is written into `.git/config`.
    """
    _rc, url = git("config", "--get", "remote.origin.url", check=False)
    if not url.strip():
        print("[sync] no origin remote, so nothing was pushed. lab.bundle is current either way; "
              "SYNC.md §4 adds a remote in two commands", file=sys.stderr)
        return 1
    rc, out = git("push", "origin", "main", "--follow-tags", check=False)
    for line in out.splitlines()[-3:]:
        print(f"[sync] push: {line}")
    if rc:
        print(f"[sync] PUSH FAILED (exit {rc}) - the bundle on disk is still valid, so nothing is "
              "lost; fix the credential/network and re-run with --push", file=sys.stderr)
        return rc
    _rc2, head = git("rev-parse", "HEAD", check=False)
    _rc2, remote = git("ls-remote", "origin", "refs/heads/main", check=False)
    got = remote.split()[0] if remote.strip() else ""
    agrees = bool(got) and got == head.strip()
    print(f"[sync] origin/main at {got[:12] or '?'} -> {'matches HEAD' if agrees else 'DOES NOT MATCH HEAD'}")
    return 0 if agrees else 1


def check_only() -> int:
    if not os.path.exists(BUNDLE):
        print("[sync] no bundle yet: run  python3 tools/sync.py bundle", file=sys.stderr)
        return 1
    rc, out = git("bundle", "verify", BUNDLE, check=False)
    print(out)
    if rc == 0:
        print("[sync] ok. " + pull_command())
    return rc


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status", help="what is tracked, dirty, published")
    b = sub.add_parser("bundle", help="commit (optional) + write + verify lab.bundle")
    b.add_argument("--m", default="", help="commit message; commits every tracked change first")
    b.add_argument("--incremental", action="store_true",
                   help="only the newest commit's delta (recipient must already have the previous one)")
    b.add_argument("--push", action="store_true",
                   help="after bundling, also push main + tags to the origin remote and confirm it moved")
    sub.add_parser("check", help="verify the existing bundle and print the pull command")
    a = ap.parse_args()
    if a.cmd == "status":
        return status()
    if a.cmd == "bundle":
        rc = bundle(a.incremental, a.m)
        if a.push:
            prc = push_to_origin()
            return rc if rc else prc       # a broken bundle outranks a broken push
        return rc
    return check_only()


try:                            # Windows console/encoding shim; no-op elsewhere
    import sys as _sys, os as _os
    _sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "lab"))
    import win
    win.ready()
except ImportError:
    pass

if __name__ == "__main__":
    raise SystemExit(main())
