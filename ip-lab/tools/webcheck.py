#!/usr/bin/env python3
"""webcheck.py — proves every planted class in apps/shop.py fires, and every fix holds.

    python3 tools/webcheck.py                # spawns vuln + hard instances, A/B's them
    python3 tools/webcheck.py --keep         # ...and leave the servers up for you to poke
    python3 tools/webcheck.py --only vuln    # one side

For each vulnerability class the expected answer is unambiguous: FIRES on the
vulnerable instance, BLOCKED on the hardened one. `blocked` means the payload
either stopped working (401/404/405/rejected) or came back inert (escaped,
neutralised, redirected to a relative path). This is the file that decides
whether notes/11 is telling you the truth.

Localhost only. It talks to the two shop.py processes it starts, nothing else.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHOP = os.path.join(HERE, "apps", "shop.py")
VULN_PID = VULN_PORT = None


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def b64(d) -> str:
    return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")


FORGED_JWT = b64({"alg": "none", "typ": "JWT"}) + "." + \
    b64({"sub": "boss@shop.test", "id": 3, "role": "admin"}) + "."


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def req(base: str, path: str, data: str | None = None, hdr: dict | None = None,
        method: str | None = None) -> tuple[int, str, dict]:
    r = urllib.request.Request(base + path, data=data.encode() if data is not None else None,
                               headers=hdr or {}, method=method)
    op = urllib.request.build_opener(NoRedirect)
    try:
        with op.open(r, timeout=6,) as f:
            return f.status, f.read().decode(errors="replace"), dict(f.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace"), dict(e.headers)


FORM = {"Content-Type": "application/x-www-form-urlencoded"}


def replay_probe(base: str):
    """Log in as the lab user, then use the session they got from a different device profile.
    This is what a stolen bearer token looks like on the wire: valid token, wrong browser."""
    st, body, hdr = req(base, "/login", "email=ada%40shop.test&password=password123", FORM, "POST")
    sc = hdr.get("Set-Cookie", "")
    tok = sc.split("session=", 1)[1].split(";")[0] if "session=" in sc else ""
    return req(base, "/account/orders", None, {"User-Agent": "curl-attacker/8.0",
                                               "Authorization": "Bearer " + tok})
BEAR = {"Authorization": "Bearer " + FORGED_JWT}


def wait_up(base: str, tries: int = 200) -> bool:
    """Poll /healthz for up to ~30 s.

    A fresh python process on Windows can be held for seconds by real-time AV scanning, so 60
    quick tries (9 s) was long enough on my box to pass and short enough on a slower one to fail -
    and a too-short budget is what turns an environment problem into a wrong verdict about a
    vulnerability class. Cheap to widen, so widen it."""
    for _ in range(tries):
        try:
            if req(base, "/healthz")[0] == 200:
                return True
        except Exception:
            time.sleep(0.15)
    return False


# ------------------------------------------------------------------ the battery
# Each row: (class id, name, setup() or None, probe(base) -> (request bits), judge(text, hdrs))
BATTERY = [
    ("A1", "SQLi — always-true dumps the catalog",
     lambda b: req(b, "/search?q=%27%20OR%201%3D1--"),
     lambda t, h: "BAG-01" in t and "TEE-02" in t),

    ("A2", "SQLi — UNION reads the users table",
     lambda b: req(b, "/search?q=x%27%20UNION%20SELECT%20id%2Cemail%2C0%2Chash%20FROM%20users--"),
     lambda t, h: "ada@shop.test" in t and "482c811da5d5b4bc6d497ffa98491e38" in t),

    ("A3", "SQLi — error message echoed to the page",
     lambda b: req(b, "/search?q=x%27"),
     lambda t, h: "SQL error" in t or "unterminated" in t),

    ("A4", "SQLi — login bypass with ' OR 1=1--",
     lambda b: req(b, "/login", "email=%27+OR+1%3D1--&password=x", FORM, "POST"),
     lambda t, h: h.get("Set-Cookie", "").startswith("session=eyJ") or "302" in str(h)),

    ("A5", "User enumeration — 404 for unknown, 401 for wrong password",
     lambda b: req(b, "/login", "email=nobody@shop.test&password=x", FORM, "POST"),
     lambda t, h: "no such user" in t),

    ("B1", "XSS — reflected in the search box",
     lambda b: req(b, "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
     lambda t, h: "<script>alert(1)</script>" in t),

    ("B2", "XSS — stored in the guestbook",
     lambda b: (req(b, "/notes", "note=%3Cimg+src%3Dx+onerror%3Dalert%281%29%3E", FORM, "POST"),
                req(b, "/notes"))[1],
     lambda t, h: "<img src=x onerror=alert(1)>" in t),

    ("B3", "Upload served as same-origin HTML (script executes)",
     lambda b: (req(b, "/upload", "filename=b3.html&data=%3Cscript%3Eboom()%3C%2Fscript%3E", FORM, "POST"),
                req(b, "/file?name=b3.html"))[1],
     lambda t, h: "<script>boom()</script>" in t and "text/html" in h.get("Content-Type", "")),

    ("C1", "Path traversal — /etc/passwd via /file?name=",
     lambda b: req(b, "/file?name=..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd"),
     lambda t, h: "root:x:0:0" in t),

    ("C2", "Absolute path accepted by the file reader",
     lambda b: req(b, "/file?name=%2Fetc%2Fpasswd"),
     lambda t, h: "root:x:0:0" in t),

    ("D1", "Open redirect on logout",
     lambda b: req(b, "/logout?next=https%3A%2F%2Fevil.test"),
     lambda t, h: h.get("Location", "").startswith("https://evil.test")),

    ("D2", "JWT alg=none — forged admin token accepted",
     lambda b: req(b, "/account/orders", None, BEAR),
     lambda t, h: "NGN-4411" in t or "NGN-ADMIN" in t),

    ("D3", "IDOR — one customer token reads another account",
     lambda b: req(b, "/account/orders?id=2", None, BEAR),
     lambda t, h: "NGN-9001" in t),

    ("D4", "Missing function-level authz — /admin with any valid token",
     lambda b: req(b, "/admin", None, BEAR),
     lambda t, h: "boss@shop.test" in t),

    ("E1", "Mass assignment — role=admin at registration",
     lambda b: req(b, "/register", "email=e@shop.test&role=admin", FORM, "POST"),
     lambda t, h: '"role": "admin"' in t),

    ("E2", "Client-supplied price honoured",
     lambda b: req(b, "/cart/add", '{"id":1,"price":1}', {"Content-Type": "application/json"}, "POST"),
     lambda t, h: '"charged": 1' in t),

    ("E3", "CSRF by GET — coupon spent with no token, no POST",
     lambda b: req(b, "/cart/coupon?code=LAUNCH25"),
     lambda t, h: '"ok": true' in t),

    ("F1", "Secrets in /.env",
     lambda b: req(b, "/.env"),
     lambda t, h: "JWT_SECRET=" in t),

    ("F2", "/debug leaks the signing key and paths",
     lambda b: req(b, "/debug"),
     lambda t, h: "correct-horse-battery" in t or "db_path" in t),

    ("F3", "robots.txt advertises the admin surface",
     lambda b: req(b, "/robots.txt"),
     lambda t, h: "Disallow: /debug" in t),

    ("F4", "Directory listing on /uploads/",
     lambda b: req(b, "/uploads/"),
     lambda t, h: "index of /uploads" in t),

    ("F5", "Server header fingerprint (fake nginx + PHP)",
     lambda b: req(b, "/"),
     lambda t, h: "nginx/1.24" in h.get("Server", "") or "PHP/7.4" in h.get("X-Powered-By", "")),

    ("H1", "Session replay — stolen token used from another device",
     lambda b: replay_probe(b),
     lambda t, h: '"orders"' in t),

    ("H2", "Session fixation — attacker-chosen sid survives authentication",
     lambda b: req(b, "/session/auth", "sid=ATTACKER123&as=ada%40shop.test", FORM, "POST"),
     lambda t, h: '"rotated": false' in t),

    ("H3", "Session table readable by a non-admin (/admin/sessions)",
     lambda b: req(b, "/admin/sessions", None, BEAR),
     lambda t, h: '"sessions"' in t),

    ("G1", "Upload — .html accepted and served back inline",
     lambda b: (req(b, "/upload", "filename=x.html&data=%3Cscript%3E1%3C%2Fscript%3E", FORM, "POST")),
     lambda t, h: "saved" in t),
]

# classes whose exploit is a *sequence*, judged after the single probes
RACE = ("E4", "Coupon race — 1 seat, 8 winners (check-then-act)",
        lambda b: "see --race")


def run_race(base: str, n: int = 8, use_post: bool = False) -> int:
    """Fire n coupon redemptions as close to simultaneously as this sandbox allows.

    One seat must never produce more than one winner. Vuln mode spends it over GET (that is
    the CSRF half of the bug); hard mode refuses GET, so the same test goes over POST there."""
    import threading
    hits = []

    def one(path, data, hdr, method):
        hits.append(req(base, path, data, hdr, method)[1])

    if use_post:
        th = [threading.Thread(target=one, args=("/cart/coupon", "code=LAUNCH25", FORM, "POST"))
              for _ in range(n)]
    else:
        th = [threading.Thread(target=one, args=("/cart/coupon?code=LAUNCH25", None, None, None))
              for _ in range(n)]
    [x.start() for x in th]
    [x.join() for x in th]
    return sum(1 for h in hits if '"ok": true' in h)


def start_reason(mode: str) -> str:
    """Why a spawned instance never became ready, from its own stderr."""
    detail = tail_err(mode)
    if detail:
        return f"stderr: {detail}"
    return (f"no output at all - still starting, or something holds out/shop.sqlite "
            f"(child log: {ERRLOG.get(mode, 'n/a')})")


def wait_up_or_death(proc: subprocess.Popen, base: str, tries: int = 60) -> bool:
    """Like wait_up, but quits the moment the child is gone.

    Patient about a slow start (AV scanning the interpreter: keep polling) and impatient about a
    dead one (it exited: stop, and read its stderr). Waiting out the full budget in the second case
    is how a real failure turns into a 90-second mystery."""
    for _ in range(tries):
        try:
            if req(base, "/healthz")[0] == 200:
                return True
        except Exception:
            time.sleep(0.15)
        if proc.poll() is not None:
            return False
    return False


def spawn_ready(mode: str, seats: int, attempts: int = 3, extra: tuple = ()):
    """Spawn one shop.py and wait for it, retrying before giving up.

    Returns (proc, base, None) on success, (None, "", reason) on failure. Never pretend a
    measurement taken against a dead server says something about a class: callers that cannot
    start their instance must report it as unverified, not as a result.
    """
    last = ""
    for attempt in range(1, attempts + 1):
        proc, base = spawn(mode, seats, extra)
        if wait_up_or_death(proc, base):
            return proc, base, None
        last = start_reason(mode)
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:      # noqa: BLE001 - already failing; don't mask the reason
            pass
        if attempt < attempts:
            time.sleep(1.0 * attempt)     # give AV/EDR time to finish scanning the interpreter
    return None, "", f"{mode} instance never answered /healthz after {attempts} attempts; {last}"


def _have_curl() -> bool:
    from shutil import which
    return which("curl") is not None


ERRLOG = {}


def spawn(mode: str, seats: int = 40, extra: tuple = ()) -> tuple[subprocess.Popen, str]:
    """Start one shop.py. Its stderr goes to a file, not a pipe: a startup traceback is the one
    thing a harness must not swallow, and `wait_up` failing without it is just "it didn't come
    up" - which is exactly the message that sent me hunting for a bug in a working lab."""
    port = free_port()
    err = os.path.join(HERE, "out", f"webcheck-{mode}.err")
    os.makedirs(os.path.dirname(err), exist_ok=True)
    fh = open(err, "w", encoding="utf-8", errors="replace")
    ERRLOG[mode] = err
    p = subprocess.Popen([sys.executable, SHOP, "--port", str(port), "--mode", mode,
                          "--seats", str(seats), *[str(x) for x in extra]],
                         stdout=subprocess.DEVNULL, stderr=fh)
    p._errfile = fh            # closed when the child is reaped below
    return p, f"http://127.0.0.1:{port}"


def tail_err(mode: str, lines: int = 6) -> str:
    try:
        body = open(ERRLOG.get(mode, ""), encoding="utf-8", errors="replace").read().strip().splitlines()
    except OSError:
        return ""
    return " | ".join(body[-lines:]) if body else ""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", choices=["vuln", "hard", "both"], default="both")
    ap.add_argument("--seats", type=int, default=40, help="coupon seats on the spawned instances")
    ap.add_argument("--keep", action="store_true", help="leave the servers running")
    ap.add_argument("--base", default="", help="test an already-running instance instead of spawning")
    ap.add_argument("--json", default=os.path.join(HERE, "out", "webcheck.json"))
    a = ap.parse_args()

    sides = []
    if a.base:
        sides = [("custom", a.base, None)]
    else:
        for m in (["vuln", "hard"] if a.only == "both" else [a.only]):
            p, base, why = spawn_ready(m, a.seats)
            if p is None:
                print(f"[webcheck] {why}", file=sys.stderr)
                print("[webcheck] nothing was measured - fix the startup problem, do not read "
                      "anything into the class rows", file=sys.stderr)
                return 1
            sides.append((m, base, p))

    results, mismatches, unverified = [], 0, 0
    print(f"{'id':4s}{'class':52s}{'vuln':>10s}{'hard':>10s}   verdict")
    print("-" * 96)
    for cid, name, probe, judge in BATTERY:
        row = {"id": cid, "name": name}
        for m, base, _ in sides:
            st, body, hd = probe(base)
            fired = judge(body, hd)
            row[m] = {"status": st, "fired": fired}
        if len(sides) == 2:
            v, h = row["vuln"]["fired"], row["hard"]["fired"]
            verdict = "ok" if (v and not h) else "MISMATCH"
            if verdict == "MISMATCH":
                mismatches += 1
            def cell(r, want_fire):
                lab = "FIRES" if r["fired"] else "quiet"
                flag = "" if (r["fired"] == want_fire) else "*"
                return f"{lab}{flag}/{r['status']}"
            print(f"{cid:4s}{name[:51]:52s}{cell(row['vuln'], True):>14s}{cell(row['hard'], False):>16s}"
                  f"   {verdict}")
        else:
            m = sides[0][0]
            print(f"{cid:4s}{name[:51]:52s}{str(row[m]['status']):>10s}{'':10s}   "
                  f"{'fires' if row[m]['fired'] else 'quiet'}")
        results.append(row)

    # E4 needs its own pair: exactly one seat, so any overspend is unambiguous
    if len(sides) == 2:
        # --racers 8 makes the vulnerable instance hold all eight redemptions inside the
        # check-then-act gap together. Without it the oversell depends on the scheduler cooperating,
        # and on the Windows box this was tested on it did not: one request at a time in flight,
        # "1 winner", and the row reported a MISMATCH for a class that was behaving exactly as
        # written. Measure the bug; do not hope to catch it.
        vp, vbase, vwhy = spawn_ready("vuln", 1, extra=("--racers", "8"))
        hp, hbase, hwhy = spawn_ready("hard", 1)
        if vp is None or hp is None:
            why = vwhy or hwhy
            print(f"{'E4':4s}{'Coupon race — 1 seat, 8 parallel redemptions':41s}"
                  f"{'-':>14s}{'-':>16s}   unverified")
            print(f"[webcheck] E4 could not be measured ({why}) - that is a startup problem on "
                  "this machine, not a verdict about the race. Re-run it alone: "
                  "python3 tools/webcheck.py --only vuln", file=sys.stderr)
            results.append({"id": "E4", "name": "coupon race (1 seat vs 8 parallel)",
                            "verdict": "unverified", "why": why})
            unverified += 1
        else:
            # 0 wins on either side is not a possible outcome of two live servers (the vulnerable
            # pair overspends, the fixed one gives exactly 1), so a zero means they were not
            # serving yet. Re-measure instead of reporting a verdict that is really a timing artefact.
            for tries in range(3):
                v_win = run_race(vbase, 8)                  # spends the seat over GET (the CSRF half)
                h_win = run_race(hbase, 8, use_post=True)   # same test, POST, atomic
                if v_win and h_win:
                    break
                time.sleep(1.0)
            ok = v_win > 1 and h_win == 1
            mismatches += 0 if ok else 1
            if v_win == 1:
                print("[webcheck] E4: the vulnerable instance handed the seat to exactly one caller, "
                      "which should be impossible with --racers 8 - check that apps/shop.py is current",
                      file=sys.stderr)
            print(f"{'E4':4s}{'Coupon race — 1 seat, 8 parallel redemptions':41s}"
                  f"{f'{v_win} wins':>14s}{f'{h_win} wins':>16s}   {'ok' if ok else 'MISMATCH'}")
            vp.terminate()
            hp.terminate()
            results.append({"id": "E4", "name": "coupon race (1 seat vs 8 parallel)",
                            "vuln": {"fired": v_win > 1, "wins": v_win},
                            "hard": {"fired": h_win > 1, "wins": h_win}})

    os.makedirs(os.path.dirname(a.json), exist_ok=True)
    json.dump({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "results": results}, open(a.json, "w", encoding="utf-8"), indent=2)
    print("-" * 96)
    print(f"[webcheck] {len(results)} classes checked -> {a.json}")
    if mismatches:
        print(f"[webcheck] {mismatches} MISMATCH(ES): a class did not behave as the docs claim")
    elif unverified:
        # never print the all-clear sentence while something went unmeasured: that sentence is a
        # claim about every class, and an unverified row is not evidence of anything
        print(f"[webcheck] {unverified} class(es) UNVERIFIED - not measured, so this run claims "
              "nothing about them (usually AV/EDR slowing the spawned server, or a busy port)")
    else:
        print("[webcheck] every class fires when vulnerable and is blocked when hardened")

    if not a.keep:
        for _, _, p in sides:
            if p:
                p.terminate()
    else:
        for m, base, _ in sides:
            print(f"[webcheck] {m}: {base}  (left running)")
    if unverified:
        return 2                    # distinct from 1: nothing contradicted a class, something was not measured
    return 0 if mismatches == 0 else 1


if __name__ == "__main__":
    try:                            # Windows console/encoding shim; no-op elsewhere
        import sys as _sys, os as _os
        _sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "lab"))
        import win
        win.ready()
    except ImportError:
        pass
    raise SystemExit(main())
