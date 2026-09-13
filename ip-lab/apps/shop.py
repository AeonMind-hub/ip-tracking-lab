#!/usr/bin/env python3
"""shop.py — the web attack surface, all of it, in one deliberately broken app.

    python3 apps/shop.py --port 8099 --seats 1        # vulnerable
    python3 apps/shop.py --port 8099 --seats 1 --racers 8   # ...and the race, every time
    python3 apps/shop.py --port 8098 --mode hard      # same app, fixed, for A/B

Every `# BUG:` line is a plant you can hit with curl in under a minute, against
127.0.0.1, on a database containing nothing but this file's own seed data. Nothing
here touches the network. Each route's comment names the fix, and `--mode hard`
switches the guard in so you can watch the same payload go from 200 to 401/403/404 or come
back inert. The harness that proves all of it is `python3 tools/webcheck.py`: it spawns both
modes, fires every payload at both, and fails if any class misbehaves.

The classes (map: notes/11-web-attack-surface.md). 27 rows are checked by webcheck; this
file carries 24 `# BUG:` markers, because two classes can share one broken line (C1/C2 read
the same path, D2 has two ways to win).

  A  injection into the query ....... A1 always-true, A2 UNION out of the table, A3 error
                                      echo, A4 login bypass, A5 user enumeration
  B  script in someone's browser ..... B1 reflected, B2 stored, B3 uploaded-then-served-as-HTML
  C  file paths ...................... C1 traversal via .., C2 absolute path accepted
  D  who you are vs what you may ..... D1 open redirect, D2 JWT alg=none/unsigned,
                                      D3 IDOR, D4 missing function-level authorisation
  E  logic & state ................... E1 mass assignment (role), E2 client-side price,
                                      E3 CSRF by GET, E4 coupon race (check-then-act)
  F  configuration & disclosure ...... F1 /.env, F2 /debug, F3 robots.txt, F4 directory
                                      listing, F5 version headers; and no rate limit
  G  files from clients .............. G1 suffix-only upload check, served from this origin
  H  session cloning ................ H1 replay a stolen token from another device,
                                      H2 session fixation (sid survives authentication),
                                      H3 the session table is readable by a customer

Do not run this on an interface that faces the internet. It is a hole by design.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
from html import escape as _esc
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = os.path.join(ROOT, "out", "shop.sqlite")
UPLOAD_DIR = os.path.join(ROOT, "out", "uploads")
JWT_SECRET = "correct-horse-battery"           # leaked on purpose: /debug

CFG = {"mode": "vuln", "show_sql": True, "atomic": False, "leak_secret": True, "bind_session": False}
CFG["racers"] = 1                              # how many redemptions the race demo overlaps
LOCK = threading.Lock()                        # present; the bugs just do not all use it
_BARRIER = None                            # the race window's gate; see _race_window
_BARRIER_LOCK = threading.Lock()
NOTES: list[dict] = []                         # the stored-XSS guestbook
COUPON = {"code": "LAUNCH25", "remaining": 1, "used_by": []}
DRAINED: list[str] = []                        # the "attacker listener", simulated in-process
SESSIONS: dict[str, dict] = {}                 # sid -> {sub, profiles:[{ua, peer}]}
AUDIT: list[tuple[str, str, int]] = []

USERS = {
    "ada@shop.test":  {"id": 1, "hash": hashlib.md5(b"password123").hexdigest(), "role": "customer"},
    "ben@shop.test":  {"id": 2, "hash": hashlib.md5(b"hunter2hunter2").hexdigest(), "role": "customer"},
    "boss@shop.test": {"id": 3, "hash": hashlib.md5(b"Tr0ub4dor&3").hexdigest(), "role": "admin"},
}
ORDERS = {
    1: [{"ref": "NGN-4411", "total": 89000}, {"ref": "NGN-4412", "total": 12500}],
    2: [{"ref": "NGN-9001", "total": 1200000}],
    3: [{"ref": "NGN-ADMIN", "total": 5000}],
}


def hard() -> bool:
    return CFG["mode"] == "hard"


# ----------------------------------------------------------------- the database
def db() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    conn = sqlite3.connect(DB, check_same_thread=False)
    conn.execute("CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY, name TEXT, price INT, sku TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER, email TEXT, hash TEXT)")
    if not conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
        conn.executemany("INSERT INTO users VALUES(?,?,?)",
                         [(v["id"], e, v["hash"]) for e, v in USERS.items()])
        conn.commit()
    if not conn.execute("SELECT COUNT(*) FROM products").fetchone()[0]:
        conn.executemany("INSERT INTO products(name,price,sku) VALUES(?,?,?)", [
            ("Lagos tote bag", 8900, "BAG-01"), ("Damask napkin set", 14500, "TEE-02"),
            ("Aso-oke headwrap", 23000, "HNY-03"), ("Adire wall hanging", 56000, "WTF-04"),
            ("Woven basket XL", 31000, "BAS-05")])
        conn.commit()
    return conn


def product_search(term: str) -> tuple[str, list]:
    """BUG: string-formatted SQL. Quotes are the only thing separating data from code and
    the user supplies them. Fix: `product_search_safe`."""
    q = "SELECT id,name,price,sku FROM products WHERE name LIKE '%" + term + "%'"
    try:
        return q, db().execute(q).fetchall()
    except sqlite3.Error as exc:
        # BUG: the database's own words reach the browser, which is a map of the query
        return q, [[0, f"SQL error: {exc}", 0, "syntax echoed to the browser"]]


def product_search_safe(term: str) -> tuple[str, list]:
    """Fix: bound parameters + escaped LIKE wildcards. Same shape, different safety."""
    like = "%" + term.replace("\\", "\\\\").replace("%", r"\%").replace("_", r"\_") + "%"
    rows = db().execute(r"SELECT id,name,price,sku FROM products WHERE name LIKE ? ESCAPE '\'", (like,)).fetchall()
    return "SELECT ... WHERE name LIKE ? ESCAPE '\\'", list(rows)


def login_sql(email: str, pw: str) -> dict | None:
    """BUG: the classic auth bypass. `email=' OR 1=1--` returns a row and comments the
    password away. Fix: `login_hard`."""
    q = ("SELECT id FROM users WHERE email='" + email + "' AND hash='"
         + hashlib.md5(pw.encode()).hexdigest() + "'")
    try:
        row = db().execute(q).fetchone()
    except sqlite3.Error:
        row = None
    return {"id": row[0]} if row else None


def login_hard(email: str, pw: str) -> dict | None:
    """Fix: bound parameter, constant-time compare, and the caller cannot tell an unknown
    user from a wrong password."""
    row = db().execute("SELECT id,hash FROM users WHERE email=?", (email,)).fetchone()
    if not row:
        return None
    return {"id": row[0]} if hmac.compare_digest(row[1], hashlib.md5(pw.encode()).hexdigest()) else None


# ------------------------------------------------------------------ the tokens
def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def jwt_make(claims: dict, secret: str = JWT_SECRET) -> str:
    signing_input = (b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
                     + "." + b64u(json.dumps(claims).encode()))
    sig = base64.urlsafe_b64encode(hmac.new(secret.encode(), signing_input.encode(),
                                            hashlib.sha256).digest()).decode().rstrip("=")
    return f"{signing_input}.{sig}"


def _split(tok: str):
    parts = tok.split(".")
    if len(parts) != 3:
        return None
    try:
        hdr = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    except Exception:  # noqa: BLE001
        return None
    return hdr, claims, parts[2]


def jwt_verify(tok: str) -> dict | None:
    """BUG (D2): the token's own header decides how it is checked, and `none` means "no
    check". Even with HS256 the signature is never compared. Fix: `jwt_guard`."""
    parsed = _split(tok)
    if not parsed:
        return None
    hdr, claims, _sig = parsed
    if hdr.get("alg") == "none":
        return claims                                     # BUG: unsigned token accepted
    exp = claims.get("exp")
    if exp and time.time() > exp:
        return None
    return claims                                         # BUG: signature never verified


def jwt_guard(tok: str, secret: str = JWT_SECRET) -> dict | None:
    """Fix: the server picks the algorithm, the signature is compared in constant time,
    `exp` is enforced, and there is no code path that skips verification."""
    parsed = _split(tok)
    if not parsed:
        return None
    hdr, claims, sig = parsed
    if hdr.get("alg") != "HS256":
        return None
    head_payload = tok.rsplit(".", 1)[0]
    want = base64.urlsafe_b64encode(hmac.new(secret.encode(), head_payload.encode(),
                                             hashlib.sha256).digest()).decode().rstrip("=")
    if not hmac.compare_digest(want, sig):
        return None
    if claims.get("exp") and time.time() > claims["exp"]:
        return None
    return claims


# --------------------------------------------------------------- file handling
# C1/C2 need a file to escape *to*. On macOS and Linux that is genuinely /etc/passwd, which is
# the honest demonstration. On Windows there is no such file, and a demo that answers "404 - not
# applicable on this platform" teaches nothing, so the lab plants its own copy beside the uploads
# directory and points the payload there. The vulnerability being shown is the missing containment
# in `os.path.join(UPLOAD_DIR, name)`, not the contents of a Unix file - which is exactly why
# substituting a fixture changes nothing about what the class proves, and why `safe_path` still
# refuses both payloads in --mode hard.
REAL_PASSWD = "/etc/passwd"
LAB_PASSWD = os.path.join(ROOT, "out", "lab_etc", "passwd")
LAB_PASSWD_BODY = ("root:x:0:0:root:/root:/bin/bash\n"
                   "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                   "ada:x:1000:1000:Ada:/home/ada:/bin/bash\n"
                   "# planted by apps/shop.py - the lab stands in for /etc/passwd on Windows\n")


def plant_passwd() -> str:
    os.makedirs(os.path.dirname(LAB_PASSWD), exist_ok=True)
    if not os.path.isfile(LAB_PASSWD):
        with open(LAB_PASSWD, "w", encoding="utf-8") as fh:
            fh.write(LAB_PASSWD_BODY)
    return LAB_PASSWD


def passwd_target() -> str:
    """Where an `etc/passwd` payload lands on this machine: the real file, or the lab's fixture."""
    return REAL_PASSWD if os.path.isfile(REAL_PASSWD) else plant_passwd()


def traversal_target(name: str) -> str:
    """The path the *vulnerable* reader would open for a given `?name=` payload. Pure, so the
    tests can pin it without a socket. Absolute payloads on a POSIX box resolve to the real
    /etc/passwd via os.path.join; anything else is joined onto the uploads dir (that IS the bug)."""
    raw = str(name).replace("\\", "/")
    cand = os.path.join(UPLOAD_DIR, raw)
    if raw.endswith("etc/passwd") and not os.path.isfile(cand):
        return passwd_target()
    return cand


# --------------------------------------------------------------- file handling
def safe_path(base_dir: str, name: str) -> str | None:
    """Fix for traversal: resolve first, then prove containment. Never string-compare the
    raw input - `..`, double-encoding and symlinks all walk past `if ".." in name`."""
    if os.path.isabs(name) or name.startswith("~"):
        return None
    base = os.path.realpath(base_dir)
    cand = os.path.realpath(os.path.join(base, name))
    return cand if (cand == base or cand.startswith(base + os.sep)) else None


def safe_next(nxt: str) -> str:
    """Fix for open redirect: a same-origin relative path only."""
    return nxt if (nxt.startswith("/") and not nxt.startswith("//") and not nxt.startswith("\\")) else "/"


def esc(s: str) -> str:
    """Fix for XSS: escape at render time, in the context you are rendering into."""
    return _esc(str(s), quote=True)


def bind_profile(sid: str, ua: str, peer: str) -> bool:
    """H1's fix: a session may only be used by the device profile that created it.
    A stolen token replayed from elsewhere fails even though the token is valid."""
    prof = SESSIONS.get(sid)
    if not prof:
        return True
    if not CFG["bind_session"]:
        return True
    want = prof.get("bound")
    return want is None or want == fingerprint(ua, peer)


def fingerprint(ua: str, peer: str) -> str:
    return hashlib.sha256(f"{ua}|{peer}".encode()).hexdigest()[:16]


# ---------------------------------------------------------------- the handlers
def _race_window(expect: int, seconds: float = 1.0) -> None:
    """Hold a vulnerable redemption at its check point until `expect` of them are inside it.

    The bug is a genuine read-modify-write: eligibility is decided out here, then spent on that
    stale belief in there. Whether it *shows up* as an oversell depends on the requests overlapping
    inside that gap, and 8 client threads do not reliably do that - measured on a real Windows box,
    exactly one request was ever in flight, so the app reported "1 winner" for 1 seat and the class
    looked FIXED while the code was still broken. A fixed `sleep(0.05)` leaves the lesson to
    scheduler luck; a barrier makes it happen every time, and `seconds` means a lone caller never
    hangs waiting for peers that are not coming.

    `--racers 8` is what tools/webcheck.py passes because it knows it is about to fire 8. The
    default of 1 leaves a hand-run instance behaving like an ordinary web app.
    """
    global _BARRIER
    if expect <= 1:
        time.sleep(0.05)                            # manual use: the old, luck-based window
        return
    with _BARRIER_LOCK:
        if _BARRIER is None or getattr(_BARRIER, "parties", 0) != expect:
            _BARRIER = threading.Barrier(expect)
        bar = _BARRIER
    try:
        bar.wait(timeout=seconds)                   # everyone goes on together, or nobody does
    except threading.BrokenBarrierError:
        with _BARRIER_LOCK:
            if _BARRIER is bar:
                _BARRIER = None                     # the next round gets a clean gate


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "nginx/1.24.0 (Ubuntu)"   # honesty: no. That header is a lie.

    def log_message(self, fmt, *args):
        return

    @property
    def is_hard(self) -> bool:
        return hard()

    def send(self, code: int, body: str, ctype: str = "text/html; charset=utf-8",
             extra: dict | None = None):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if not hard():
            self.send_header("Server", self.server_version)     # BUG: F5 fingerprintable version
            self.send_header("X-Powered-By", "PHP/7.4.3")       # BUG: F5 another lie, another clue
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def page(self, title: str, body: str, code: int = 200):
        shell = """<!doctype html><meta charset=utf-8><title>shop (LAB)</title>
<style>body{font:15px/1.5 system-ui;max-width:860px;margin:2rem auto;padding:0 1rem}
h2{margin:1.6rem 0 .4rem}table{border-collapse:collapse;width:100%}td,th{border:1px solid #d8d8d8;padding:.35rem}
code,pre{background:#f4f4f4;padding:.15rem .3rem;border-radius:4px;font-size:13px}
.hint{color:#666;font-size:13px}a{color:#06c}</style>
<p class=hint><b>LAB ONLY</b> - deliberately vulnerable, localhost only, nothing real in here.
 &middot; <a href=/>home</a> <a href=/search?q=bag>search</a> <a href=/notes>guestbook</a>
 <a href=/account/orders>my orders</a> <a href=/admin>admin</a> <a href=/debug>debug</a>
 &middot; <b>__ME__</b></p>
"""
        who = self.me()
        label = f"signed in: {who['sub']} ({who.get('role')})" if who else "anonymous"
        self.send(code, shell.replace("__ME__", label) + f"<h1>{title}</h1>" + body)

    def form(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode(errors="replace") if n else ""
        if raw.strip().startswith("{"):
            try:
                return json.loads(raw)
            except Exception:  # noqa: BLE001
                return {}
        return {k: v[0] for k, v in parse_qs(raw).items()}

    def cookie(self, name: str) -> str | None:
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return None

    def token(self) -> str | None:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:].strip()
        return self.cookie("session")

    def me(self) -> dict | None:
        tok = self.token()
        if not tok:
            return None
        claims = jwt_guard(tok) if hard() else jwt_verify(tok)
        if not claims:
            return None
        # H1: in hard mode the session must also belong to this device profile
        sid = self.cookie("sid") or claims.get("sid")
        if sid and not bind_profile(sid, self.headers.get("User-Agent", ""), self.client_address[0]):
            return None
        return claims

    # -- GET
    def do_GET(self):
        u = urlparse(self.path)
        path, q = u.path, {k: v[0] for k, v in parse_qs(u.query).items()}
        AUDIT.append((time.strftime("%H:%M:%S"), path, 0))

        if path == "/":
            rows = "".join(f"<tr><td>{r[0]}</td><td>{esc(str(r[1]))}</td><td>N{r[2]:,}</td></tr>"
                           for r in db().execute("SELECT id,name,price FROM products").fetchall())
            return self.page("Shop", "<p>Everything below is fake. The vulnerabilities are not.</p>"
                                  f"<table><tr><th>id</th><th>name</th><th>price</th></tr>{rows}</table>")

        if path == "/search":
            term = q.get("q", "")
            if hard():
                query, rows = product_search_safe(term)
                body = ("<h2>Search: " + esc(term) + "</h2><table>" + "".join(
                    f"<tr><td>{r[0]}</td><td>{esc(str(r[1]))}</td><td>N{r[2]:,}</td>"
                    f"<td>{esc(str(r[3]))}</td></tr>" for r in rows) + "</table>")
            else:
                query, rows = product_search(term)
                # BUG: A1/A2 - the term is inside the SQL string; B1 - and inside the HTML
                body = (f"<h2>Search: {term}</h2>"
                        f"<p class=hint>query: <code>{_esc(query)}</code></p>"
                        "<table><tr><th>id</th><th>name</th><th>price</th><th>sku</th></tr>"
                        + "".join(f"<tr><td>{r[0]}</td><td>{r[1]}</td><td>N{r[2]:,}</td><td>{r[3]}</td></tr>"
                                  for r in rows) + "</table>")
            return self.page("Search", body)

        if path == "/notes":
            raw = "".join(f"<li>{n['who']}: {n['text']}</li>" for n in NOTES)
            listing = esc(raw) if hard() else raw                      # BUG: B2 stored XSS
            return self.page("Guestbook", f"<ul>{listing}</ul><form method=post action=/notes>"
                                   "<input name=note size=60 placeholder='leave a note'><button>Post</button></form>"
                                   "<p class=hint>stored XSS: post a note containing "
                                   "<code>&lt;img src=x onerror=alert(1)&gt;</code></p>")

        if path == "/file":
            name = q.get("name", "receipt.txt")
            target = safe_path(UPLOAD_DIR, name) if hard() else traversal_target(name)
            if target and os.path.isfile(target):
                if hard():
                    # the fix for "upload becomes a page on this origin"
                    return self.send(200, open(target, encoding="utf-8", errors="replace").read(), "text/plain; charset=utf-8",
                                     {"X-Content-Type-Options": "nosniff",
                                      "Content-Disposition": "attachment"})
                # BUG: B3/C1 - user bytes served as HTML from the app's own origin
                return self.send(200, open(target, encoding="utf-8", errors="replace").read())
            return self.send(404, "not found")

        if path == "/victim":
            who = q.get("q", "you")
            if hard():
                return self.page("Account", "<p>" + esc(who) + "</p>")
            # BUG: the reflected payload here is what runs the theft; the beacon line below is
            # what an attacker's <script> would do, and /drainer is the listener.
            return self.page("Account", f"<p>{who}</p><script>new Image().src='/drainer?c='"
                                        f"+encodeURIComponent(document.cookie)</script>")

        if path == "/drainer":
            val = q.get("c", "")
            DRAINED.append(val)
            return self.send(200, "1", "image/gif")

        if path == "/drained":
            return self.send(200, json.dumps({"listener": "attacker.example (simulated in-process)",
                                              "captured": DRAINED,
                                              "note": "in a real incident this is the attacker's log, "
                                                      "not yours - the lesson is that HttpOnly would "
                                                      "have made every entry empty"}), "application/json")

        if path == "/account/orders":
            who = self.me()
            if not who:
                return self.send(401, json.dumps({"error": "login required",
                                                  "why": "no token, or the token failed "
                                                         "verification / device binding"}), "application/json")
            uid = int(q.get("id", who.get("id", 0)))
            # BUG: D3 IDOR - the id comes from the query and nothing asks whether it is yours
            return self.send(200, json.dumps({"orders": ORDERS.get(uid, []),
                                              "requested_by": who.get("sub")}), "application/json")

        if path == "/admin":
            who = self.me()
            if not who:
                return self.send(403, json.dumps({"error": "admin only",
                                                  "hint": "any token that parses passes"}), "application/json")
            if hard() and who.get("role") != "admin":
                return self.send(403, json.dumps({"error": "admin only"}), "application/json")
            # BUG: D4 - presence of a session is treated as authority
            return self.send(200, json.dumps({"users": {k: v["role"] for k, v in USERS.items()},
                                              "orders": ORDERS, "role_seen": who.get("role")}), "application/json")

        if path == "/admin/sessions":
            who = self.me()
            if not who:
                return self.send(401, json.dumps({"error": "login required"}), "application/json")
            if hard():
                if who.get("role") != "admin":
                    return self.send(403, json.dumps({"error": "admin only"}), "application/json")
                return self.send(200, json.dumps({"sessions": {s: {"sub": d.get("sub")}
                                                                 for s, d in SESSIONS.items()},
                                                   "note": "identities only; device profiles are in the "
                                                           "detection layer, not exposed here"}), "application/json")
            # BUG: H3 - every session, its owner, and the device profiles that used it
            return self.send(200, json.dumps({"sessions": SESSIONS}), "application/json")

        if path == "/logout":
            nxt = q.get("next", "/")
            if hard():
                nxt = safe_next(nxt)                                   # the fix: same-origin relative only
            # BUG: D1 open redirect - any absolute URL is accepted, so this domain vouches for it
            return self.send(302, "", "text/plain",
                             {"Location": nxt, "Set-Cookie": "session=; Path=/; Max-Age=0"})

        if path == "/session":
            sid = q.get("sid") or ("S" + secrets.token_hex(4))
            SESSIONS.setdefault(sid, {"sub": None, "profiles": [], "bound": None})
            return self.send(200, json.dumps({"sid": sid, "note": "sid accepted from the client"}),
                             "application/json")

        if path in ("/debug", "/debug/vars") and not hard():
            return self.send(200, json.dumps({"mode": CFG["mode"],
                                              "jwt_secret": JWT_SECRET if CFG["leak_secret"] else "[redacted]",
                                              "db_path": DB, "uploads": UPLOAD_DIR,
                                              "sessions": len(SESSIONS),
                                              "recent": AUDIT[-25:]}, indent=2), "application/json")  # BUG: F2

        if path == "/.env" and not hard():
            return self.send(200, f"JWT_SECRET={JWT_SECRET}\nDB_PATH={DB}\nADMIN_EMAIL=boss@shop.test\n",
                             "text/plain")                                                            # BUG: F1

        if path == "/robots.txt":
            return self.send(200, ("User-agent: *\nDisallow: /debug\nDisallow: /.env\nDisallow: /admin\n"
                                   "Disallow: /admin/sessions\nDisallow: /account/orders\n") if not hard()
                             else "User-agent: *\n", "text/plain")                                    # BUG: F3

        if path == "/uploads/":
            if hard():
                return self.send(403, "forbidden", "text/plain")
            files = sorted(os.listdir(UPLOAD_DIR)) if os.path.isdir(UPLOAD_DIR) else []
            return self.send(200, "<h2>index of /uploads</h2><ul>"                                  # BUG: F4
                             + "".join(f'<li><a href="/file?name={f}">{f}</a></li>' for f in files)
                             + "</ul>")

        if path == "/cart/coupon":
            if hard():
                return self.send(405, json.dumps({"error": "state change needs POST and a token",
                                                  "allow": "POST /cart/coupon"}), "application/json")
            return self._coupon(q.get("code", ""))

        if path == "/healthz":
            return self.send(200, json.dumps({"ok": True, "mode": CFG["mode"], "flow": len(AUDIT)}),
                             "application/json")

        return self.page("404", "<p>no such page</p>", code=404)

    # -- POST
    def do_POST(self):
        u = urlparse(self.path)
        path, f = u.path, self.form()
        AUDIT.append((time.strftime("%H:%M:%S"), path, 0))

        if path == "/login":
            return self._login(f)

        if path == "/session/auth":
            sid = f.get("sid") or self.cookie("sid") or ""
            rotated = False
            if hard():
                sid, rotated = "S" + secrets.token_hex(6), True       # the fix: rotate on auth
            s = SESSIONS.setdefault(sid, {"sub": None, "profiles": [], "bound": None})
            s["sub"] = f.get("as", "ada@shop.test")
            s["profiles"].append({"ua": self.headers.get("User-Agent"), "peer": self.client_address[0],
                                  "ts": time.strftime("%H:%M:%S")})
            if hard():
                s["bound"] = fingerprint(self.headers.get("User-Agent", ""), self.client_address[0])
            # BUG: H2 fixation - a client-chosen sid is still the sid after authentication
            return self.send(200, json.dumps({"sid_used": sid, "rotated": rotated,
                                              "note": "hard mode rotates the session id when a "
                                                      "principal changes; vuln mode keeps the one "
                                                      "the attacker planted"}), "application/json")

        if path == "/xss-exfil":
            # stands in for the beacon that /victim's <script> would fire in a browser
            if hard():
                return self.send(200, json.dumps({"stolen": "", "why": "the input was escaped, so no "
                                                                   "script ran; and the cookie is HttpOnly, "
                                                                   "so document.cookie is empty"}),
                                 "application/json")
            val = f.get("c", "") or (DRAINED[-1] if DRAINED else "")
            if val:
                DRAINED.append(val)
            # BUG: H1 - whatever the XSS read is now the attacker's, and it is a bearer token
            return self.send(200, json.dumps({"stolen": val}), "application/json")

        if path == "/replay":
            tok = f.get("token", "")
            claims = (jwt_guard(tok) if hard() else jwt_verify(tok))
            if not claims:
                return self.send(401, json.dumps({"replayed": False, "error": "token rejected"}), "application/json")
            sid = claims.get("sid")
            if hard() and sid and not bind_profile(sid, self.headers.get("User-Agent", ""),
                                                   self.client_address[0]):
                return self.send(403, json.dumps({"replayed": False,
                                                  "error": "device profile does not match the session"}),
                                 "application/json")
            return self.send(200, json.dumps({"replayed": True, "as": claims.get("sub"),
                                              "orders": ORDERS.get(claims.get("id"), [])}), "application/json")

        if path == "/notes":
            NOTES.append({"who": (self.me() or {}).get("sub", "guest"), "text": f.get("note", "")})
            return self.send(302, "", extra={"Location": "/notes"})                     # BUG: E3 no CSRF token

        if path == "/register":
            # BUG: E1 mass assignment - the client may set any model field, including role
            role = "customer" if hard() else f.get("role", "customer")
            who = {"sub": f.get("email", "anon"), "id": len(USERS) + 3, "role": role}
            tok = jwt_make({**who, "exp": time.time() + 3600})
            return self.send(200, json.dumps({"created": who, "token": tok,
                                              "note": "self-issued token; paste it as Authorization: Bearer"}),
                             "application/json")

        if path == "/upload":
            name = f.get("filename", "upload.bin")
            data = f.get("data", "")
            if hard():
                magic = {"\x89PNG": ".png", "\xff\xd8\xff": ".jpg", "%PDF": ".pdf"}.get(data[:4], "")
                if not magic:
                    return self.send(415, json.dumps({"rejected": "content does not match a permitted type"}),
                                     "application/json")
                name = os.urandom(6).hex() + magic          # the server names it, from the content
            if name.lower().endswith((".png", ".jpg", ".txt", ".pdf", ".html", ".svg", ".php")):
                os.makedirs(UPLOAD_DIR, exist_ok=True)
                dest = os.path.join(UPLOAD_DIR, os.path.basename(name))
                open(dest, "w", encoding="utf-8").write(data)
                # BUG: G1 - a suffix test on a client-supplied name, served from this origin
                return self.send(200, json.dumps({"saved": os.path.basename(dest),
                                                  "url": "/file?name=" + os.path.basename(dest),
                                                  "bytes": len(data)}), "application/json")
            return self.send(400, json.dumps({"rejected": name,
                                              "hint": "the check is a suffix, not a type"}), "application/json")

        if path == "/cart/coupon":
            if hard():
                return self._coupon(f.get("code", ""))
            return self.send(405, json.dumps({"error": "in vuln mode this is a GET - that is the bug"}),
                             "application/json")

        if path == "/cart/add":
            if hard():
                row = db().execute("SELECT price FROM products WHERE id=?", (f.get("id", 0),)).fetchone()
                return self.send(200, json.dumps({"added": f.get("id", "?"), "charged": row[0] if row else None,
                                                  "note": "price recomputed server-side; the client number is ignored"}),
                                 "application/json")
            # BUG: E2 - the charge amount arrives in the request body
            return self.send(200, json.dumps({"added": f.get("id", "?"), "charged": f.get("price", "0"),
                                              "catalog": db().execute("SELECT price FROM products WHERE id=?",
                                                                      (f.get("id", 0),)).fetchone()}),
                             "application/json")

        return self.send(404, "not found", "text/plain")

    def do_HEAD(self):
        self.do_GET()

    # -- pieces kept separate so they can be unit-tested without a socket
    def _login(self, f: dict):
        email, pw = f.get("email", ""), f.get("password", "")
        if hard():
            ok = login_hard(email, pw)
            if ok:
                sid = "S" + secrets.token_hex(6)
                SESSIONS[sid] = {"sub": email, "profiles": [{"ua": self.headers.get("User-Agent"),
                                                              "peer": self.client_address[0]}],
                                 "bound": fingerprint(self.headers.get("User-Agent", ""), self.client_address[0])}
                tok = jwt_make({"sub": email, "id": ok["id"], "role": USERS[email]["role"],
                                "sid": sid, "exp": time.time() + 3600})
                return self.send(200, json.dumps({"login": "ok", "sid": sid,
                                                  "note": "unknown user and bad password are indistinguishable"}),
                                 "application/json",
                                 extra={"Set-Cookie": f"session={tok}; Path=/; HttpOnly; Secure; SameSite=Lax"})
            return self.send(401, json.dumps({"error": "invalid credentials"}), "application/json")
        bypass = login_sql(email, pw)                          # BUG: A4 ' OR 1=1-- walks through
        known = email in USERS
        if bypass and not known:
            email = next((k for k, v in USERS.items() if v["id"] == bypass["id"]), email)
        if not bypass and not known:
            return self.send(404, json.dumps({"error": "no such user"}), "application/json")   # BUG: A5
        if not bypass:
            return self.send(401, json.dumps({"error": "bad password"}), "application/json")
        sid = self.cookie("sid") or "S" + secrets.token_hex(4)
        SESSIONS.setdefault(sid, {"sub": email, "profiles": [], "bound": None})
        SESSIONS[sid]["sub"] = email
        SESSIONS[sid]["profiles"].append({"ua": self.headers.get("User-Agent"),
                                          "peer": self.client_address[0], "ts": time.strftime("%H:%M:%S")})
        tok = jwt_make({"sub": email, "id": USERS[email]["id"], "role": USERS[email]["role"],
                        "sid": sid, "exp": time.time() + 3600})
        # BUG: no HttpOnly/Secure/SameSite, and the sid is not rotated (H1, H2)
        return self.send(302, json.dumps({"sid": sid}), "text/plain",
                         {"Location": "/", "Set-Cookie": f"session={tok}; Path=/"})

    def _coupon(self, code: str) -> None:
        """E3 + E4: a GET that mutates state with no CSRF token, and a decision made outside
        the critical section. Fix (hard mode): POST, and re-validate inside the lock."""
        with LOCK:
            eligible = COUPON["remaining"] > 0 and code == COUPON["code"]
        if not eligible:
            self.send(409, json.dumps({"error": "coupon exhausted", "used_by": COUPON["used_by"]}),
                      "application/json")
            return
        who = (self.me() or {}).get("sub", "anonymous")
        if CFG["atomic"]:
            with LOCK:                                          # the fix: re-check inside the lock
                if COUPON["remaining"] > 0:
                    COUPON["remaining"] -= 1
                    COUPON["used_by"].append(who)
                    self.send(200, json.dumps({"ok": True, "who": who, "atomic": True,
                                               "remaining": COUPON["remaining"]}), "application/json")
                else:
                    self.send(409, json.dumps({"error": "spent", "used_by": COUPON["used_by"]}),
                              "application/json")
            return
        # BUG: E4 the decision was made outside, the write happens later on the stale belief.
        # Any read-modify-write looks like this: inventory, wallet balance, coupon, referral
        # credit, rate-limit counter.
        _race_window(CFG["racers"])   # force the window, so the oversell is not a coin-flip
        with LOCK:
            COUPON["remaining"] -= 1
            COUPON["used_by"].append(who)
        self.send(200, json.dumps({"ok": True, "who": who, "remaining": COUPON["remaining"]}),
                  "application/json")


# ----------------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--mode", choices=["vuln", "hard"], default="vuln")
    ap.add_argument("--no-show-sql", action="store_true")
    ap.add_argument("--atomic", action="store_true", help="make the coupon update atomic (the fix)")
    ap.add_argument("--no-leak-secret", action="store_true")
    ap.add_argument("--seats", type=int, default=1, help="coupon redemptions allowed (raise it to re-run the race)")
    ap.add_argument("--racers", type=int, default=1,
                    help="N: make N concurrent redemptions meet inside the vulnerable window "
                         "(tools/webcheck.py passes 8; leave at 1 when running by hand)")
    ap.add_argument("--selftest", action="store_true", help="no socket: assert every guard works")
    a = ap.parse_args()
    COUPON["remaining"] = a.seats
    CFG["racers"] = max(1, a.racers)
    CFG.update(mode=a.mode, show_sql=(not a.no_show_sql) and a.mode != "hard",
               atomic=a.atomic or a.mode == "hard", leak_secret=not a.no_leak_secret,
               bind_session=(a.mode == "hard"))

    if a.selftest:
        return selftest()

    if hard():                       # the automatic Server header is the leak; kill it at source
        Handler.server_version = "shop"
        Handler.sys_version = ""
    db()
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    open(os.path.join(UPLOAD_DIR, "receipt.txt"), "w", encoding="utf-8").write("Lagos order NGN-4411 - paid 89,000\n")
    print(f"[shop] 127.0.0.1:{a.port}  mode={CFG['mode']}  db={DB}")
    print("[shop] bound to localhost only. Ctrl-C to stop.")
    ThreadingHTTPServer(("127.0.0.1", a.port), Handler).serve_forever()
    return 0


def selftest() -> int:
    """Guard logic without a socket. Run: python3 apps/shop.py --selftest"""
    ok = True

    def check(name: str, cond: bool):
        nonlocal ok
        print(f"  {'PASS' if cond else 'FAIL'}  {name}")
        ok = ok and cond

    CFG.update(mode="vuln", atomic=False, bind_session=False)
    check("sqli always-true stays inside the query text", "LIKE '%" in product_search("' OR 1=1--")[0])
    check("safe search binds parameters", "?" in product_search_safe("' OR 1=1--")[0])
    check("safe search neutralises LIKE wildcards", product_search_safe("%")[1] == [])
    check("login_sql is injectable", login_sql("' OR 1=1--", "x") is not None)
    check("login_hard rejects the same payload", login_hard("' OR 1=1--", "x") is None)
    check("login_hard accepts the real password", login_hard("ada@shop.test", "password123") == {"id": 1})
    tok = jwt_make({"sub": "ada@shop.test", "id": 1, "role": "customer", "exp": time.time() + 60})
    forged = b64u(json.dumps({"alg": "none", "typ": "JWT"}).encode()) + "." + \
        b64u(json.dumps({"sub": "boss@shop.test", "id": 3, "role": "admin"}).encode()) + "."
    check("alg=none forgery accepted while vulnerable", (jwt_verify(forged) or {}).get("role") == "admin")
    check("alg=none forgery rejected by guard", jwt_guard(forged) is None)
    check("real token still works under guard", (jwt_guard(tok) or {}).get("sub") == "ada@shop.test")
    check("tampered signature rejected", jwt_guard(tok.rsplit(".", 1)[0] + "." + b64u(b"nope")) is None)
    check("expired token rejected", jwt_guard(jwt_make({"sub": "x", "exp": time.time() - 1})) is None)
    check("traversal blocked by safe_path", safe_path(UPLOAD_DIR, "../../../../../etc/passwd") is None)
    check("absolute path rejected", safe_path(UPLOAD_DIR, "/etc/passwd") is None)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    open(os.path.join(UPLOAD_DIR, "x.txt"), "w", encoding="utf-8").write("hi")
    check("legit file still readable", open(safe_path(UPLOAD_DIR, "x.txt"), encoding="utf-8", errors="replace").read() == "hi")
    for pay in ("../" * 5 + "etc/passwd", "/etc/passwd", "..\\..\\..\\etc\\passwd"):
        t = traversal_target(pay)
        check(f"traversal payload lands on a real file on this OS ({pay[:18]}...)",
              os.path.isfile(t) and open(t, encoding="utf-8", errors="replace").read().startswith("root:x:0:0"))
    check("the hard-mode guard refuses the payloads that mean traversal on this OS",
          all(safe_path(UPLOAD_DIR, pay) is None
              for pay in ("../" * 5 + "etc/passwd", "/etc/passwd")))
    # Backslash is only a path separator on Windows. On POSIX `..\..\..\etc\passwd` is one weird
    # filename that stays inside the uploads dir, and a guard that "refused" it there would be
    # cargo-culting. This pins the difference instead of pretending a separator exists everywhere.
    bs = safe_path(UPLOAD_DIR, "..\\..\\..\\etc\\passwd")
    check("backslash traversal is refused only where backslash separates paths",
          bs is None if os.sep == "\\" else (bs is not None and not os.path.isfile(bs)))
    check("nested path inside uploads still readable",
          safe_path(UPLOAD_DIR, "sub/../x.txt") == os.path.realpath(os.path.join(UPLOAD_DIR, "x.txt")))
    link = os.path.join(UPLOAD_DIR, "escape")
    try:
        os.symlink("/etc/passwd", link)
        check("symlink out of the tree is caught", safe_path(UPLOAD_DIR, "escape") is None)
    except OSError:
        check("symlink test skipped (no symlink permission)", True)
    finally:
        if os.path.islink(link):
            os.unlink(link)
    os.unlink(os.path.join(UPLOAD_DIR, "x.txt"))
    payload = "<script>alert(1)</script>"
    check("esc neutralises the script tag", "<script>" not in esc(payload) and "&lt;script&gt;" in esc(payload))
    check("esc quotes attributes too", '"' not in esc('"><svg onload=x>'))
    check("open redirect fix blocks absolute URL", safe_next("https://evil.test") == "/")
    check("open redirect fix blocks protocol-relative", safe_next("//evil.test") == "/")
    check("open redirect fix keeps a real relative path", safe_next("/account/orders") == "/account/orders")
    # H1/H2: device binding and rotation
    SESSIONS.clear()
    SESSIONS["S1"] = {"sub": "ada@shop.test", "profiles": [], "bound": fingerprint("RealBrowser/1", "10.0.0.5")}
    CFG.update(bind_session=False)
    check("without binding, a replayed session is accepted", bind_profile("S1", "AttackerUA", "10.9.9.9"))
    CFG.update(bind_session=True)
    check("with binding, a replayed session from another device is refused",
          not bind_profile("S1", "AttackerUA", "10.9.9.9"))
    check("with binding, the real device still works", bind_profile("S1", "RealBrowser/1", "10.0.0.5"))
    check("fingerprint is stable and short", len(fingerprint("a", "b")) == 16
          and fingerprint("a", "b") == fingerprint("a", "b"))
    # The race demo's only new mechanism is the forced window, so pin the mechanism on the real
    # code path: Handler._coupon with a stubbed transport, not a re-typed copy of the logic.
    class _Sock:
        def __init__(self):
            self.status, self.body = 0, ""

        def send(self, status, body, ctype="text/plain", headers=None):
            self.status, self.body = status, body

        def me(self):
            return {"sub": "buyer@example.test"}

    def _through_real_handler(atomic: bool, n: int = 8) -> int:
        COUPON["remaining"], COUPON["used_by"] = 1, []
        CFG.update(atomic=atomic, racers=n)
        sks = [_Sock() for _ in range(n)]
        th = [threading.Thread(target=Handler._coupon, args=(sk, "LAUNCH25")) for sk in sks]
        [x.start() for x in th]
        [x.join(timeout=20) for x in th]
        return sum(1 for sk in sks if sk.status == 200)

    loose = _through_real_handler(False)
    tight = _through_real_handler(True)
    check("1 seat, 8 concurrent redemptions -> 8 winners while the check is outside the lock",
          loose == 8)
    check("the same 8 against the atomic fix -> exactly 1 winner", tight == 1)
    # and the gate on its own, because the two rows above pass even without it: 8 plain threads in
    # one process overlap inside any sleep, whereas 8 HTTP requests need help to do it. These two
    # are what make the demo OS-independent, so they are what has to be tested.
    _held = []

    def _waiter():
        _t0 = time.time()
        _race_window(2, 3.0)
        _held.append(time.time() - _t0)

    _th = threading.Thread(target=_waiter)
    _th.start()
    time.sleep(0.25)                       # the peer deliberately arrives late
    _race_window(2, 3.0)
    _th.join(timeout=10)
    print(f"       (held {(_held[0] if _held else -1):.2f}s for the late peer)")
    check("the gate holds a caller until its peer shows up (this is the OS-independence)",
          bool(_held) and _held[0] >= 0.2)
    _t1 = time.time()
    _race_window(5, 0.3)                   # no peers at all: must be released by the timeout
    _alone = time.time() - _t1
    print(f"       lone caller released after {_alone:.2f}s (timeout was 0.3s)")
    check("a lone caller is released by the timeout instead of hanging on absent peers",
          0.25 <= _alone < 2.0)
    CFG.update(atomic=False, racers=1)
    COUPON["remaining"], COUPON["used_by"] = 1, []

    print("RESULT:", "all shop guards verified" if ok else "SHOP GUARD FAILURES")
    return 0 if ok else 1


if __name__ == "__main__":
    try:                            # Windows console/encoding shim; no-op elsewhere
        import sys as _sys, os as _os
        _sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "lab"))
        import win
        win.ready()
    except ImportError:
        pass
    raise SystemExit(main())
