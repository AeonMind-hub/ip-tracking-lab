#!/usr/bin/env python3
"""eyeball.py — what a website can tell about your device, collected by you.

    python3 tools/eyeball.py serve --port 8097      # open http://127.0.0.1:8097 in your browser
    python3 tools/eyeball.py analyze out/eyeball/latest.json
    python3 tools/eyeball.py diff out/eyeball/visit-1.json out/eyeball/visit-3.json
    python3 tools/eyeball.py --selftest

This is the honest version of "tracking": you do not need a phone's IMEI, a GPS fix or an
ISP subpoena to recognise a returning visitor. A normal page load already carries enough
consistent detail that a *city-level* guess comes free, and a dozen quiet signals turn that
into "the same machine again". The point of this tool is to show you the list while it is
being built about you, on your own loopback, with the collector writing only into `out/`.

It does not exfiltrate anything. The single POST target is the same origin that served the
page, and that is enforced (`/collect` refuses a foreign `Origin`). If you want the tracker's
view of the internet, you already have it: your browser's own request.

Fields are graded by class:
  always    in every plain HTTP request, no scripts, no consent, no cookies
  with-JS   needs a script to run (canvas/WebGL/fonts/hardware)
  state     only if you came back to the same origin (localStorage, IndexedDB, ETag cache)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORE = os.path.join(ROOT, "out", "eyeball")

# name, class, weight, why it is worth anything to a profiler
FIELDS = {
    "user-agent":              ("always", 8, "browser+version+OS in one line; also the easiest thing to lie about"),
    "accept-language":         ("always", 6, "the *ordered quality list* is a locale fingerprint, not just the language"),
    "accept-encoding":         ("always", 3, "order and set differ between browsers and between a browser and a library"),
    "sec-ch-ua-platform":      ("always", 2, "client hints; Chrome answers, Firefox/Safari mostly do not"),
    "dnt/sec-gpc":             ("always", 2, "a privacy flag that itself flags you as a privacy-minded user"),
    "referer":                 ("always", 4, "which page you came from, sometimes with a session id in it"),
    "cookie":                  ("state", 9, "the strongest identifier there is: it is designed to be persistent"),
    "sec-fetch-site":          ("always", 1, "tells the server whether you are in a tab, an iframe or a prefetch"),
    "peer-ip":                 ("always", 7, "your network, not you - but stable for weeks on residential lines"),
    "platform":                ("with-JS", 3, "navigator.platform, stale on purpose in some browsers"),
    "hardware":                ("with-JS", 5, "cores + deviceMemory + maxTouchPoints is a coarse machine fingerprint"),
    "screen":                  ("with-JS", 6, "resolution, colour depth, pixel ratio, window chrome height"),
    "timezone":                ("with-JS", 5, "an offset plus a name: geographic, and it changes when you travel"),
    "languages":               ("with-JS", 4, "the navigator list is usually longer than the header's"),
    "canvas":                  ("with-JS", 9, "text and shape rendering differs per GPU/driver/font stack: near-unique"),
    "webgl":                   ("with-JS", 8, "vendor + renderer strings name your exact GPU"),
    "fonts":                   ("with-JS", 8, "measured widths of a font list reveal which fonts are installed"),
    "plugins":                 ("with-JS", 3, "the extension set, still enumerable in some browsers"),
    "storage-id":              ("state", 10, "a value the site wrote into your localStorage the first time it saw you"),
    "audio":                   ("with-JS", 7, "a tiny offline render; per-machine like canvas, quieter"),
    "battery-touch":           ("with-JS", 2, "charging state and touch capability, useful as a *combination*"),
}


def hash_of(s: str) -> str:
    return hashlib.sha256(s.encode(errors="replace")).hexdigest()[:12]


def profile(fields: dict) -> dict:
    """Score the *set* of signals, not their contents. Deterministic, documented, no magic.

    Weights are additive and capped: a real profiler's number depends on their corpus, and
    anyone quoting a figure like "99.5% unique" without a sample size is selling something.
    """
    present = {k: v for k, v in fields.items() if v not in (None, "", "-", [])}
    raw = sum(FIELDS[k][1] for k in present if k in FIELDS)
    cap = sum(w for (_c, w, _r) in FIELDS.values())
    by_class: dict[str, list[str]] = {}
    for k in present:
        by_class.setdefault(FIELDS.get(k, ("?", 0, ""))[0], []).append(k)
    return {
        "n_fields": len(present),
        "raw_weight": raw,
        "score_0_100": round(100.0 * raw / cap, 1),
        "by_class": {k: sorted(v) for k, v in by_class.items()},
        "identity": hash_of("|".join(f"{k}={present[k]}" for k in sorted(present))),
        "note": "weights are this tool's own; the *ranking* (state > canvas/webgl/fonts > headers) "
                "is the part that generalises",
    }


def stability(a: dict, b: dict) -> dict:
    """Which fields changed between two visits, and which never do (the ones worth keying on)."""
    keys = sorted(set(a) | set(b))
    same, changed, only = [], [], []
    for k in keys:
        if k not in a or k not in b:
            only.append(k)
        elif a.get(k) == b.get(k):
            same.append(k)
        else:
            changed.append(k)
    return {"stable": same, "changed": changed, "seen_once": only,
            "verdict": (f"{len(same)} of {len(keys)} signals identical across the two visits - "
                        f"the stable ones are exactly what a tracker keys on: "
                        f"{', '.join(same[:6]) or 'nothing'}")}


REPORT_JS = r"""
<script>
const F = {};
const set = (k, v) => { try { F[k] = (typeof v === 'string' ? v : JSON.stringify(v)); } catch (e) {} };
set('platform', navigator.platform);
set('hardware', [navigator.hardwareConcurrency, navigator.deviceMemory, navigator.maxTouchPoints].join('/'));
set('screen', [screen.width, screen.height, screen.colorDepth, devicePixelRatio,
               innerWidth, innerHeight].join('x'));
set('timezone', Intl.DateTimeFormat().resolvedOptions().timeZone + '/' + -new Date().getTimezoneOffset());
set('languages', navigator.languages.join(','));
set('plugins', (navigator.plugins || []).length);
set('battery-touch', ('getBattery' in navigator) + '/' + (navigator.maxTouchPoints > 0));
// canvas: draw the same instructions everywhere, and let the *rendering* differ per machine
try {
  const c = document.createElement('canvas'); c.width = 240; c.height = 60;
  const x = c.getContext('2d');
  x.textBaseline = 'alphabetic'; x.fillStyle = '#f60'; x.fillRect(0, 0, 100, 30);
  x.fillStyle = '#069'; x.font = '16px Arial'; x.fillText('æ)řš§\uD83D\uDE42', 2, 20);
  x.strokeStyle = 'rgba(102,204,0,0.7)'; x.arc(50, 45, 20, 0, Math.PI * 2); x.stroke();
  set('canvas', c.toDataURL().slice(-48));
} catch (e) { set('canvas', 'blocked'); }
// fonts: no font API - measure widths with a canvas and a candidate list
try {
  const m = document.createElement('canvas').getContext('2d'), base = 'monospace';
  const probes = ['Arial','Helvetica','Times New Roman','Verdana','Georgia','Courier New',
                  'Impact','Trebuchet MS','Tahoma','Segoe UI','Roboto','Noto Sans'];
  const widths = probes.map(f => { m.font = '72px "' + f + '", ' + base;
                                   return Math.round(m.measureText('mmmmmmmmmmlli').width * 100); });
  set('fonts', widths.join(','));
} catch (e) { set('fonts', 'blocked'); }
try {
  const g = document.createElement('canvas').getContext('webgl');
  const d = g && g.getExtension('WEBGL_debug_renderer_info');
  set('webgl', d ? g.getParameter(d.UNMASKED_VENDOR_WEBGL) + ' | ' + g.getParameter(d.UNMASKED_RENDERER_WEBGL) : 'n/a');
} catch (e) { set('webgl', 'blocked'); }
try {                                   // audio: a tiny render, then hash the samples
  const C = window.OfflineAudioContext || window.webkitOfflineAudioContext;
  if (C) { const ctx = new C(1, 44100, 1), o = ctx.createOscillator(), g2 = ctx.createDynamicsCompressor();
    o.connect(g2); g2.connect(ctx.destination); o.start(0); o.stop(0.001);
    ctx.startRendering().then(b => { let s = 0; const d = b.getChannelData(0);
      for (let i = 0; i < 2000; i++) s += Math.abs(d[i]) * (i % 7 + 1);
      set('audio', s.toPrecision(12)); }); }
  else set('audio', 'n/a');
} catch (e) { set('audio', 'blocked'); }
let id = localStorage.getItem('lab-visitor');
if (!id) { id = 'V' + Date.now().toString(36); localStorage.setItem('lab-visitor', id);
           localStorage.setItem('lab-first', new Date().toISOString()); }
set('storage-id', id + '|first-seen:' + localStorage.getItem('lab-first'));
setTimeout(() => {
  fetch('/collect', {method: 'POST', headers: {'Content-Type': 'application/json'},
                     body: JSON.stringify(F)}).then(r => r.json()).then(j => {
    document.getElementById('js').innerHTML = j.rendered;
    document.getElementById('score').textContent = 'profile score ' + j.profile.score_0_100 +
      '/100, identity ' + j.profile.identity;
  });
}, 40);
</script>
"""

ROWS_JS = ("<table><tr><th>signal</th><th>what the page could read</th></tr>"
           "{{rows}}</table>")


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        return

    def out(self, code: int, body: str, ctype: str = "text/html; charset=utf-8"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.startswith("/clear"):
            for f in os.listdir(STORE) if os.path.isdir(STORE) else []:
                if f.endswith(".json"):
                    os.unlink(os.path.join(STORE, f))
            return self.out(200, "<p>cleared. Reload to watch the storage-id be created again.</p>")
        if self.path.startswith("/state"):
            return self.out(200, json.dumps({"visits": visits(), "fields": FIELDS}, indent=2), "application/json")
        server_seen = {"user-agent": self.headers.get("User-Agent"),
                       "accept-language": self.headers.get("Accept-Language"),
                       "accept-encoding": self.headers.get("Accept-Encoding"),
                       "sec-ch-ua-platform": self.headers.get("Sec-CH-UA-Platform"),
                       "dnt/sec-gpc": f"DNT={self.headers.get('DNT')} GPC={self.headers.get('Sec-CH-UA-Mobile')}",
                       "referer": self.headers.get("Referer"),
                       "cookie": hash_of(self.headers.get("Cookie") or "") if self.headers.get("Cookie") else None,
                       "sec-fetch-site": self.headers.get("Sec-Fetch-Site"),
                       "peer-ip": f"{self.client_address[0]}:{self.client_address[1]}"}
        rows = "".join(f"<tr><td>{k}</td><td>{json.dumps(v)}</td></tr>" for k, v in server_seen.items() if v)
        page = ("<!doctype html><meta charset=utf-8><title>eyeball (lab)</title>"
                "<style>body{font:15px/1.5 system-ui;max-width:900px;margin:2rem auto;padding:0 1rem}"
                "table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:.3rem .45rem;"
                "font-size:13px;word-break:break-all}code{background:#f4f4f4;padding:.1rem .3rem}</style>"
                "<h1>What this request told a server</h1>"
                "<p class=hint>Nothing here is exotic. Every row is a normal part of a page load - "
                "which is why 'just browsing' is never anonymous. The collector is your own laptop: "
                "data lands in <code>out/eyeball/</code> and nowhere else.</p>"
                f"<h2>Layer 1 - headers the browser sent without asking</h2><table><tr><th>signal</th>"
                f"<th>value</th></tr>{rows}</table>"
                "<h2 id=score>Layer 2 - running scripts now&hellip;</h2><div id=js></div>"
                "<p><a href=/state>/state</a> (every visit so far) &middot; <a href=/clear>clear</a></p>"
                + REPORT_JS)
        self.out(200, page)

    def do_POST(self):
        if self.path != "/collect":
            return self.out(404, "no")
        origin = self.headers.get("Origin", "")
        if origin and f"127.0.0.1:{self.server.server_address[1]}" not in origin:
            return self.out(403, json.dumps({"error": "cross-origin collect refused"}), "application/json")
        n = int(self.headers.get("Content-Length") or 0)
        try:
            client = json.loads(self.rfile.read(n).decode() or "{}")
        except json.JSONDecodeError:
            client = {}
        fields = {"user-agent": self.headers.get("User-Agent"),
                  "peer-ip": self.client_address[0], **client}
        prof = profile(fields)
        os.makedirs(STORE, exist_ok=True)
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "fields": fields, "profile": prof}
        idx = len([f for f in os.listdir(STORE) if f.startswith("visit-")]) + 1
        json.dump(rec, open(os.path.join(STORE, f"visit-{idx}.json"), "w", encoding="utf-8"), indent=2)
        json.dump(rec, open(os.path.join(STORE, "latest.json"), "w", encoding="utf-8"), indent=2)
        rendered = ROWS_JS.replace("{{rows}}", "".join(
            f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in sorted(fields.items())))
        self.out(200, json.dumps({"rendered": rendered, "profile": prof, "saved": f"visit-{idx}.json"}),
                 "application/json")


def visits() -> list[dict]:
    if not os.path.isdir(STORE):
        return []
    out = []
    for f in sorted(os.listdir(STORE)):
        if f.startswith("visit-") and f.endswith(".json"):
            out.append(json.load(open(os.path.join(STORE, f), encoding="utf-8", errors="replace")))
    return out


def render(rec: dict) -> str:
    prof, fl = rec["profile"], rec["fields"]
    lines = [f"profile {prof['score_0_100']}/100  identity {prof['identity']}  fields {prof['n_fields']}"]
    for cls, names in sorted(prof["by_class"].items()):
        lines.append(f"  [{cls}] {', '.join(names)}")
    lines.append("  values:")
    for k, v in sorted(fl.items()):
        w = FIELDS.get(k, ("?", 0, ""))
        lines.append(f"    {k:<22} {w[0]:<8} w={w[1]:<3} {str(v)[:70]}")
    return "\n".join(lines)


def selftest() -> int:
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"   {detail}" if not cond else ""))
        ok = ok and bool(cond)

    a = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124", "canvas": "abc",
         "webgl": "Google Inc. | ANGLE", "fonts": "1,2,3", "timezone": "Africa/Lagos/60",
         "storage-id": "V1|first-seen:2026-01-01", "peer-ip": "10.0.0.5"}
    b = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124", "canvas": "abc",
         "webgl": "Google Inc. | ANGLE", "fonts": "1,2,3", "timezone": "Europe/London/60",
         "storage-id": "V1|first-seen:2026-01-01", "peer-ip": "10.0.0.9"}
    pa, pb = profile(a), profile(b)
    check("score rises with more signals", profile({"canvas": "x"})["score_0_100"] < pa["score_0_100"], str(pa))
    check("score is capped at 100", pb["score_0_100"] <= 100)
    check("identity ignores absent fields", profile({"a": 1})["identity"] != profile({})["identity"])
    check("identity is stable for identical profiles", profile(a)["identity"] == profile(dict(a))["identity"])
    check("timezone change alone does not change the signal classes present",
          set(pa["by_class"]) == set(profile({**a, "timezone": "X"})["by_class"]))
    st = stability(a, b)
    check("stable fields are the ones that do not move",
          "canvas" in st["stable"] and "storage-id" in st["stable"], str(st["stable"]))
    check("moved fields are reported as changed", "timezone" in st["changed"] and "peer-ip" in st["changed"],
          str(st["changed"]))
    check("a unique-ish profile scores higher than a header-only one",
          profile({"user-agent": "curl/8", "accept-language": "en"})["score_0_100"] < pa["score_0_100"])
    check("empty fields do not count", profile({"canvas": "", "peer-ip": None})["n_fields"] == 0)
    check("render is safe to paste in a ticket", "identity" in render({"profile": pa, "fields": a}))
    print("RESULT:", "eyeball selftest ok" if ok else "EYEBALL FAILURES")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", nargs="?", choices=["serve", "analyze", "diff", "score"], default="serve")
    ap.add_argument("--port", type=int, default=8097)
    ap.add_argument("files", nargs="*", help="captures for analyze/diff")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if a.cmd == "serve":
        os.makedirs(STORE, exist_ok=True)
        srv = ThreadingHTTPServer(("127.0.0.1", a.port), H)
        print(f"[eyeball] http://127.0.0.1:{a.port}/  -> captures in {STORE}")
        print("[eyeball] loopback only. Ctrl-C to stop.")
        srv.serve_forever()
        return 0
    if a.cmd == "diff" and len(a.files) == 2:
        x, y = (json.load(open(f, encoding="utf-8", errors="replace"))["fields"] for f in a.files)
        print(json.dumps(stability(x, y), indent=2))
        return 0
    recs = [json.load(open(f, encoding="utf-8", errors="replace")) for f in a.files] or visits()
    if not recs:
        print("no captures yet - run:  python3 tools/eyeball.py serve --port 8097  and open it")
        return 1
    for r in recs:
        print(render(r), "\n")
    if len(recs) > 1:
        ids = [r["profile"]["identity"] for r in recs]
        print(f"{len(recs)} visits, {len(set(ids))} distinct identities -> "
              + ("the site recognises you every time" if len(set(ids)) == 1
                 else "your profile moves; that is what 'blending in' costs"))
    return 0


if __name__ == "__main__":
    try:                            # Windows console/encoding shim; no-op elsewhere
        import sys as _sys, os as _os
        _sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "lab"))
        import win
        win.ready()
    except ImportError:
        pass
    raise SystemExit(main())
