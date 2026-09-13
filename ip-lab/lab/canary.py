"""
Module 5 - the "honey link" (canary token) side of attribution.

This is the piece that is genuinely dangerous in the wrong hands, so the code is
deliberately built around a consent ledger:

  * a token only produces a REPORTED hit if it exists in canary_tokens.json;
  * hits from IPs outside the CIDRs you listed in `consent` are recorded and
    FLAGGED for you to delete/escalate, never auto-pushed to a person;
  * there is no code path here that maps an address to a human. That lookup is
    an ISP + court job, and this lab will not pretend otherwise.

What it teaches instead: how much a target leaks by merely *opening* a page -
IP, UA, Accept-Language, timezone, screen, canvas, WebRTC ICE candidates,
Referer - and why the movie "track IP" scene is really a browser-fingerprint
scene.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE = os.path.join(ROOT, "out", "canary_state.json")

BEACON_JS = r"""
// Everything a browser volunteers for free. Read this list and you understand
// why "tracking" is mostly a client-side problem, not a netcat problem.
(function () {
  var d = {
    ua: navigator.userAgent,
    langs: (navigator.languages || [navigator.language]).join(','),
    tz: Intl.DateTimeFormat().resolvedOptions().timeZone,
    tzOff: new Date().getTimezoneOffset(),
    screen: screen.width + 'x' + screen.height + '@' + (window.devicePixelRatio || 1),
    viewport: innerWidth + 'x' + innerHeight,
    cores: navigator.hardwareConcurrency || null,
    mem: navigator.deviceMemory || null,
    touch: navigator.maxTouchPoints || 0,
    ref: document.referrer || null,
    now: new Date().toISOString(),
    localIPs: [],
    canvas: null,
    storage: (function () { try { localStorage.setItem('_t', '1'); localStorage.removeItem('_t'); return true; } catch (e) { return false; } })()
  };
  try {
    var c = document.createElement('canvas'), x = c.getContext('2d');
    c.width = 240; c.height = 60; x.textBaseline = 'top';
    x.font = "16px 'Arial'"; x.fillStyle = '#f60'; x.fillRect(60, 2, 80, 20);
    x.fillStyle = '#069'; x.fillText('aeonlabs-lab-\u00e9\u017c\u015f', 6, 12);
    x.globalCompositeOperation = 'lighter'; x.fillStyle = 'rgba(102,204,0,0.7)';
    x.beginPath(); x.arc(30, 30, 20, 0, 6.28, true); x.fill();
    d.canvas = c.toDataURL().slice(-256);
  } catch (e) { d.canvas = 'blocked'; }
  try {
    var pc = new RTCPeerConnection({ iceServers: [] });
    pc.createDataChannel('');
    pc.onicecandidate = function (e) {
      if (!e || !e.candidate || !e.candidate.candidate) return;
      var m = /([0-9]{1,3}(\.[0-9]{1,3}){3})/.exec(e.candidate.candidate);
      if (m && d.localIPs.indexOf(m[1]) < 0) d.localIPs.push(m[1]);
    };
    pc.createOffer().then(function (o) { return pc.setLocalDescription(o); });
    setTimeout(function () { try { pc.close(); } catch (e) {} post(); }, 900);
  } catch (e) { post(); }
  function post() {
    var img = new Image(); img.src = '/c/BEACON/open.png';   // confirms the click
    navigator.sendBeacon
      ? navigator.sendBeacon('/c/BEACON/ping', JSON.stringify(d))
      : fetch('/c/BEACON/ping', { method: 'POST', body: JSON.stringify(d), keepalive: true });
  }
})();
"""

PAGE_TMPL = """<!doctype html><html><head><meta charset="utf-8"><title>Report R-4471</title>
<style>body{{font:15px/1.6 ui-sans-serif,system-ui;background:#101418;color:#e6edf3;margin:0;padding:3rem}}
main{{max-width:44rem;margin:0 auto;border:1px solid #263041;border-radius:14px;padding:2rem;background:#151b23}}
code{{background:#1c2431;padding:2px 6px;border-radius:6px}}</style></head>
<body><main>
<h1>Lab document R-4471</h1>
<p>This is the <b>aeonlabs ip-lab</b> canary page. It exists to show you what a
browser hands over when someone merely <i>reads</i> a document.</p>
<p>Token <code>{token}</code> - issued to <b>{who}</b> under consent scope <b>{scope}</b>.</p>
<div id="done" style="margin-top:1rem;color:#7ee787">telemetry captured: {captured}</div>
</main><script>{js}</script></body></html>"""


# ------------------------------------------------------------------ state file
def _load() -> dict:
    if not os.path.exists(STATE):
        return {"tokens": {}, "hits": [], "consent": {"allowed_cidrs": [], "notes": "fill me in: who agreed, when, and to what"}}
    with open(STATE, encoding="utf-8", errors="replace") as fh:
        return json.load(fh)


def _save(state: dict) -> None:
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    state["updated"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    tmp = STATE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)
    os.replace(tmp, STATE)


def issue(who: str, scope: str, secret: str | None = None, path: str = "/lab/report-4471") -> str:
    """
    Mint a token bound to a *named, consenting* recipient. `who`/`scope` are not
    decoration: if you cannot fill them in honestly, do not issue the token.
    """
    if not who.strip() or not scope.strip():
        raise ValueError("a canary requires a named consenting recipient and a stated scope")
    secret = secret or os.environ.get("CANARY_SECRET") or secrets.token_hex(16)
    tok = (hmac.new(secret.encode(), f"{who}|{path}".encode(), hashlib.sha256).hexdigest()[:10])
    state = _load()
    state["tokens"][tok] = {"who": who, "scope": scope, "path": path, "issued": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "revoked": None}
    _save(state)
    return tok


def revoke(tok: str) -> bool:
    state = _load()
    if tok in state["tokens"]:
        state["tokens"][tok]["revoked"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        _save(state)
        return True
    return False


def set_consent(cidrs: list[str], notes: str = "") -> None:
    state = _load()
    state["consent"]["allowed_cidrs"] = cidrs
    if notes:
        state["consent"]["notes"] = notes
    _save(state)


def in_consent(ip: str, state: dict | None = None) -> bool:
    state = state or _load()
    for c in state["consent"].get("allowed_cidrs", []):
        try:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False


def record(tok: str, ip: str, headers: dict, body: dict | None) -> dict:
    """Called by the server for every beacon. Never sends anything anywhere."""
    state = _load()
    t = state["tokens"].get(tok)
    hit = {
        "t": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "token": tok,
        "token_known": bool(t),
        "who": (t or {}).get("who"),
        "scope": (t or {}).get("scope"),
        "revoked": bool((t or {}).get("revoked")),
        "ip": ip,
        "ip_class": _kind(ip),
        "consented": in_consent(ip, state),
        "xff_seen": headers.get("X-Forwarded-For") or headers.get("CF-Connecting-IP"),
        "headers": {k.lower(): v for k, v in headers.items()},
        "client": body or {},
    }
    if not hit["token_known"]:
        hit["action_required"] = "UNKNOWN TOKEN: someone probed a token you never issued. Log, do not chase."
    elif not hit["consented"]:
        hit["action_required"] = "NOT IN CONSENT SCOPE: you may capture this (it is your own server's data), but you must not investigate, contact, or act against this person without authorisation. Review, then delete."
    state["hits"].append(hit)
    state["hits"] = state["hits"][-500:]
    _save(state)
    return hit


def _kind(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "garbage"
    if a.is_loopback:
        return "loopback (self-test)"
    if a.is_private:
        return "private - stops at your NAT"
    if a.version == 6:
        return "ipv6 global"
    return "ipv4 public"


def report() -> str:
    state = _load()
    lines = [f"canary state: {len(state['tokens'])} tokens, {len(state['hits'])} hits",
             f"consent CIDRs: {state['consent'].get('allowed_cidrs') or 'NONE SET -> nothing may be reported'}",
             f"consent note: {state['consent'].get('notes')}", ""]
    for tok, meta in state["tokens"].items():
        hits = [h for h in state["hits"] if h["token"] == tok]
        lines.append(f"token {tok} -> {meta['who']} ({meta['scope']}) issued {meta['issued']}"
                     + (" [REVOKED]" if meta.get("revoked") else ""))
        for h in hits:
            c = h["client"] or {}
            lines.append(f"   {h['t']}  {h['ip']:<16} {h['ip_class']:<22} consented={h['consented']}  "
                         f"tz={c.get('tz')}  lang={c.get('langs')}  screen={c.get('screen')}  webrtc={c.get('localIPs')}")
            if h.get("action_required"):
                lines.append(f"      !! {h['action_required']}")
        if not hits:
            lines.append("   (no hits yet)")
    return "\n".join(lines)
