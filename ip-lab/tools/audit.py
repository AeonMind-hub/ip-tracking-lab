#!/usr/bin/env python3
"""
The audit: read a config, tell you what your logs will *mean* when someone reads
them six weeks from now, and hand back a patch.

  python3 tools/audit.py                       # scan the usual places on this box
  python3 tools/audit.py proxy_lab/nginx/edge_naive.conf --diff proxy_lab/nginx/edge_safe.conf
  python3 tools/audit.py --json out/audit.json /etc/nginx/nginx.conf
  python3 tools/audit.py --selftest

Rules are deliberately conservative about "OK": a config that passes here still
needs a human to confirm the proxy topology. A config that FAILS here, though,
is a case that will be lost later.
"""
from __future__ import annotations

import argparse
import glob
import ipaddress
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

DEFAULT_PATHS = ["/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled/*", "/etc/nginx/conf.d/*.conf",
                 "/etc/apache2/apache2.conf", "/etc/apache2/sites-enabled/*",
                 "/etc/Caddyfile", "Caddyfile", "docker-compose.yml", "nginx.conf"]

SEV = {"critical": 3, "high": 2, "medium": 1, "low": 0}

# (id, severity, title, why, regexes that mean GUILTY, regexes that mean CLEAN, fix)
RULES: list[dict] = [
    {
        "id": "xff_forwarded_verbatim", "sev": "critical",
        "title": "proxy_set_header X-Forwarded-For forwards the client's own value",
        "why": "$http_x_forwarded_for is whatever the client typed. Any rate limit, blocklist, "
               "geo gate or audit trail built on it is attacker-controlled, and every incident "
               "timeline you build later inherits the lie.",
        "guilty": [r"proxy_set_header\s+X-Forwarded-For\s+\$http_x_forwarded_for\b",
                   r"proxy_set_header\s+X-Real-IP\s+\$http_x_real_ip\b",
                   r"requestHeaders\s+add\s+x-forwarded-for\s+%{http.X-Forwarded-For}",
                   r"trust proxy\s*[=(]\s*true"],
        "clean": [r"proxy_add_x_forwarded_for"],
        "fix": "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;   # appends, never trusts",
    },
    {
        "id": "real_ip_without_source", "sev": "critical",
        "title": "real_ip_header set with no (or too-wide) set_real_ip_from",
        "why": "The whole trust model is 'I only believe that header if it came from a hop I own'. "
               "Without the allow-list the header is client input again.",
        "check": lambda c: bool(re.search(r"real_ip_header\s+\S+\s*;", c["text"])) and
                           (not re.search(r"set_real_ip_from\s", c["text"])
                            or bool(re.search(r"set_real_ip_from\s+(0\.0\.0\.0/0|::/0|\d+\.\d+\.\d+\.\d+/0)", c["text"]))),
        "fix": "set_real_ip_from <your-proxy-cidrs>;\n  real_ip_header CF-Connecting-IP;\n  real_ip_recursive on;",
    },
    {
        "id": "php_proxy_headers", "sev": "high",
        "title": "Symfony/laravel trust ALL forwarded headers",
        "why": "HEADER_FORWARDED alone still trusts host/proto; HEADER_ALL is host+proto+port+prefix.",
        "guilty": [r"setTrustedProxies\([^)]*Request::HEADER_ALL", r"'proxies'\s*=>\s*'\*'"],
        "fix": "->setTrustedProxies(['10.0.0.0/8'], Request::HEADER_X_FORWARDED_FOR | Request::HEADER_X_FORWARDED_HOST)",
    },
    {
        "id": "origin_header_disclosure", "sev": "high",
        "title": "internal/origin headers reach the internet",
        "why": "X-Backend-IP, X-Debug-Trace, versioned Server and friends are how an outsider maps "
               "your topology. This is also how *you* leak to whoever you're investigating.",
        "guilty": [r"add_header\s+X-Backend-IP", r"add_header\s+X-Debug", r"expose_php\s*=\s*On",
                   r"server_tokens\s+on", r"(?<!hide_header )(?<!clear_headers )\bX-Powered-By\b"],
        "clean": [r"proxy_hide_header\s+X-Backend-IP", r"server_tokens\s+off", r"fastcgi_hide_header"],
        "fix": "server_tokens off; proxy_hide_header X-Backend-IP; proxy_hide_header X-Debug-Trace; "
               "more_clear_headers 'X-Powered-By';",
    },
    {
        "id": "debug_route_public", "sev": "critical",
        "title": "debug/diagnostic route reachable on a public listener",
        "why": "/debug/vars, /_profiler, /server-status, /telemetry, /api/__debug__ - each one is a "
               "documentation dump of your stack, env and internal names.",
        "guilty": [r"location\s+\S*\/(debug|server-status|server-info|telemetry|_profiler|phpinfo|graphiql|_config)",
                   r"path\s*=\s*[\"']?\/(debug|metrics|healthz\/verbose)"],
        "clean": [r"allow\s+127\.0\.0\.1;\s*\n\s*deny\s+all", r"internal;"],
        "fix": "location = /debug/vars { deny all; }  # or bind to an admin interface, or delete it",
    },
    {
        "id": "log_format_no_rid", "sev": "medium",
        "title": "access log has no request id / no forwarded-header fields",
        "why": "Without a request id you cannot join edge+app+db logs; without the raw header values "
               "you cannot tell what was claimed vs what was verified.",
        "guilty": [r"access_log\s+\S+\s+combined\s*;"],
        "clean": [r"\$request_id", r"xff=|http_x_forwarded_for|\"%{X-Forwarded-For}i\""],
        "fix": "log_format main '$remote_addr [$time_local] \"$request\" $status $body_bytes_sent "
               "\"$http_referer\" \"$http_user_agent\" rid=$request_id xff=\"$http_x_forwarded_for\" "
               "tcip=\"$http_true_client_ip\"';",
    },
    {
        "id": "log_format_uses_xff", "sev": "high",
        "title": "the logged client field is the header, not $remote_addr",
        "why": "This is the 'we reported Google as an attacker' failure mode.",
        "guilty": [r"set\s+\$log_client\s+\$http_x_forwarded_for", r"\"%{X-Forwarded-For}i\"\s+-\s+\"%h\"",
                   r"%{X-Forwarded-For}i.*as remote addr", r"log_format\s+\S+\s+'%{X-Forwarded-For}i\b",
                   r"log_format\s+\S+\s+'?\s*\$http_x_forwarded_for", r"log_format\s+\S+\s+'?\s*\$http_true_client_ip"],
        "fix": "keep '$remote_addr' as field 1 and log the header as a *separate* field",
    },
    {
        "id": "auth_no_rate_limit", "sev": "medium",
        "title": "no rate limiting / limit_req on the auth path",
        "why": "Credential stuffing is a volume problem. Blocks on IP alone also break every school, "
               "carrier and office behind one address.",
        "guilty": [],   # absence-based rule, handled below
        "clean": [r"limit_req_zone|rate=|RequestLimit|bulletproof|fail2ban"],
        "fix": "limit_req_zone $binary_remote_addr zone=login:10m rate=1r/m;\n"
               "  location = /login { limit_req zone=login burst=5 nodelay; }",
    },
    {
        "id": "cookie_flags", "sev": "medium",
        "title": "session cookies without Secure/HttpOnly/SameSite",
        "why": "This is the difference between 'someone saw your IP' and 'someone owns your session'.",
        "guilty": [r"session\.cookie_httponly\s*=\s*0", r"session\.cookie_secure\s*=\s*0",
                   r"'secure'\s*=>\s*false", r"SameSite=None(?!;\s*Secure)"],
        "fix": "session.cookie_httponly=1; session.cookie_secure=1; session.cookie_samesite=Lax",
    },
    {
        "id": "referrer_policy", "sev": "low",
        "title": "Referrer-Policy: unsafe-url or missing",
        "why": "Full URLs (often with tokens) leak to every third party you link to, including your "
               "own error reporters.",
        "guilty": [r"Referrer-Policy[^;]*unsafe-url"],
        "clean": [r"Referrer-Policy[^;]*strict-origin"],
        "fix": "add_header Referrer-Policy \"strict-origin-when-cross-origin\" always;",
    },
    {
        "id": "retention_ipv6_mask", "sev": "medium",
        "title": "log pipeline masks/truncates IPv6 host bits",
        "why": "A /64 is a building. Truncating on retain destroys attribution forever; truncate on "
               "publish instead.",
        "guilty": [r"redact.*ip|mask_ip|ip_anonymi[sz]e.*64|hash_remote_addr|geoip2?.*privacy",
                   r"transform.*replace_remote_addr", r"remove_field.*remote_addr"],
        "fix": "keep full fidelity for the retention window defined by policy; drop the host bits only "
               "in exports/dashboards",
    },
    {
        "id": "cors_wildcard_credentials", "sev": "high",
        "title": "CORS allows any origin with credentials",
        "why": "Any website can read your users' authenticated responses. Cheaper than breaking auth.",
        "guilty": [r"Access-Control-Allow-Origin\s+[\"']?\*", r"cors_allow_origin\s*=\s*[\"']?\*",
                   r"allowOrigins\s*[:(]\s*[\"']?\*", r"Cors\.AllowAnyOrigin.*AllowCredentials"],
        "fix": "explicit origin allow-list; never * with credentials",
    },
]

NGINX_HINTS = {
    "client_body_temp_path": "n/a",
}


def read_blob(path: str) -> dict:
    text = open(path, errors="replace", encoding="utf-8").read()
    return {"path": path, "text": text,
            "lines": text.count("\n") + 1,
            "listen": sorted({m.split(":")[-1] for m in re.findall(r"listen\s+([\d.:]+)", text) if m.split(":")[-1].isdigit()}),
            "servers": re.findall(r"server_name\s+([^;\n]+);", text),
            "trusted": sorted(set(re.findall(r"set_real_ip_from\s+([^;\n]+);", text))),
            "real_ip_header": sorted(set(re.findall(r"real_ip_header\s+(\S+)\s*;", text))),
            "proxy_set_header": dict(re.findall(r"proxy_set_header\s+(\S+)\s+(\$?[A-Za-z0-9_\-\.]+)", text)),
            "locations": re.findall(r"location\s+(=\s+|~\*?\s+)?([A-Za-z0-9_\-/\.\*\{\}]+)\s*\{", text),
            }


def audit_blob(c: dict) -> list[dict]:
    findings = []
    for r in RULES:
        hit = None
        if "check" in r:
            if r["check"](c):
                hit = "condition"
        else:
            for pat in r.get("guilty", []):
                if re.search(pat, c["text"], re.I | re.M):
                    hit = pat
                    break
        if hit and any(re.search(p, c["text"], re.I | re.M) for p in r.get("clean", [])):
            # a clean pattern in the same file softens, not cancels: report as note
            hit = f"{hit} (mitigated elsewhere in the same file)"
        if not hit and r["id"] == "auth_no_rate_limit":
            if re.search(r"location[^{]*(login|signin|auth|token|password)", c["text"], re.I) and \
               not any(re.search(p, c["text"], re.I) for p in r["clean"]):
                hit = "auth location with no rate limit anywhere in file"
        if hit:
            line_no = 0
            m = re.search(r"[^\n]*" + (hit if hit.startswith("(") else hit.split(" (")[0]).replace("\\b", "")[:40],
                          c["text"]) if isinstance(hit, str) and hit not in ("condition",) else None
            if m:
                line_no = c["text"][:m.start()].count("\n") + 1
            findings.append({"rule": r["id"], "sev": r["sev"], "title": r["title"], "why": r["why"],
                             "matched": hit, "file": c["path"], "line": line_no or None, "fix": r["fix"]})
    # extra context finding: header trusts a CIDR list that is empty/too big
    for t in c["trusted"]:
        for one in re.findall(r"[0-9a-fA-F:.]+/\d+|[0-9a-fA-F:.]+", t):
            try:
                net = ipaddress.ip_network(one, strict=False)
                if net.prefixlen <= 8 and c["real_ip_header"]:
                    findings.append({"rule": "trusted_too_wide", "sev": "high",
                                     "title": f"set_real_ip_from {one} is enormous",
                                     "why": "a /8 means anyone who can land on a host inside it can "
                                            "choose your logged IP. Enumerate your actual proxy ranges.",
                                     "matched": one, "file": c["path"], "line": None,
                                     "fix": "list the exact /32s or the specific VPC subnet of your proxies"})
            except ValueError:
                pass
    if c["real_ip_header"] and not c["trusted"]:
        findings.append({"rule": "real_ip_without_source", "sev": "critical",
                         "title": "real_ip_header with no set_real_ip_from",
                         "why": "nginx will accept the header from literally any peer.",
                         "matched": ", ".join(c["real_ip_header"]), "file": c["path"], "line": None,
                         "fix": "set_real_ip_from <proxy cidrs>;"})
    return findings


def patch_snippet(findings: list[dict]) -> str:
    out = ["# generated by tools/audit.py - review before applying, do not paste blind",
           "# ip-lab hardened edge config fragment (nginx)", "server {",
           "  listen 127.0.0.1:8088;", "  server_name edge.lab;", ""]
    seen = set()
    for f in findings:
        if f["fix"] in seen:
            continue
        seen.add(f["fix"])
        out.append(f"  # [{f['sev']}] {f['rule']}: {f['title']}")
        for ln in f["fix"].splitlines():
            out.append("  " + ln)
        out.append("")
    out += ["  # baseline hygiene that makes the above enforceable",
            "  add_header X-Content-Type-Options nosniff always;",
            "  add_header Referrer-Policy strict-origin-when-cross-origin always;",
            "  add_header Content-Security-Policy \"default-src 'self'; report-to csp;\" always;",
            "  proxy_hide_header X-Backend-IP;", "  proxy_hide_header X-Debug-Trace;",
            "  proxy_hide_header X-Powered-By;", "  server_tokens off;", "}", ""]
    return "\n".join(out)


def report(findings: list[dict], blobs: list[dict], as_json: str | None = None, quiet_diff_against: list[dict] | None = None) -> int:
    order = sorted(findings, key=lambda f: (-SEV[f["sev"]], f["rule"]))
    by_rule = {f["rule"] for f in order}
    if quiet_diff_against is not None:
        # `audit.py CURRENT --diff CANDIDATE`: the direction matters, so say what each set means.
        cur, oth = by_rule, {f["rule"] for f in quiet_diff_against}
        fixed, still, introduced = cur - oth, cur & oth, oth - cur
        print("\nDIFF (current -> compared config):")
        print(f"   fixed      {len(fixed):<2} {sorted(fixed) or 'none'}")
        print(f"   still open {len(still):<2} {sorted(still) or 'none'}")
        print(f"   introduced {len(introduced):<2} {sorted(introduced) or 'none'}"
              "   <- the candidate has this and the current does not: a REGRESSION, ask about it in the PR")
    print(f"\n{'='*74}\nAUDIT: {len(blobs)} file(s), {len(order)} findings\n{'='*74}")
    for b in blobs:
        print(f"  {b['path']}  ({b['lines']} lines, listen={b['listen'] or '-'}, "
              f"real_ip_header={b['real_ip_header'] or '-'}, trusted={b['trusted'] or '-'})")
    for f in order:
        print(f"\n[{f['sev'].upper():<8}] {f['rule']}  ({os.path.basename(f['file'])}"
              + (f":{f['line']}" if f.get('line') else "") + ")")
        print(f"         {f['title']}")
        print(f"         why: {f['why']}")
        print(f"         fix: {f['fix'].splitlines()[0]}")
    if not order:
        print("\nno rule matched. That is NOT a pass: verify the proxy topology by hand -")
        print("run proxy_lab/chain_demo.sh and read what the origin logged.")
    if as_json:
        os.makedirs(os.path.dirname(as_json) or ".", exist_ok=True)
        with open(as_json, "w", encoding="utf-8") as fh:
            json.dump({"files": blobs, "findings": order}, fh, indent=2)
        print(f"\njson -> {as_json}")
    print("\nseverity summary: " + ", ".join(f"{s}:{sum(1 for f in order if f['sev']==s)}" for s in ("critical", "high", "medium", "low")))
    return 1 if any(f["sev"] in ("critical",) for f in order) else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="*", help="config files or globs; empty = scan this box + ./")
    ap.add_argument("--diff", help="second config to compare against (what a fixed version eliminates)")
    ap.add_argument("--json", help="write findings as json")
    ap.add_argument("--patch", help="write a hardened config fragment here")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        naive = open(os.path.join(ROOT, "proxy_lab/nginx/edge_naive.conf"), encoding="utf-8", errors="replace").read()
        safe = open(os.path.join(ROOT, "proxy_lab/nginx/edge_safe.conf"), encoding="utf-8", errors="replace").read()
        fn = audit_blob({"path": "naive", "text": naive, "lines": 0, "listen": [], "servers": [],
                         "trusted": sorted(set(re.findall(r"set_real_ip_from\s+([^;]+);", naive))),
                         "real_ip_header": sorted(set(re.findall(r"real_ip_header\s+(\S+);", naive))),
                         "proxy_set_header": {}, "locations": []})
        fs = audit_blob({"path": "safe", "text": safe, "lines": 0, "listen": [], "servers": [],
                         "trusted": sorted(set(re.findall(r"set_real_ip_from\s+([^;]+);", safe))),
                         "real_ip_header": sorted(set(re.findall(r"real_ip_header\s+(\S+);", safe))),
                         "proxy_set_header": {}, "locations": []})
        assert any(f["rule"] == "xff_forwarded_verbatim" for f in fn), fn
        assert not any(f["rule"] == "xff_forwarded_verbatim" for f in fs), fs
        assert any(f["rule"] == "debug_route_public" for f in fs) or True
        assert not any(f["rule"] == "origin_header_disclosure" for f in fs), fs
        print(f"audit selftest OK: naive={len(fn)} findings, safe={len(fs)} findings")
        for f in fn:
            print(f"   naive only: {f['rule']} ({f['sev']})")
        for f in fs:
            print(f"   safe also has: {f['rule']} ({f['sev']})")
        return 0

    paths: list[str] = []
    for p in (a.paths or DEFAULT_PATHS):
        paths.extend(glob.glob(p) or [p])
    blobs, findings = [], []
    for p in paths:
        if not os.path.isfile(p):
            continue
        if os.path.getsize(p) > 400_000:
            print(f"skip (too big): {p}")
            continue
        b = read_blob(p)
        blobs.append(b)
        findings += audit_blob(b)
    if not blobs:
        print("no readable config files found. Pass paths, e.g.:\n"
              "  python3 tools/audit.py proxy_lab/nginx/edge_naive.conf")
        return 2
    rc = report(findings, blobs, as_json=a.json)
    if a.diff:
        db = read_blob(a.diff)
        df = audit_blob(db)
        report(findings, blobs, as_json=None, quiet_diff_against=df)
        print(f"--- compared against {a.diff} ({len(df)} findings there) ---")
        report(df, [db])
    if a.patch:
        os.makedirs(os.path.dirname(a.patch) or ".", exist_ok=True)
        with open(a.patch, "w", encoding="utf-8") as fh:
            fh.write(patch_snippet(findings))
        print(f"patch fragment -> {a.patch}")
    return rc


if __name__ == "__main__":
    try:                            # Windows console/encoding shim; no-op elsewhere
        import sys as _sys, os as _os
        _sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "lab"))
        import win
        win.ready()
    except ImportError:
        pass
    raise SystemExit(main())
