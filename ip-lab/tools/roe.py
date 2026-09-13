#!/usr/bin/env python3
"""
Authorization machinery: the paperwork that makes testing legal, and the gate that
keeps you inside it.

Everything in this file exists because of one fact: the difference between a
penetration test and a crime is a document, a window, and a hash — not intent.
"Purely educational" is not a defence anywhere; a countersigned scope with a time
window and an emergency contact is. So the professional stack is:

  generate   -> scope.json (machine-readable) + ROE letter + get-out-of-jail card +
                custody log header, with your details filled in and placeholders for
                everything only the client can supply
  check      -> is THIS target, on THIS date, with THIS method inside the signed scope?
                exit 0 = allowed, 1 = refused, with the reason
  sign / verify -> sha256 over the scope file + a timestamp, written outside the scope
                file. This is how you prove the scope existed *before* the test, which
                is exactly what a court or a platform's Trust & Safety team asks
  log        -> append an artefact (file, pcap, screenshot) with its hash + time to the
                chain-of-custody CSV
  sweep      -> turn a scope into the two operational artefacts a real engagement needs:
                a declared-source-IP block for the client's allowlist decision, and a
                SOC notification email body
  --selftest

  python3 tools/roe.py generate --client "Acme NG" --slug acme --contact-sec soc@acme.ng
  python3 tools/roe.py check --scope out/scope-acme.json --target http://127.0.0.1:8095/api/v1/user/1 --method GET
  python3 tools/roe.py sign --scope out/scope-acme.json
  python3 tools/roe.py verify --scope out/scope-acme.json
  python3 tools/roe.py log --custody out/custody-acme.csv --artifact out/triage_alerts.json --note "detection run"
  python3 tools/roe.py sweep --scope out/scope-acme.json --src 203.0.113.4 --src 203.0.113.5

`tools/web.py --scope out/scope-acme.json` uses this as a hard gate.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import fnmatch
import hashlib
import json
import os
import sys
import urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NOW = _dt.datetime.now(_dt.timezone.utc)

DEFAULT_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]
# Things no professional does without an explicit, named, separately-signed permission,
# and even then usually not from a lab machine. They are listed here so the *refusal* is
# machine-readable rather than a vibe.
NEVER = {
    "do": ["data_exfiltration_beyond_proof", "deny_of_service", "credential_harvest_of_real_users",
           "log_or_audit_tampering", "persistence_on_production", "access_personal_data_of_third_parties",
           "social_engineering_of_staff", "phishing", "physical_security", "wireless_attacks",
           "third_party_hosting_without_authorisation", "person_identification_from_ip"],
    "why": "each of these either exceeds what any client can lawfully consent to on behalf of "
           "their own users, or converts a test into an offence against someone who never signed anything",
}

SCENE = {
    "black_box": "no prior knowledge, engagement rules still fully apply",
    "grey_box": "user-level creds supplied",
    "white_box": "source/architecture supplied",
}


def _p(path: str) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    return path


def default_scope(client: str, slug: str, days: int = 14) -> dict:
    start = NOW
    end = NOW + _dt.timedelta(days=days)
    return {
        "version": 1,
        "slug": slug,
        "client": client,
        "engagement": {
            "type": "penetration_test",
            "knowledge": "grey_box",
            "window_start_utc": start.isoformat(timespec="seconds"),
            "window_end_utc": end.isoformat(timespec="seconds"),
            "max_requests_per_minute": 60,
            "max_concurrency": 4,
            "out_of_hours_allowed": False,
        },
        "authorised_by": {"name": "<SIGNATORY NAME AND TITLE>", "email": "<sec@client.example>",
                          "signed_at": "", "reference": "<ticket or PO number>"},
        "contact": {"security": "<soc@client.example>", "24x7": "+234-800-000-0000",
                    "report_immediately_if": ["you reach production customer data",
                                              "an alert triggers an incident-declaration",
                                              "you can move laterally off the scoped host",
                                              "anything in scope is unreachable for >15 min"]},
        "in_scope": [
            {"target": "127.0.0.1", "ports": [8095], "protocols": ["http"],
             "note": "the lab target in this repo - the only thing here you actually own"},
        ],
        "out_of_scope": [
            {"target": "*", "note": "everything not listed above, including any other host on the same subnet, "
                                    "any third-party SaaS the app talks to, and any employee account that is not yours"},
        ],
        "allowed_methods": DEFAULT_METHODS,
        "allowed_techniques": ["auth_bypass_testing", "idor_enumeration_within_tenant", "ssrf_against_own_metadata_only",
                               "header_differential_testing", "vulnerability_scanning_rate_limited"],
        "declared_source_ips": [],
        "data_handling": {
            "local_storage": "encrypted volume only; no client data on personal devices",
            "artefacts_kept": ["request/response pairs proving each finding", "screenshots with UTC timestamp"],
            "max_records_per_finding": 3,
            "destroy_by_utc": (end + _dt.timedelta(days=30)).isoformat(timespec="seconds"),
            "certificate_of_destruction": True,
        },
        "reporting": {"severity_model": "CVSS3.1 + business impact", "deliverables": ["exec summary", "findings",
                                                                                      "retest results", "custody log"],
                      "embargo_days": 0},
        "never": NEVER,
    }


def generate(a: object) -> int:
    sc = default_scope(a.client, a.slug, a.days)
    sc["declared_source_ips"] = list(a.src or [])
    if a.ips:
        sc["in_scope"].append({"target": a.ips, "ports": [80, 443], "protocols": ["http", "https"],
                               "note": "ADD ONLY IF WRITTEN BY THE CLIENT: hostname in their DNS they control"})
    sp = _p(os.path.join(ROOT, "out", f"scope-{a.slug}.json"))
    with open(sp, "w", encoding="utf-8") as fh:
        json.dump(sc, fh, indent=2)
    win = f"{sc['engagement']['window_start_utc']} .. {sc['engagement']['window_end_utc']}"
    roe = f"""# Rules of engagement — {a.client}
Generated {NOW.isoformat(timespec='seconds')} · scope file: `scope-{a.slug}.json` · this document is a DRAFT until countersigned.

## 1. Authority
Test activity described here is authorised in writing by the party in `authorised_by`. No testing begins before
`signed_at` is non-empty. If you cannot produce the signed copy, you have no authorisation and everything below is
just a plan to commit an offence.

## 2. Boundaries
- Targets: {json.dumps(sc['in_scope'], indent=2)}
- Window (UTC): {win}
- Rate: {sc['engagement']['max_requests_per_minute']} req/min, concurrency {sc['engagement']['max_concurrency']}
- Out-of-hours: {sc['engagement']['out_of_hours_allowed']}
- Declared tester source addresses: {sc['declared_source_ips'] or 'TO BE SUPPLIED - the client decides whether to allowlist or to watch'}

Anything not in `in_scope` is out of scope, including hosts that answer on the same IP, SaaS the app talks to,
and employee accounts that are not yours. "It was reachable" is not "it was authorised".

## 3. Hard prohibitions (no signature makes these legal)
{chr(10).join(f'- {x}' for x in NEVER['do'])}
Reason: {NEVER['why']}.

## 4. Stop conditions — stop the moment any of these is true, then send the notification
- production customer data is read, written or exported beyond a proof-of-access sample
- an alert triggers an incident declaration, a page, or a customer-facing outage
- you obtain a foothold on a host not in scope, or credentials for an account not in scope
- the client's on-call asks you to stop (their word ends the test; no negotiation)
- you find evidence of an ongoing compromise by a third party (report immediately; do not investigate further)

## 5. Evidence and custody
- every finding: request, response, UTC timestamp, the exact command used, and the scope reference
- {sc['data_handling']['max_records_per_finding']} records maximum per finding — prove it, don't collect it
- custody log: `custody-{a.slug}.csv` (this tool appends to it with `log`)
- destruction by {sc['data_handling']['destroy_by_utc']}, certificate issued to the client

## 6. Reporting
{json.dumps(sc['reporting'], indent=2)}

## 7. If you are contacted by law enforcement, a hostmaster, or an abuse desk
Say: the activity is authorised, name the client and the reference, produce this document and the signed scope,
give the security contact, and stop testing until the client confirms in writing. Do not delete anything. Do not
"clarify" by continuing.

---
Get-out-of-jail summary card (print it, keep it with your laptop):

```
PENETRATION TEST IN PROGRESS
Client: {a.client}   Reference: <ticket>
Authorised signatory: {sc['authorised_by']['name']}  {sc['authorised_by']['email']}
Window (UTC): {win}
Tester: <your name>  <your phone>  <your email>
If anything looks wrong: contact the client's 24x7 number FIRST: {sc['contact']['24x7']}
Nothing here authorises access beyond the listed targets.
```
"""
    rp = _p(os.path.join(ROOT, "out", f"ROE-{a.slug}.md"))
    with open(rp, "w", encoding="utf-8") as fh:
        fh.write(roe)
    cp = _p(os.path.join(ROOT, "out", f"custody-{a.slug}.csv"))
    if not os.path.exists(cp):
        with open(cp, "w", encoding="utf-8") as fh:
            fh.write("utc,artifact,sha256,size,note\n")
    print(f"scope   -> {sp}")
    print(f"ROE     -> {rp}")
    print(f"custody -> {cp}")
    print("\nFill in <PLACEHOLDERS>, get it countersigned, run `sign`, and only then touch a target.")
    print("Until `authorised_by.signed_at` is set, `check` refuses everything - that is the design, not a bug.")
    return 0


def load_scope(path: str) -> dict:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return json.load(fh)


def _host_matches(spec: str, host: str) -> bool:
    return host == spec or fnmatch.fnmatch(host, spec)


def assess(scope: dict, target: str, method: str = "GET", when: _dt.datetime | None = None) -> tuple[bool, list[str]]:
    """The decision an operator should never have to make from memory."""
    why: list[str] = []
    u = urllib.parse.urlparse(target if "//" in target else f"http://{target}")
    host = u.hostname or ""
    port = u.port or (443 if u.scheme == "https" else 80)
    when = when or NOW
    a = scope.get("authorised_by", {})
    if not a.get("signed_at"):
        why.append("NOT SIGNED: authorised_by.signed_at is empty, so there is no written authorisation to rely on")
    hit = None
    for entry in scope.get("in_scope", []):
        if _host_matches(str(entry.get("target", "")), host):
            ports = entry.get("ports") or []
            if not ports or port in ports:
                hit = entry
                break
            why.append(f"{host} is listed but only on ports {ports}, not {port}")
    if not hit:
        why.append(f"target {host}:{port} is not in in_scope")
    for entry in scope.get("out_of_scope", []):
        if _host_matches(str(entry.get("target", "*")), host) and entry.get("target") != "*":
            why.append(f"target is explicitly out of scope: {entry.get('note', '')}")
            hit = None
    eng = scope.get("engagement", {})
    try:
        s0 = _dt.datetime.fromisoformat(eng["window_start_utc"])
        s1 = _dt.datetime.fromisoformat(eng["window_end_utc"])
        if not (s0 <= when <= s1):
            why.append(f"outside the agreed window ({eng['window_start_utc']} .. {eng['window_end_utc']})")
    except (KeyError, ValueError, TypeError):
        why.append("window missing or unparseable")
    if method.upper() not in [m.upper() for m in scope.get("allowed_methods", [])]:
        why.append(f"method {method} not allowed by scope")
    return (not why), why


def advisories(scope: dict, src_ip: str | None = None) -> list[str]:
    """Things that are not reasons to refuse, but that a professional acts on."""
    out = []
    declared = scope.get("declared_source_ips") or []
    if declared and src_ip and src_ip not in declared:
        out.append(f"your source {src_ip} is not in declared_source_ips {declared} - either add it to the scope "
                   "or expect the client's SOC to treat you as unknown traffic")
    if declared and not src_ip:
        out.append(f"declared source IPs on file: {declared} (pass --src to `sweep`, and use one of them)")
    if not scope["engagement"].get("out_of_hours_allowed") and NOW.hour < 6:
        out.append("it is currently outside typical working hours and out_of_hours_allowed is false - "
                   "a 03:00 scan is an incident even when the host is in scope")
    if not scope["contact"].get("24x7", "").strip("+234-800-000-0000"):
        out.append("no 24x7 contact filled in: if their SOC pages you and you cannot reach a human at the "
                   "client, the engagement ends and may be reported")
    return out


def check(a: object) -> int:
    ok, why = assess(load_scope(a.scope), a.target, a.method)
    print(("ALLOW " if ok else "REFUSE") + f"  {a.target}  ({a.method})")
    for w in why:
        print(f"   - {w}")
    for note in advisories(load_scope(a.scope), a.src):
        print(f"   note: {note}")
    if ok:
        print("   in scope, inside the window, signed. Stay inside this decision for every request you send.")
        return 0
    print("   Do not send the request. Ask for a scope amendment instead.")
    return 1


def sign(a: object) -> int:
    blob = open(a.scope, "rb").read()
    h = hashlib.sha256(blob).hexdigest()
    sig = {"scope": os.path.basename(a.scope), "sha256": h, "signed_at": NOW.isoformat(timespec="seconds"),
           "note": "hash of the scope as it existed at this moment; keep it, it is your alibi"}
    out = _p(a.out or (a.scope + ".sig"))
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(sig, fh, indent=2)
    print(f"{out}\n  sha256 {h}\n  {sig['signed_at']}")
    return 0


def verify(a: object) -> int:
    sig = load_scope(a.sig or (a.scope + ".sig"))
    h = hashlib.sha256(open(a.scope, "rb").read()).hexdigest()
    same = h == sig.get("sha256")
    print(("MATCH" if same else "MISMATCH") + f"  scope sha256 {h}")
    if not same:
        print("  the scope changed after it was signed. Re-sign and re-notify the client, or stop.")
    return 0 if same else 1


def log_entry(a: object) -> int:
    data = open(a.artifact, "rb").read()
    row = f"{NOW.isoformat(timespec='seconds')},{a.artifact},{hashlib.sha256(data).hexdigest()},{len(data)},\"{a.note}\"\n"
    with open(_p(a.custody), "a", encoding="utf-8") as fh:
        fh.write(row)
    print("appended: " + row.strip())
    return 0


def sweep(a: object) -> int:
    sc = load_scope(a.scope)
    sc["declared_source_ips"] = list(a.src or sc.get("declared_source_ips", []))
    with open(a.scope, "w", encoding="utf-8") as fh:
        json.dump(sc, fh, indent=2)
    allow = "\n".join(f"{ip}/32  # tester source" for ip in sc["declared_source_ips"]) or "# (none declared)"
    mail = f"""Subject: authorised security testing against {sc['client']} — {NOW:%Y-%m-%d} window

Hi,

Reminder of the engagement we agreed, so your SOC can tell noise from an incident:

- Reference / PO: {sc['authorised_by'].get('reference')}
- Window (UTC): {sc['engagement']['window_start_utc']} to {sc['engagement']['window_end_utc']}
- In scope: {', '.join(e['target'] + ':' + ','.join(map(str, e.get('ports', []))) for e in sc['in_scope'])}
- Tester source addresses: {', '.join(sc['declared_source_ips']) or 'none declared - we will not ask you to allowlist'}
- Expected shape: {', '.join(sc['allowed_techniques'])}
- Rate ceiling: {sc['engagement']['max_requests_per_minute']} req/min from us; we stop on request, immediately.
- We are deliberately NOT asking you to allowlist us out of your detection stack. Alert on us; page us
  through {sc['contact'].get('security')} and we will confirm within 15 minutes.

Stop conditions and prohibitions are in the signed ROE. Anything that looks like a stop condition, we stop first and
explain second.
"""
    ap = _p(os.path.join(ROOT, "out", f"allowlist-{sc['slug']}.conf"))
    mp = _p(os.path.join(ROOT, "out", f"soc-notify-{sc['slug']}.txt"))
    open(ap, "w", encoding="utf-8").write("# if the client chooses to allowlist, they should do it in their WAF/SIEM, not you in their infra\n" + allow + "\n")
    open(mp, "w", encoding="utf-8").write(mail)
    print(f"scope updated     -> {a.scope}")
    print(f"allowlist fragment-> {ap}")
    print(f"SOC notification  -> {mp}")
    print("\nThat notification is the single highest-value OPSEC move in this whole file: a SOC that knows")
    print("you exist pages you instead of calling the police, and closes the incident as 'expected activity'.")
    return 0


def selftest() -> int:
    import tempfile
    tmp = tempfile.mkdtemp(prefix="roeself")
    sc = default_scope("Selftest Ltd", "selftest", days=1)
    sp = os.path.join(tmp, "scope.json")
    json.dump(sc, open(sp, "w", encoding="utf-8"), indent=2)
    ok = True
    # unsigned -> refuse
    ok &= not assess(sc, "http://127.0.0.1:8095/x")[0]
    sc["authorised_by"]["signed_at"] = NOW.isoformat(timespec="seconds")
    ok &= assess(sc, "http://127.0.0.1:8095/x")[0] is True
    ok &= not assess(sc, "http://10.1.1.1/x")[0]                 # host not in scope
    ok &= not assess(sc, "http://127.0.0.1:9999/x")[0]           # port not in scope
    ok &= not assess(sc, "http://127.0.0.1:8095/x", "TRACE")[0]  # method not allowed
    ok &= not assess(sc, "http://127.0.0.1:8095/x", "GET",
                     when=NOW + _dt.timedelta(days=90))[0]       # outside window
    # sign/verify round trip + tamper detection
    h = hashlib.sha256(json.dumps(sc, indent=2).encode()).hexdigest()
    open(sp, "w", encoding="utf-8").write(json.dumps(sc, indent=2))
    sig = {"sha256": h}
    ok &= sig["sha256"] == hashlib.sha256(open(sp, "rb").read()).hexdigest()
    open(sp, "a", encoding="utf-8").write("\n")
    ok &= sig["sha256"] != hashlib.sha256(open(sp, "rb").read()).hexdigest()  # tamper is visible
    # the prohibitions must survive any client signature
    sc["declared_source_ips"] = ["203.0.113.9"]
    ok &= assess(sc, "http://127.0.0.1:8095/x")[0] is True          # a source note must not block
    ok &= bool(advisories(sc, "198.51.100.7"))                       # ...but it must be said
    ok &= "log_or_audit_tampering" in sc["never"]["do"] and "person_identification_from_ip" in sc["never"]["do"]
    print("roe selftest:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("generate")
    g.add_argument("--client", required=True)
    g.add_argument("--slug", default="engagement")
    g.add_argument("--days", type=int, default=14)
    g.add_argument("--src", action="append", help="declared tester source address (repeatable)")
    g.add_argument("--ips", help="comma-free single extra hostname to propose (only if the client wrote it)")
    c = sub.add_parser("check")
    c.add_argument("--scope", required=True)
    c.add_argument("--target", required=True)
    c.add_argument("--method", default="GET")
    c.add_argument("--src", help="the address you will actually test from (advisory only)")
    s = sub.add_parser("sign")
    s.add_argument("--scope", required=True)
    s.add_argument("--out")
    v = sub.add_parser("verify")
    v.add_argument("--scope", required=True)
    v.add_argument("--sig")
    l = sub.add_parser("log")
    l.add_argument("--custody", required=True)
    l.add_argument("--artifact", required=True)
    l.add_argument("--note", default="")
    w = sub.add_parser("sweep")
    w.add_argument("--scope", required=True)
    w.add_argument("--src", action="append")
    # --selftest has to be reachable before subparsers, so sniff argv for it
    if "--selftest" in sys.argv:
        return selftest()
    a = ap.parse_args()
    return {"generate": generate, "check": check, "sign": sign, "verify": verify,
            "log": log_entry, "sweep": sweep}[a.cmd](a)


if __name__ == "__main__":
    try:                            # Windows console/encoding shim; no-op elsewhere
        import sys as _sys, os as _os
        _sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "lab"))
        import win
        win.ready()
    except ImportError:
        pass
    raise SystemExit(main())
