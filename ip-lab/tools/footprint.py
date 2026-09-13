#!/usr/bin/env python3
"""
The footprint instrument: who can see you, right now, and what they keep.

This is the honest version of "can I be a ghost?". It does two things, both read-only:

  1. MODELS the observation chain for a scenario (home / cafe / mobile / vpn / tor /
     vps / client-jump-host). Every hop carries: what it records, whose record it is,
     realistic retention, who can compel it, whether YOU can delete it, and an
     `identify` weight (0 = anonymous blob, 10 = names you). The score is arithmetic,
     not vibes: ghostability = 100 - 10 * max(identify). One hop at 10 zeroes it, and
     the output names that hop as the binding constraint.
  2. INVENTORIES your own machine: the artifacts that already tie actions to you
     (history files, machine-id, resolver, ARP + route tables, git identity, ssh keys,
     browser profile, cloud credentials, live sockets). Nothing is deleted, nothing is
     written outside out/. Destroying someone else's record is a different offence from
     the one people imagine you're being charged with; destroying yours is usually
     logged on its own and is detectable by design.

  python3 tools/footprint.py                      # both, for your actual box
  python3 tools/footprint.py --scenario tor --explain
  python3 tools/footprint.py --egress               # what a target will log about you
  python3 tools/footprint.py --report out/footprint.md
  python3 tools/footprint.py --selftest
"""
from __future__ import annotations

import argparse
import getpass
import glob
import json
import os
import platform
import socket
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# --------------------------------------------------------------------- the model
# identify: 0 nobody can tell who; 10 the record contains your name/address/lease.
# delete:   "no" = the record is somebody else's property; "partly" = you can scrub
#           your copy but not the record; "yes" = local to you (and its absence can be
#           noticed, which is its own signal).
HOPS: dict[str, dict] = {
    "device": {
        "name": "your own machine/phone",
        "records": "shell history, journalctl/event log, DNS cache, ARP/NDP table, Wi-Fi profiles, "
                   "browser profile + session DB, editor/terminal scrollback, tool temp files, "
                   "crash dumps, .bash_history timestamps, USB/device history, SRUM (Win)",
        "owner": "you (and whoever owns the device management: MDM/Intune/Workspace One)",
        "retention": "90 d - forever, depending on config; journal defaults to 4 weeks volatile",
        "compel": "seizure of the device; MDM tenant admin; any sync/backup account",
        "identify": 9, "delete": "partly",
        "note": "the machine is the identity: encryption protects it from others, not from a lawful "
                "order to whoever holds the keys - and a wiped machine at the wrong minute is evidence",
    },
    "sync": {
        "name": "account sync/backup (Google, Apple, Microsoft)",
        "records": "device name, signed-in account, location history, photo roll, clipboard, backups of "
                   "the exact files you thought you deleted",
        "owner": "the provider", "retention": "years, by policy", "compel": "MLAT / provider legal process",
        "identify": 10, "delete": "no",
        "note": "this is the hop people forget; it is also the one that ends most 'ghost' claims in one request",
    },
    "lan": {
        "name": "your LAN: router / AP / captive portal",
        "records": "DHCP lease (MAC <-> IP), NAT session table, per-client flow counters, guest-portal logs "
                   "(hotels/cafes often keep MAC + time + sometimes phone number)",
        "owner": "household or venue", "retention": "reboot-wiped to 90 d; ISP-managed CPE often ships logs upstream",
        "compel": "venue CCTV + booking record; ISP for their CPE", "identify": 8, "delete": "no",
        "note": "a cafe's router + its till receipt is a timestamp and a face",
    },
    "isp": {
        "name": "your ISP / mobile carrier",
        "records": "subscriber account, RADIUS/PPP session start-stop, CGNAT port-assignment logs "
                   "(which inside IP:port held which public port at what second), DNS resolver queries "
                   "if you used theirs, NetFlow/IPDR exports, cell tower + sector for mobile",
        "owner": "the carrier", "retention": "session/account data: months to years; CGNAT maps commonly 30-90 d; "
                                              "flow records often 7-30 d (varies by operator and law)",
        "compel": "subpoena / production order / lawful intercept - and in many countries retention is mandatory",
        "identify": 10, "delete": "no",
        "note": "this is the wall from Module 5 in reverse: the same record that lets police identify a "
                "subscriber in an afternoon is what makes 'untraceable from home' impossible",
    },
    "vpn": {
        "name": "commercial VPN / proxy you rent",
        "records": "connection logs (your IP, timestamps, bytes), sometimes payment email + card last4, "
                   "server-side netflow to their uplink, support tickets, abuse complaints against their ranges",
        "owner": "a company in some jurisdiction with employees and a bank account",
        "retention": "policy says 'none'; the reality is billing + uplink + law-enforcement requests. "
                     "No-logs claims have been broken by seizure more than once (2016-2022 era examples)",
        "compel": "their jurisdiction; also their *upstream* ISP keeps the same shape of record",
        "identify": 6, "delete": "no",
        "note": "you moved the trust problem, you did not remove it; and VPN exit ranges are loudly labelled "
                "in every reputation feed, so you arrive flagged (lab/tracer.py shows you this in 3 seconds)",
    },
    "tor": {
        "name": "Tor (guard + middle + exit)",
        "records": "nothing by design at relays, BUT: your ISP sees a Tor handshake; the guard knows "
                   "you-and-nothing-else; the exit sees cleartext unless you use TLS; a target sees an "
                   "exit address that is a known Tor exit",
        "owner": "volunteer relays", "retention": "minutes", "compel": "any relay operator can be served; "
                                                                        "malicious relays exist and have been run by adversaries",
        "identify": 4, "delete": "no",
        "note": "correlation of entry/exit timing+volume is the classic break, and endpoint compromise "
                "(browser exploits, logins, fonts, WebRTC) does the work for them; using Tor also *is* a signal "
                "in a log where nobody else does",
    },
    "vps": {
        "name": "a VPS you bought",
        "records": "registration KYC, payment instrument, control-plane logins (source IP + UA!), API call "
                   "logs, snapshot/abuse tickets, provider netflow, provider's uplink, provider's WHOIS/RDAP "
                   "object linking the range to your order",
        "owner": "the provider (cheap registrars are the weakest link and get subpoenaed routinely)",
        "retention": "billing data: years, by tax law. Access logs: 30 d - 2 y",
        "compel": "provider legal portal, often in a fast, low-friction jurisdiction",
        "identify": 9, "delete": "no",
        "note": "one control-plane login from your home IP and the whole chain collapses to one row",
    },
    "target_edge": {
        "name": "the target's edge: CDN / LB / WAF",
        "records": "full request line + every header + client IP + JA3/JA4 + HTTP/2 SETTINGS fingerprint + "
                   "Ray ID/attempt id + geo + WAF rule hits + block/allow decision",
        "owner": "your client (or their CDN)", "retention": "CDN: hours-days for full headers; LB: yours to keep",
        "compel": "their own investigation, or a report to the hosting provider / abuse desk",
        "identify": 7, "delete": "no",
        "note": "you cannot opt out of the logs on the box you are pointing tools at. Module 6 is entirely about "
                "how this record is written, and how little 'I sent no footprint' means here",
    },
    "target_app": {
        "name": "the target's app + auth + audit trails",
        "records": "access log, application log, auth events (login attempt, MFA, session id), object-level "
                   "audit rows, request ids, data-access rows",
        "owner": "your client", "retention": "30 d - 7 y (regulated systems keep everything)",
        "compel": "internal review; incident response; law enforcement if they call it",
        "identify": 8, "delete": "no",
        "note": "in a real engagement, deleting or editing these is obstruction, and it is also what triggers "
                "the highest-severity alert most SOCs have (audit tampering)",
    },
    "target_edr": {
        "name": "endpoint/server detection on their side",
        "records": "process create with full argv + hash + parent chain, script-block logging, network connect "
                   "events from the server, privilege escalation, new local accounts, LOLBIN use "
                   "(curl/powershell/wmic/mshta), file integrity monitoring on config + log paths",
        "owner": "their EDR tenant (CrowdStrike/Defender/SentinelOne...)",
        "retention": "6-12 months of raw telemetry in the tenant, cloud-side, outside anyone's LAN",
        "compel": "the EDR vendor, on request from their customer",
        "identify": 8, "delete": "no",
        "note": "this hop is why 'living off the land' is not quiet: the land is instrumented, and the "
                 "telemetry leaves the network you were in",
    },
    "human": {
        "name": "you, operationally",
        "records": "reuse: same handle, email, phone, payment card, GitHub repo, PGP key, SSH key, typing "
                   "style, timezone/locale in headers, tool defaults, the words you choose in a chat",
        "owner": "you", "retention": "as long as you keep using it",
        "compel": "graph linkage - this is how real attribution happens, not packet inspection",
        "identify": 10, "delete": "partly",
        "note": "the single most reliable identifier in every case file is reuse. Discipline, not encryption, is what separates a pro",
    },
}

SCENARIOS: dict[str, dict] = {
    "home": {"hops": ["device", "sync", "lan", "isp", "target_edge", "target_app", "human"],
             "claim": "nothing to hide, everything to see",
             "reality": "the target's client IP is your carrier's address and your ISP's session table names you in minutes"},
    "cafe": {"hops": ["device", "sync", "lan", "isp", "human", "target_edge", "target_app"],
             "claim": "no fixed address",
             "reality": "venue captive portal + CCTV + card payment for the coffee: now you have a face and a timestamp, "
                        "and the venue's ISP is still an accountable party"},
    "mobile": {"hops": ["device", "sync", "isp", "human", "target_edge", "target_app"],
               "claim": "CGNAT hides me",
               "reality": "CGNAT exists so the carrier CAN attribute; port-assignment logs + tower/sector do it. "
                          "Mobile is the least anonymous link a person can use, whatever the forums say"},
    "vpn": {"hops": ["device", "sync", "lan", "isp", "vpn", "human", "target_edge", "target_app"],
            "claim": "the VPN ate my logs",
            "reality": "your ISP logs that you connected, the VPN's uplink logs the session, the VPN bills you, "
                       "and the target sees a datacenter + 'VPN' reputation flag"},
    "tor": {"hops": ["device", "sync", "lan", "isp", "tor", "human", "target_edge", "target_app"],
            "claim": "onion routing, perfect secrecy",
            "reality": "entry-guard timing + your own endpoint + any login you make + a JA4 and a UA: "
                       "anonymity sets are small when the behaviour is unique"},
    "vps_chain": {"hops": ["device", "sync", "lan", "isp", "vps", "vps", "human", "target_edge", "target_app", "target_edr"],
                  "claim": "two hops and nobody can follow it",
                  "reality": "two purchase records, two KYCs, two payment rails, two control-plane logins from your home IP, "
                             "and a provider in a jurisdiction chosen for speed of compliance, not opacity"},
    "authorized_test": {"hops": ["device", "sync", "human", "target_edge", "target_app", "target_edr"],
                        "claim": "a professional engagement",
                        "reality": "you are loud by agreement: declared source ranges, a signed scope, a SOC that knows the "
                                   "shape of your traffic, and evidence trails on BOTH sides. That is what keeps you out "
                                   "of custody and gets you paid"},
}

W = 10.0  # ghostability denominator: 100 - W * max(identify)


def ghostability(hops: list[str]) -> tuple[float, str]:
    """100 = invisible (nobody can tie the action to you anywhere), 0 = named."""
    worst, worst_name = -1.0, ""
    for h in hops:
        w = HOPS[h]["identify"]
        if w > worst:
            worst, worst_name = w, HOPS[h]["name"]
    return max(0.0, 100 - W * worst), worst_name


# ------------------------------------------------------------------ local inventory
def _lines(path: str) -> int:
    try:
        with open(path, "rb") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return -1


def local_inventory() -> list[dict]:
    home = os.path.expanduser("~")
    out: list[dict] = []

    def add(key, desc, who, dele, present, detail=""):
        out.append({"source": key, "records": desc, "owner": who, "delete": dele,
                    "present": bool(present), "detail": detail})

    host = socket.gethostname()
    mid = ""
    try:
        mid = open("/etc/machine-id", encoding="utf-8", errors="replace").read().strip()
    except OSError:
        pass
    add("hostname + machine-id", "ties every log line you generate to a named box; machine-id ships in "
        "DHCP/DNS requests to your router and thus your ISP lease table",
        "you + router/DHCP", "yes (and network behaviour changes when you do)",
        host, f"host={host} machine-id={mid[:12]}{'…' if len(mid) > 12 else ''}")

    for name in (".bash_history", ".zsh_history"):
        p = os.path.join(home, name)
        add(f"shell history ({name})", "every command you typed, with the shell's own timestamps if HISTTIMEFORMAT is set",
            "you", "yes - and the gap is visible in any forensic image",
            os.path.exists(p), f"{_lines(p)} lines" if os.path.exists(p) else "absent")

    resolv = ""
    try:
        resolv = "\n".join(l.strip() for l in open("/etc/resolv.conf", encoding="utf-8", errors="replace") if l.startswith(("nameserver", "options")))
    except OSError:
        pass
    ns = [l.split()[1] for l in resolv.splitlines() if l.startswith("nameserver")]
    add("recursive resolver", "whoever answers your lookups sees every domain you resolve, per client address",
        "the resolver's operator", "no", bool(ns), f"nameservers={ns or 'unknown (systemd-resolved stub? run: resolvectl status)'}")

    try:
        arp = [l for l in open("/proc/net/arp", encoding="utf-8", errors="replace").read().splitlines()[1:] if l.strip()]
    except OSError:
        arp = []
    add("ARP / NDP table", "which devices shared your L2 segment when - it is how 'I was not there' gets argued against",
        "you (and any pcap on the segment)", "yes", bool(arp), f"{len(arp)} entries")

    routes = []
    try:
        raw = open("/proc/net/route", encoding="utf-8", errors="replace").read().splitlines()
        for l in raw[1:]:
            f = l.split()
            if f[1] == "00000000":
                routes.append(f"{f[0]} gw={socket.inet_ntoa(bytes.fromhex(f[2])[::-1])}")
    except OSError:
        pass
    add("default route", "the next hop of every packet - i.e. the box whose logs start the chain", "you + that device",
        "no (it is a device property)", bool(routes), "; ".join(routes) or "n/a")

    conns = 0
    try:
        for f in ("tcp", "tcp6"):
            conns += max(0, len(open(f"/proc/net/{f}", encoding="utf-8", errors="replace").read().splitlines()) - 1)
    except OSError:
        pass
    add("established sockets", "every destination you are talking to right now - mirrored in your router's NAT table and "
        "your ISP's flow records", "you + every hop", "no", conns > 0, f"{conns} sockets")

    git_email = ""
    try:
        for l in open(os.path.join(home, ".gitconfig"), encoding="utf-8", errors="replace"):
            if "email" in l:
                git_email = l.split("=")[-1].strip().strip('"')
    except OSError:
        pass
    add("git identity", "the author address on every repo you touch, including your lab commits - "
        "this is the classic linkage edge in graph attribution", "you + every remote you pushed to", "partly (history rewrites are visible)",
        bool(git_email), git_email)

    keys = glob.glob(os.path.join(home, ".ssh", "*.pub"))
    add("ssh keys", "the public half is on every host you have logged into (authorized_keys) - "
        "one shared key across contexts links them forever", "you + every host you touched", "no (on their side)",
        bool(keys), f"{len(keys)} public key(s)")

    prof = [p for pat in ("google-chrome", "Chromium", "Mozilla/Firefox", "BraveSoftware")
            for p in glob.glob(os.path.join(home, ".config", pat))]
    add("browser profile", "history, session storage, cookies, and typed URLs in leveldb - the record that puts a "
        "person, not an IP, at a site at a time", "you + any sync account", "partly", bool(prof),
        ", ".join(os.path.basename(p) for p in prof) or "none found")

    cloud = [c for c in (".aws/credentials", ".config/gcloud", ".config/az", ".kube/config", ".docker/config.json")
             if os.path.exists(os.path.join(home, c))]
    add("cloud/k8s credentials", "identity with billing, audit logs and KYC attached - every API call is logged "
        "server-side with source IP and UA", "the provider", "no", bool(cloud), ", ".join(cloud) or "none")

    env_present = [k for k in ("GH_TOKEN", "GITHUB_TOKEN", "AWS_ACCESS_KEY_ID") if k in os.environ]
    add("ambient tokens in env", "tokens in the environment land in crash dumps, /proc/*/environ, CI logs and any "
        "child process you spawn", "whoever can read the process table", "partly", bool(env_present),
        f"set: {env_present or 'none'} (values never printed by this tool)")

    add("user + platform", "the identity every other record is keyed on", "you", "no", True,
        f"user={getpass.getuser()} sys={platform.system()} {platform.release()} python={platform.python_version()}")
    return out


# ------------------------------------------------------------------------- render
def render(scen: str, inv: list[dict] | None, egress: dict | None, explain: bool = True) -> str:
    L: list[str] = []
    s = SCENARIOS[scen]
    score, binding = ghostability(s["hops"])
    L.append("=" * 74)
    L.append(f"FOOTPRINT MODEL · scenario = {scen}")
    L.append("=" * 74)
    L.append(f"  the claim : {s['claim']}")
    L.append(f"  the record: {s['reality']}")
    L.append(f"  ghostability = {score:.0f}/100   (formula: 100 - 10 x max identify-weight over the hops)")
    L.append(f"  binding constraint: {binding}")
    ranked = sorted(((HOPS[h]["identify"], HOPS[h]["name"], h) for h in s["hops"]), reverse=True)
    L.append("  what dominates, in order (and what removing the top one would actually buy you):")
    for rank, (w, nm, key) in enumerate(ranked[:4]):
        rest = [x for x in s["hops"] if x != key]
        after = ghostability(rest)[0] if rest else 100.0
        L.append(f"    {rank+1}. identify={w:<3} {nm[:44]:<44} -> drop it and you are at {after:.0f}/100")
    L.append("  Read that last column: anonymity stacks are a MIN over the hops, so the only hop worth")
    L.append("  engineering is the worst one, and the worst one is usually not a network hop at all.")
    L.append("")
    L.append(f"  {'hop':<34} {'identify':<9} {'you can delete':<15} retention")
    L.append(f"  {'-'*34} {'-'*9} {'-'*15} {'-'*28}")
    for h in s["hops"]:
        d = HOPS[h]
        L.append(f"  {d['name'][:34]:<34} {d['identify']:<9} {d['delete']:<15} {d['retention'][:28]}")
    L.append("")
    L.append("  who else holds a copy of the thing you are trying not to create:")
    for h in s["hops"]:
        d = HOPS[h]
        L.append(f"    - {d['name']}: compellable by {d['compel']}")
    if explain:
        L.append("")
        L.append("  per-hop notes (read these; they are the whole argument):")
        for h in s["hops"]:
            L.append(f"    {HOPS[h]['name']}")
            L.append(f"      records: {HOPS[h]['records']}")
            L.append(f"      -> {HOPS[h]['note']}")
    if inv is not None:
        L.append("")
        L.append("=" * 74)
        L.append("LOCAL INVENTORY (read-only; nothing was modified, nothing was deleted)")
        L.append("=" * 74)
        for row in inv:
            flag = "PRESENT" if row["present"] else "absent "
            L.append(f"  [{flag}] {row['source']:<32} owner={row['owner']}")
            if row["detail"]:
                L.append(f"            {row['detail']}")
            L.append(f"            records: {row['records']}")
            L.append(f"            you can delete it: {row['delete']}")
    if egress:
        L.append("")
        L.append("=" * 74)
        L.append("LIVE EGRESS (what every target will write in its log field 1)")
        L.append("=" * 74)
        for k, v in egress.items():
            L.append(f"  {k:<26} {v}")
    L.append("")
    L.append("  The conclusion is not 'don't bother': it is that the professional answer to 'how do I stay clean'")
    L.append("  is scope + authorization + evidence discipline, not absence of records. tools/roe.py builds those.")
    return "\n".join(L)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default="home", choices=sorted(SCENARIOS))
    ap.add_argument("--report", help="also write markdown here (default out/footprint_<scenario>.md)")
    ap.add_argument("--json", help="write the whole model as json")
    ap.add_argument("--egress", action="store_true", help="query ipinfo for the address targets will log")
    ap.add_argument("--no-local", action="store_true", help="skip the machine inventory")
    ap.add_argument("--explain", action="store_true", help="print the notes for every hop in the model")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        ok = True
        for name, sc in SCENARIOS.items():
            for h in sc["hops"]:
                if h not in HOPS:
                    ok = False
                    print(f"FAIL {name}: unknown hop {h}")
                if not 0 <= HOPS[h]["identify"] <= 10:
                    ok = False
                    print(f"FAIL {h}: identify out of range")
        for name in ("home", "tor", "authorized_test"):
            sc, _ = ghostability(SCENARIOS[name]["hops"])
            print(f"  score {name:<16} {sc:.0f}/100")
        if not (ghostability(SCENARIOS["authorized_test"]["hops"])[0] == ghostability(SCENARIOS["home"]["hops"])[0] == 0.0):
            ok = False
            print("FAIL: home and authorized_test should both score 0 - that is the honest point of the tool")
        inv = local_inventory()
        if not inv or not all(set(r) == {"source", "records", "owner", "delete", "present", "detail"} for r in inv):
            ok = False
            print("FAIL: inventory shape")
        blob = render("vpn", inv, None, explain=True)
        for must in ("binding constraint", "LOCAL INVENTORY", "compellable by"):
            if must not in blob:
                ok = False
                print(f"FAIL: render missing {must}")
        print("footprint selftest:", "OK" if ok else "FAILED")
        return 0 if ok else 1

    inv = None if a.no_local else local_inventory()
    egress = None
    if a.egress:
        egress = {}
        for url, key in (("https://ipinfo.io/ip", "public_address_seen_by_a_server"),
                         ("https://dns.google/resolve?name=ip-lab.test&type=A", "doh_answer_proof_of_egress")):
            try:
                import urllib.request
                with urllib.request.urlopen(url, timeout=8) as r:
                    txt = r.read(400).decode("utf-8", "replace").strip()
                egress[key] = txt[:120].replace("\n", " ")
            except Exception as exc:  # noqa: BLE001
                egress[key] = f"no route / offline ({type(exc).__name__})"
        egress["interpretation"] = "whatever is in public_address_seen_by_a_server is field 1 of every log line you generate"
    out = render(a.scenario, inv, egress, explain=a.explain)
    print(out)
    if a.report:
        os.makedirs(os.path.dirname(a.report) or ".", exist_ok=True)
        with open(a.report, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
        print(f"\nreport -> {a.report}")
    if a.json:
        os.makedirs(os.path.dirname(a.json) or ".", exist_ok=True)
        with open(a.json, "w", encoding="utf-8") as fh:
            json.dump({"scenario": a.scenario, "hops": [HOPS[h] | {"key": h} for h in SCENARIOS[a.scenario]["hops"]],
                       "score": ghostability(SCENARIOS[a.scenario]["hops"])[0],
                       "local": inv, "egress": egress}, fh, indent=2, default=str)
        print(f"json   -> {a.json}")
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
