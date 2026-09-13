#!/usr/bin/env python3
"""netinv.py — audit the devices on YOUR network, read-only, and get a fix list.

    python3 tools/netinv.py scan --arp <(arp -a) --i-own-this 192.168.1.0/24
    python3 tools/netinv.py audit  --in out/netinv_scan.json --report out/netinv.md
    python3 tools/netinv.py probe  --scope out/net-scope.json --i-own-this --live
    python3 tools/netinv.py --selftest

The question this answers is the one nobody asks until it is too late: *what is actually
sitting on my network, what does it expose, and who else can reach it?* Home routers,
cameras, printers, smart TVs and ESP32 gadgets ship with a management plane on the LAN and
no authentication on part of it. That is a real, findable, fixable problem, and finding it
on your own network is the legal, useful version of "device access".

Hard limits, enforced in code (not comments):
  * targets must be inside the ranges you pass on the command line, AND
  * targets must be private/loopback/CGNAT - public addresses are refused, always,
  * `--i-own-this` is required for any packet to leave the process,
  * every request is a GET with no body, no cookies and never an Authorization header:
    this tool does not try logins, does not test default credentials, and does not brute
    force. Credential testing against a device is an authorised-engagement activity and it
    belongs in `tools/roe.py` paperwork, not in a home audit.
  * one request per endpoint per host, 80 ms apart, everything written to an evidence file
    with a sha256 of each response body, so the report can be defended later.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# unauthenticated or weakly-authenticated management surfaces that are documented in vendor
# manuals and security write-ups. Probing your own gear for these is a legitimate check; the
# point is "should this answer at all without a login?" - not "what can I take".
ENDPOINTS = [
    ("/", "banner"),
    ("/LiveMotion.jpeg", "camera still frame readable without auth"),
    ("/snapshot.jpg", "camera still frame readable without auth"),
    ("/onvif-http/snapshot", "camera still frame readable without auth"),
    ("/axis-cgi/param.cgi?action=list", "camera config readable without auth"),
    ("/ISAPI/System/deviceInfo", "Hikvision-family device info without auth"),
    ("/cfg", "router configuration blob"),
    ("/setup.php", "open management form"),
    ("/.well-known/dnt/status", "TV/set-top debug status"),
    ("/desc.xml", "UPnP device description (serials, model, firmware)"),
    ("/rootDesc.xml", "UPnP device description (serials, model, firmware)"),
]
INTERESTING_PORTS = [23, 80, 443, 554, 8080, 8081, 8000, 1900, 32400, 5000, 9100]

CLASS_HINTS = [
    (r"(\bip-?cam|ipc|hikvision|dahua|foscam|trendnet|netcam|rtsp)", "camera/RTSP device"),
    (r"(\bprint|jetdirect|ipp|officejet|laserjet|deskjet|envy|smart.?tank|canon|epson|brother|hewlett)",
     "printer"),
    (r"(\bnas\b|synology|qnap|udisk|storage)", "NAS / file share"),
    (r"(\btv\b|BRAVIA|roku|firetv|apple-?tv|_airplay|_appletv)", "TV / media player"),
    (r"(_hap|homekit|bridge)", "HomeKit accessory"),
    (r"(google-?cast|_cast|chromecast)", "casting device"),
    (r"(esp|tuya|broadlink|shelly|sonoff|smartlife|kasa|plug|bulb)", "smart-home gadget (often no auth)"),
    (r"(router|gateway|modem|zg|hp-?link| Archer|VR\d|ZXHN|fritz)", "router/gateway"),
    (r"(android|iphone|ipad|galaxy|pixel|xiaomi)", "phone/tablet"),
    (r"(pc|desktop|laptop|workstation|thinkpad|hp-?\d)", "computer"),
]


# `arp -a` writes aa:bb:cc:dd:ee:ff on macOS/Linux and aa-bb-cc-dd-ee-ff on Windows, and the
# Windows table also contains an IPv6 block with eight groups - the negative lookahead is what
# stops us from reading the first six groups of one of those as a MAC.
MAC = r"(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f:-])"


def norm_mac(mac: str) -> str:
    return mac.lower().replace("-", ":")


def parse_arp(text: str) -> list[dict]:
    """Accepts macOS/Linux `arp -a`, Windows `arp -a` (with its Interface:/header lines),
    `ip neigh`, and a bare 'ip mac' list. MACs are normalised to colons. Returns rows."""
    rows: list[dict] = []
    seen = set()
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        m = re.match(r"^(\S+)\s+\(([\d.]+)\)\s+at\s+(" + MAC + ")", line, flags=re.I)   # arp -a
        if m:
            name, ip, mac = m.group(1), m.group(2), norm_mac(m.group(3))
        else:
            m = re.match(r"^([\d.]+)\s+(dev\s+\S+\s+)?(lladdr\s+)?(" + MAC + ")", line, flags=re.I)
            if m:                                                        # ip neigh
                ip, mac, name = m.group(1), norm_mac(m.group(4)), ""
            else:
                m = re.match(r"^([\d.]+)\s+(" + MAC + ")\b", line, flags=re.I)
                if not m:            # Windows table body, and any hand-made "ip mac [type]" list
                    continue
                ip, mac, name = m.group(1), norm_mac(m.group(2)), ""
        if (ip, mac) not in seen:
            seen.add((ip, mac))
            rows.append({"ip": ip, "mac": mac, "name": name.strip("<>")})
    return rows


def classify(row: dict, mdns: str = "") -> str:
    blob = " ".join([row.get("name", ""), row.get("ip", ""), mdns]).lower()
    for pat, label in CLASS_HINTS:
        if re.search(pat, blob, flags=re.I):
            return label
    return "unknown device"


def in_scope(ip: str, ranges: list[str]) -> tuple[bool, str]:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False, f"{ip!r} is not an IP literal"
    if not (a.is_private or a.is_loopback or a.is_link_local):
        return False, (f"{ip} is a public address - netinv refuses public targets entirely. Auditing "
                       "someone else's host needs written scope (tools/roe.py), not a flag")
    if not ranges:
        return False, "no declared ranges: pass at least one, e.g. 192.168.1.0/24"
    for r in ranges:
        try:
            if a in ipaddress.ip_network(r.strip(), strict=False):
                return True, f"in declared range {r}"
        except ValueError:
            continue
    return False, f"{ip} is not inside your declared ranges {ranges}"


def is_group_address(ip: str) -> bool:
    """True for multicast or the limited/limited-subnet broadcast. Windows `arp -a` prints
    224.0.0.0/239.x/255.255.255.255 rows per interface and macOS prints some; they never
    identify a host, so planning them would only waste requests."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return bool(a.is_multicast) or ip == "255.255.255.255"


def plan(rows: list[dict], ranges: list[str], i_own_this: bool) -> tuple[list[dict], list[str]]:
    targets, refused = [], []
    for r in rows:
        if is_group_address(r["ip"]):
            continue
        ok, why = in_scope(r["ip"], ranges)
        if not ok:
            refused.append(f"{r['ip']}: {why}")
            continue
        if not i_own_this:
            refused.append(f"{r['ip']}: in scope, but --i-own-this was not given (nothing sent)")
            continue
        targets.append({**r, "why": why, "endpoints": []})
    return targets, refused


def analyze_response(status: int, headers: dict, body: str) -> list[dict]:
    """Findings from a *response*, no exploit logic. Keys: sev, title, fix."""
    out: list[dict] = []
    low = {k.lower(): v for k, v in headers.items()}
    if status == 200:
        out.append({"sev": "high", "title": "endpoint answers without authentication",
                    "fix": "require auth on the management plane; if the device cannot do it, VLAN it off "
                           "and never expose it beyond the LAN"})
    if "text/html" in low.get("content-type", "") and re.search(
            r'<form[\s\S]{0,800}?(name\s*=\s*["\']?(password|passwd|pin|otp))', body[:4000], flags=re.I):
        out.append({"sev": "high", "title": "login form served over plain HTTP",
                    "fix": "credentials cross the network in the clear: HTTPS on the device, or manage it "
                           "only from a wired/VLAN host"})
    srv = low.get("server", "")
    if re.search(r"\d+\.\d+", srv):
        out.append({"sev": "medium", "title": f"version-bearing Server header: {srv[:48]}",
                    "fix": "free CVE lookup for anyone on the LAN; strip or neutralise it"})
    if "upnp" in low.get("content-type", "").lower() or "<deviceinfo" in body[:600].lower():
        out.append({"sev": "medium", "title": "UPnP description exposed on the LAN interface",
                    "fix": "UPnP lets any LAN device open a mapping to the WAN: disable it unless a device "
                           "needs it, and never map it from the WAN side"})
    if not low.get("strict-transport-security") and "secure" not in low.get("content-security-policy", ""):
        out.append({"sev": "low", "title": "no security headers on the management UI",
                    "fix": "cosmetic on a device UI, but HSTS/frame-ancestors closes the click-jacking path"})
    if re.search(r"(serial|macaddress|firmwareversion)", body[:3000], flags=re.I):
        out.append({"sev": "high", "title": "identity data in a body served without auth "
                                           "(serial, MAC or firmware version)",
                    "fix": "serial + firmware version is the pair used to target a known CVE or to claim a "
                           "warranty; it should never leave the device unauthenticated"})
    return out


def probe_host(ip: str, port: int, timeout: float = 1.2) -> bool:
    with socket.socket() as s:
        s.settimeout(timeout)
        return s.connect_ex((ip, port)) == 0


def fetch(ip: str, port: int, path: str, timeout: float = 2.0) -> dict:
    """One GET. No cookies, no auth header, no retries, never a body."""
    url = f"http://{ip}:{port}{path}"
    req = urllib.request.Request(url, method="GET",
                                 headers={"User-Agent": "netinv-lab/1.0 (owner audit)",
                                          "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(20000)
            return {"url": url, "status": r.status, "headers": dict(r.headers.items()),
                    "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest(),
                    "sniff": body[:1200].decode(errors="replace")}
    except urllib.error.HTTPError as e:
        return {"url": url, "status": e.code, "headers": dict((e.headers or {}).items()),
                "bytes": 0, "sha256": "", "error": str(e.reason)}
    except Exception as exc:  # noqa: BLE001
        return {"url": url, "status": None, "error": f"{type(exc).__name__}: {exc}"}


def render(targets: list[dict], notes: list[str]) -> str:
    lines = ["# Home/LAN device audit", "",
             f"generated {time.strftime('%Y-%m-%d %H:%M')} by tools/netinv.py - "
             "read-only GETs against addresses you declared as yours.", ""]
    lines.append(f"## {len(targets)} device(s) in scope")
    for t in targets:
        lines.append(f"\n### {t['ip']}  {t.get('mac','')}  ({t.get('class','unknown device')})")
        if t.get("open_ports"):
            lines.append(f"- open: {', '.join(str(p) for p in t['open_ports'])}")
        for e in t.get("endpoints", []):
            lines.append(f"- `{e['path']}` -> {e['status']} "
                         f"{'sha256=' + e['sha256'][:12] if e.get('sha256') else e.get('error', '')}")
            for f in e.get("findings", []):
                lines.append(f"    - **{f['sev']}** {f['title']}")
                lines.append(f"      fix: {f['fix']}")
    if notes:
        lines.append("\n## refused / skipped")
        lines += [f"- {n}" for n in notes]
    lines += ["", "## the three fixes that matter most",
              "1. change the device admin password and turn off WAN/remote management",
              "2. put gadgets on an IoT VLAN (or the router's guest network) with no LAN access",
              "3. update firmware, or retire the device if it will not update - a device that "
              "cannot be patched is a permanent foothold on the network it is joined to",
              "", "Note: this tool deliberately does not attempt logins or test default "
              "credentials. That belongs in a scoped engagement (`tools/roe.py`), where the "
              "permission, window and method list are written down before the first packet."]
    return "\n".join(lines)


def read_arp_file(path: str) -> str:
    """Decode `arp -a` saved to a file. `cmd /c arp -a > arp.txt` gives an OEM/ASCII file,
    PowerShell 5.1's `arp -a > arp.txt` gives UTF-16LE with a BOM, and Notepad gives UTF-8 with
    a BOM. Reading any of them as plain UTF-8 silently produces mojibake on the first and an
    empty table on the second, so sniff the leading bytes instead of trusting the extension."""
    data = open(path, "rb").read()
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", "replace")
    if data[:3] == b"\xef\xbb\xbf":
        return data.decode("utf-8-sig", "replace")
    return data.decode("utf-8", "replace")


def selftest() -> int:
    ok = True

    def check(name, cond, detail=""):
        nonlocal ok
        print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"   {detail}" if not cond else ""))
        ok = ok and bool(cond)

    arp = ("""
    ? (192.168.1.1) at a4:2b:b0:c1:d2:e3 on en0 ifscope [ethernet]
    ? (192.168.1.22) at 3c:a5:81:00:11:22 on en0 ifscope [ethernet]
    router.lan (192.168.1.254) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
    192.168.1.77 (192.168.1.77) at 44:00:55:66:77:88 [ether] on wlan0
    """)
    rows = parse_arp(arp)
    check("arp -a parsed", len(rows) == 4, str(rows))
    check("ip neigh style parses", len(parse_arp("10.0.0.5 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE\n"
                                                  "10.0.0.9 dev eth0 FAILED")) == 1)
    check("bare 'ip mac' lines parse", len(parse_arp("172.16.4.9  de:ad:be:ef:00:01")) == 1)
    win = ("Interface: 192.168.1.5 --- 0xb\r\n"
           "  Internet Address      Physical Address      Type\r\n"
           "  192.168.1.1           a4-2b-b0-c1-d2-e3     dynamic\r\n"
           "  192.168.1.22          3c-a5-81-00-11-22     dynamic\r\n"
           "  224.0.0.251           01-00-5e-00-00-fb     static\r\n"
           "  255.255.255.255       ff-ff-ff-ff-ff-ff     static\r\n")
    wrows = parse_arp(win)
    check("Windows arp -a table parses, headers ignored", len(wrows) == 4, str(wrows))
    check("dash MACs are normalised to colons", wrows[0]["mac"] == "a4:2b:b0:c1:d2:e3", str(wrows[0]))
    check("the IPv6-style ff-ff row is not read as a MAC prefix",
          all(len(r["mac"].split(":")) == 6 for r in wrows), str(wrows))
    wt, _ = plan(wrows, ["192.168.1.0/24"], i_own_this=True)
    check("multicast/broadcast rows are never planned", [r["ip"] for r in wt] == ["192.168.1.1", "192.168.1.22"],
          str([r["ip"] for r in wt]))
    import tempfile
    with tempfile.NamedTemporaryFile("wb", suffix=".txt", delete=False) as fh:
        fh.write(win.encode("utf-16"))
        tmp = fh.name
    try:
        check("PowerShell's UTF-16 `arp -a > file` still decodes", len(parse_arp(read_arp_file(tmp))) == 4)
    finally:
        os.unlink(tmp)
    check("classifier finds the camera",
          classify({"name": "IPCAM-3A1", "ip": "1"}) == "camera/RTSP device", classify({"name": "IPCAM-3A1", "ip": "1"}))
    check("classifier finds the printer", classify({"name": "hp-officejet", "ip": ""}).startswith("printer"))
    check("smart gadget recognised via tuya", classify({"name": "tuya-plug", "ip": ""}).startswith("smart-home"))
    check("router recognised", classify({"name": "router.lan", "ip": ""}) == "router/gateway")
    check("public address is refused outright", in_scope("8.8.8.8", ["192.168.1.0/24"])[0] is False
          and "public" in in_scope("8.8.8.8", ["192.168.1.0/24"])[1])
    check("out-of-range private address refused", in_scope("10.0.0.4", ["192.168.1.0/24"])[0] is False)
    check("in-range accepted", in_scope("192.168.1.22", ["192.168.1.0/24"])[0])
    check("no ranges means nothing is audited", in_scope("192.168.1.1", [])[0] is False)
    t, refused = plan(rows, ["192.168.1.0/24"], i_own_this=False)
    check("without --i-own-this nothing is planned", t == [] and len(refused) == 4, str(refused[:1]))
    t, refused = plan(rows, ["192.168.1.0/24"], i_own_this=True)
    check("with the flag, the four LAN hosts are planned", len(t) == 4, str(t))
    check("and the refusal list still explains the gate", all("i-own-this" in r or "public" in r for r in refused))
    f = analyze_response(200, {"Content-Type": "text/html", "Server": "GoAhead-Webs 4.1"},
                         '<form method=post><input name=password></form>')
    sevs = [x["sev"] for x in f]
    check("200 + HTTP login form yields two high findings", sevs.count("high") == 2, str(f))
    check("UPnP description detected", any("UPnP" in x["title"] for x in analyze_response(
        200, {"Content-Type": "text/xml"}, '<DeviceInfo><Device><serial>1</serial>')))
    check("serial disclosure is high", any(x["sev"] == "high" and "serial" in x["title"] for x in analyze_response(
        200, {}, '{"serialNumber":"C02","firmwareVersion":"1.04"}')))
    check("a 404 with no body is not a finding factory", len(analyze_response(404, {"Server": "x"}, "")) <= 2)
    # the structural promise: no auth header, no cookie, no body, ever
    # read-only by construction: the list may contain `?action=list` (a getter on Axis cams)
    # but never a setter, a reboot, a factory reset or a logout.
    mutating = re.compile(r"(action\s*=\s*(?:set|put|add|del|save|apply)|todo=save|apply\.cgi|save\.cgi|"
                          r"fwupload|upload|reboot|reset|factory|logout|\.do\b|post\.cgi)", flags=re.I)
    bad = [e[0] for e in ENDPOINTS if mutating.search(e[0])]
    check("no probe path writes, reboots or logs anything out", bad == [], str(bad))
    check("the gate reads `action=list` but refuses a setter",
          not mutating.search("/axis-cgi/param.cgi?action=list")
          and bool(mutating.search("/axis-cgi/param.cgi?action=put"))
          and bool(mutating.search("/cgi-bin/apply.cgi"))
          and bool(mutating.search("/rcmRun?todo=save")))
    check("endpoint list is all GET-able paths", all(e[0].startswith("/") for e in ENDPOINTS))
    md = render(t, refused)
    check("report renders and says it never tries logins", "does not attempt logins" in md and "### 192.168.1.22" in md)
    print("RESULT:", "netinv selftest ok" if ok else "NETINV SELFTEST FAILED")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", nargs="?", choices=["scan", "audit", "probe"], default="scan")
    ap.add_argument("--arp", help="file with `arp -a` output (cmd, PowerShell or macOS/Linux "
                                  "formats all parse, UTF-16 redirects too); '-' or empty reads stdin")
    ap.add_argument("--mdns", help="file with `avahi-browse -art` output (better classes)")
    ap.add_argument("ranges", nargs="*", help="declared own ranges, e.g. 192.168.1.0/24")
    ap.add_argument("--scope", help="JSON scope file; ranges come from it if given")
    ap.add_argument("--i-own-this", action="store_true", help="assert ownership of every declared range")
    ap.add_argument("--live", action="store_true", help="actually send the read-only GETs")
    ap.add_argument("--in", dest="infile", help="a saved scan to audit")
    ap.add_argument("--report", default=os.path.join(ROOT, "out", "netinv.md"))
    ap.add_argument("--evidence", default=os.path.join(ROOT, "out", "netinv_evidence.json"))
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()

    scope = {"ranges": list(a.ranges or []), "i_own_this": bool(a.i_own_this)}
    if a.scope and os.path.exists(a.scope):
        loaded = json.load(open(a.scope, encoding="utf-8", errors="replace"))
        scope["ranges"] = scope["ranges"] or loaded.get("declared_ranges", [])
        scope["i_own_this"] = scope["i_own_this"] or bool(loaded.get("owner_confirmed"))
    mdns_map: dict[str, str] = {}
    if a.mdns and os.path.exists(a.mdns):
        mdns_map = {"": open(a.mdns, encoding="utf-8", errors="replace").read()}

    if a.infile:
        data = json.load(open(a.infile, encoding="utf-8", errors="replace"))
        targets, notes = data.get("targets", []), data.get("refused", [])
        for t in targets:
            for e in t.get("endpoints", []):
                e["findings"] = analyze_response(e.get("status") or 0, e.get("headers", {}), e.get("sniff", ""))
    else:
        raw = ""
        if a.arp and a.arp != "-":
            raw = read_arp_file(a.arp)
        elif not sys.stdin.isatty():
            raw = sys.stdin.read()
        else:
            print("no input. Example:\n  arp -a | python3 tools/netinv.py scan --arp - 192.168.1.0/24 --i-own-this")
            return 2
        rows = parse_arp(raw)
        for r in rows:
            r["class"] = classify(r, " ".join(mdns_map.values()))
        targets, notes = plan(rows, scope["ranges"], scope["i_own_this"])
        if a.live and targets:
            ev = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "scope": scope, "targets": []}
            for t in targets:
                t["open_ports"] = [p for p in INTERESTING_PORTS if probe_host(t["ip"], p)]
                for path, _why in ENDPOINTS:
                    for port in (80, 8080, 8000, 443):
                        if port not in t["open_ports"] and port != 80:
                            continue
                        r = fetch(t["ip"], port, path)
                        r["path"] = path
                        r["findings"] = analyze_response(r.get("status") or 0, r.get("headers", {}),
                                                          r.get("sniff", ""))
                        t["endpoints"].append(r)
                        time.sleep(0.08)
                        if port == 80:
                            break
                ev["targets"].append(t)
            os.makedirs(os.path.dirname(a.evidence), exist_ok=True)
            json.dump(ev, open(a.evidence, "w", encoding="utf-8"), indent=2)
            print(f"[netinv] evidence (sha256 per response) -> {a.evidence}")
        else:
            if not a.live:
                notes.append("no --live flag: this run only planned targets and sent nothing")
    os.makedirs(os.path.dirname(a.report), exist_ok=True)
    open(a.report, "w", encoding="utf-8").write(render(targets, notes))
    print(f"{len(targets)} device(s) in scope, {len(notes)} refused/skipped -> {a.report}")
    for n in notes[:6]:
        print("   -", n)
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
