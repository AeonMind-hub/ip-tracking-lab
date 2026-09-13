"""
Module 1 - reading logs. The whole "hacking the planet" fantasy starts here,
because the only IP you can ever trust is the one your own socket reported.
"""
from __future__ import annotations

import datetime as _dt
import ipaddress
import re
from collections import Counter, defaultdict

# --- access logs: mandatory prefix, then positional quoted tails ------------
# Tail field counts: 0 -> plain CLF | 1 -> "XFF" | 2 -> "referer" "user-agent"
# | 3 -> "referer" "user-agent" "XFF" | 4 -> + "x-real-ip". Anchored, so a
# missing space never silently turns into a mislabelled field.
ACC_RE = re.compile(
    r'^(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<size>\d+|-)'
    r'(?P<tails>(?: "[^"]*")*)\s*$'
)
REQ_RE = re.compile(r'^(?:(?P<method>[A-Z]+) )?(?P<path>\S+)?(?: (?P<proto>HTTP/[0-9.]+))?$')
TAIL_NAMES = [["xff"], ["ref", "ua"], ["ref", "ua", "xff"], ["ref", "ua", "xff", "xrealip"]]

# --- nginx/apache error.log: the "who probed me" source everyone ignores -----
ERR_RE = re.compile(
    r'^(?P<time>\d{4}[-/]\d{2}[-/]\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] '
    r'(?P<pid>\d+)#\d+(?:: \*(?P<cid>\d+))? (?P<msg>.*?)'
    r'(?:, client: (?P<client>[0-9a-fA-F:.]+))?'
    r'(?:, server: (?P<server>\S+))?'
    r'(?:, request: "(?P<req>[^"]*)")?'
    r'(?:, host: "(?P<host>[^"]*)")?'
    r'(?:, referrer: "(?P<eref>[^"]*)")?'
    r'$'
)


def _quoted_tails(text: str) -> list[str]:
    return [t[1:-1] for t in re.findall(r'"[^"]*"', text or "")]


def _parse_error_line(raw: str) -> dict | None:
    m = ERR_RE.match(raw)
    if not m:
        return None
    e = {k: (v or "-") for k, v in m.groupdict().items()}
    client = e.get("client") or "-"
    # "45.148.10.66:51432" or "[::1]:51432" -> address only; port is session noise
    if client != "-":
        if client.startswith("["):
            e["ip"] = client[1:client.find("]")]
        elif client.count(":") == 1 and all(c.isdigit() for c in client.split(":")[1]):
            e["ip"] = client.split(":")[0]
        else:
            e["ip"] = client
    else:
        e["ip"] = "-"
    e["xff_list"] = []
    e["size"] = 0
    e["status"] = 0
    e["ua"] = "-"
    e["ref"] = "-"
    e["method"] = (e["req"].split() or ["-"])[0]
    e["path"] = (e["req"].split() + ["-"])[1] if e["req"] != "-" else "-"
    e["is_error_log"] = True
    try:
        fmt = "%Y/%m/%d %H:%M:%S" if "/" in e["time"] else "%Y-%m-%d %H:%M:%S"
        e["dt"] = _dt.datetime.strptime(e["time"], fmt).replace(tzinfo=_dt.timezone.utc)
    except ValueError:
        e["dt"] = None
    e["malformed"] = False
    return e


def parse(lines) -> list[dict]:
    """Parse access logs (combined / common / CLF+XFF) and error logs. Never raises."""
    out = []
    for raw in lines:
        raw = raw.strip()
        if not raw:
            continue
        m = ACC_RE.match(raw)
        if not m:
            err = _parse_error_line(raw)
            if err:
                out.append(err)
            else:
                out.append({"raw": raw, "malformed": True})
            continue
        e = {k: v for k, v in m.groupdict().items() if k != "tails"}
        e["status"] = int(e["status"])
        e["size"] = 0 if e["size"] in ("-", "") else int(e["size"])
        rq = REQ_RE.match(e["request"] or "")
        e["method"] = (rq.group("method") if rq else None) or "-"
        e["path"] = (rq.group("path") if rq else None) or "-"
        e["proto"] = (rq.group("proto") if rq else None) or "-"
        tails = _quoted_tails(m.group("tails"))
        e["ref"] = e["ua"] = e["xff"] = "-"
        if tails:
            names = TAIL_NAMES[min(len(tails), 4) - 1]
            for name, val in zip(names, tails):
                e[name] = val
        try:
            e["dt"] = _dt.datetime.strptime(e["time"], "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            try:
                e["dt"] = _dt.datetime.strptime(e["time"], "%d/%b/%Y:%H:%M:%S").replace(tzinfo=_dt.timezone.utc)
            except ValueError:
                e["dt"] = None
        e["xff_list"] = split_xff(e.get("xff") or "-")
        e["level"] = None
        out.append(e)
    return out


def parse_file(path: str) -> list[dict]:
    with open(path, errors="replace", encoding="utf-8") as fh:
        return parse(fh)


# --------------------------------------------------------------- XFF handling
def is_known_proxy(ip: str, trusted: list[str]) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in ipaddress.ip_network(c.strip(), strict=False) for c in trusted if c.strip())


def split_xff(header: str) -> list[str]:
    """Left-to-right as written. Leftmost is attacker-writable, NOT trusted."""
    if not header or header == "-":
        return []
    return [p.strip() for p in header.split(",") if p.strip()]


def real_ip(entry: dict, trusted_proxies: list[str] | None = None) -> dict:
    """
    The decision procedure. Everything else is theatre.

    trusted == [] means "my app is directly exposed": remote_addr IS the client,
    and any XFF the client sent is garbage it typed itself.
    """
    peer = entry.get("ip", "")
    chain = entry.get("xff_list") or []
    trusted = trusted_proxies or []
    res = {
        "peer": peer,
        "xff_chain": chain,
        "verdict_ip": peer,
        "why": "",
        "confidence": "high",
        "flags": [],
    }
    if not trusted:
        if chain:
            res["flags"].append("XFF SENT TO A NON-PROXIED SERVER -> client is lying or testing you")
        res["why"] = "no trusted proxies configured: remote_addr is authoritative; XFF ignored entirely"
        return res
    if not is_known_proxy(peer, trusted):
        res["why"] = (f"peer {peer} is not in your trusted-proxy set, so it cannot have appended the "
                      "chain -> whatever it claims in XFF is its own typing")
        if chain:
            res["flags"].append("untrusted peer supplied XFF -> spoofed, ignore")
        return res
    # Both directions matter here: the peer is trusted (so the chain is admissible) and we
    # consume entries right-to-left only while the *hop that wrote the next entry* is trusted.
    prev, cur, i, hops = peer, peer, len(chain) - 1, 0
    while i >= 0 and is_known_proxy(cur, trusted):
        prev = cur
        cur = chain[i]
        i -= 1
        hops += 1
    if i < 0:
        if is_known_proxy(cur, trusted):
            # chain fully trusted, and its leftmost entry is also one of my proxies:
            # the client connected straight to that proxy, so that proxy's peer is the client
            res["verdict_ip"] = prev
            res["why"] = f"all {hops} entries trusted; client connected directly to a trusted proxy -> its peer"
        else:
            res["verdict_ip"] = cur
            res["why"] = f"consumed {hops} trusted hop(s); leftmost value is the first untrusted address"
        res["confidence"] = "high"
    else:
        res["verdict_ip"] = cur
        res["why"] = f"walked {hops} trusted hop(s) right-to-left; first non-trusted value is the client"
        res["confidence"] = "high" if hops else "medium"
    for v in chain[:1]:
        try:
            a = ipaddress.ip_address(v)
            if a.is_private or a.is_loopback:
                res["flags"].append(f"leftmost XFF {v} is a private/loopback address -> physically impossible from outside, someone typed it")
        except ValueError:
            res["flags"].append(f"leftmost XFF {v!r} is not even an IP -> spoofed header")
    return res


# --------------------------------------------------------------- aggregation
def summarise(entries: list[dict], minutes: bool = True) -> dict:
    """Group by source IP and produce the profile an analyst actually writes up."""
    by_ip: dict[str, list[dict]] = defaultdict(list)
    for e in entries:
        if e.get("malformed"):
            continue
        by_ip[e["ip"]].append(e)

    out = {}
    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: e["dt"] or _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc))
        paths = Counter(e["path"].split("?")[0] for e in evs)
        statuses = Counter(e["status"] for e in evs)
        codes = Counter(str(e["status"])[0] + "xx" for e in evs)
        first, last = evs[0]["dt"], evs[-1]["dt"]
        span = (last - first).total_seconds() if first and last else 0
        gaps = []
        if minutes and first and last and len(evs) > 1:
            gaps = [round((b["dt"] - a["dt"]).total_seconds(), 1) for a, b in zip(evs, evs[1:])]
        interesting = {
            "auth_failures": statuses.get(401, 0) + statuses.get(403, 0) + statuses.get(429, 0),
            "server_errors": statuses.get(500, 0),
            "successes_after_failures": _success_after_failures(evs),
            "swept_paths": [p for p in paths if re.search(r"(env|wp-login|phpmyadmin|\.git|backup|admin|debug|config|\.json$|server-status)", p, re.I)],
            "botlike_ua": [u for u in Counter(e.get("ua", "") for e in evs) if re.search(r"curl|python|nmap|libwww|Go-http|okhttp|masscan|Zgrab", u or "", re.I)],
        }
        out[ip] = {
            "n": len(evs),
            "users": sorted({e["user"] for e in evs if e.get("user") and e["user"] != "-"}) or None,
            "first": first.isoformat() if first else None,
            "last": last.isoformat() if last else None,
            "span_s": round(span, 1),
            "rps": round(len(evs) / span, 2) if span > 1 else None,
            "median_gap_s": sorted(gaps)[len(gaps) // 2] if gaps else None,
            "methods": sorted({e["method"] for e in evs}),
            "status_codes": dict(sorted(statuses.items())),
            "status_classes": dict(sorted(codes.items())),
            "top_paths": paths.most_common(8),
            "uas": sorted({e.get("ua") or "-" for e in evs}),
            "refs": sorted({e.get("ref") or "-" for e in evs if e.get("ref") not in (None, "-")})[:5],
            "xff_chains": sorted({", ".join(e["xff_list"]) for e in evs if e["xff_list"]})[:5],
            "interesting": {k: v for k, v in interesting.items() if v},
        }
    return out


def _success_after_failures(evs: list[dict]) -> dict | None:
    fails = 0
    for e in evs:
        if e["status"] in (401, 403):
            fails += 1
        elif e["status"] in (200, 302) and fails >= 3 and e["path"].lower().startswith(("/login", "/auth", "/api/login")):
            return {"after_failed": fails, "at": e["dt"].isoformat() if e["dt"] else None, "path": e["path"]}
    return None


def timeline(entries: list[dict], ip: str | None = None, limit: int = 200) -> list[str]:
    rows = []
    for e in sorted((x for x in entries if not x.get("malformed")), key=lambda x: x["dt"] or _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc)):
        if ip and e["ip"] != ip:
            continue
        t = e["dt"].strftime("%H:%M:%S") if e["dt"] else "??"
        xff = f"  xff=[{', '.join(e['xff_list'])}]" if e["xff_list"] else ""
        rows.append(f"{t}  {e['ip']:<24} {e['status']} {e['method'] or 'GET'} {e['path']}{xff}")
    return rows[:limit]
