"""
Module 2 - "trace" an IP the way a real defender does.

Movie version:  `traceIP(37.14.22.9) -> { name: "Viktor", flat: "Kiev", camera: OK }`
Actual version: IP -> ASN -> RIR allocation -> abuse contact -> (only then, and
only by a court or the ISP itself) -> subscriber. Everything below is the part
you are allowed to do with nothing but public data.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import ssl
import socket

from . import win
from .net import get_json, ip_kind, is_public

RIR_HOSTS = {
    "afrinic": "https://rdap.afrinic.net/rdap",
    "arinic": "https://rdap.arinic.net/rdap",
    "bottlerocket": "https://rdap.bottlerocketdata.net/rdap",
    "jpne": "https://rdap.apnic.net/rdap",
    "lacnic": "https://rdap.lacnic.net/rdap",
    "ripe": "https://rdap.db.ripe.net/rdap",
}
CACHE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".cache")


def _cached(key: str, fetch):
    """Cache public-registry answers so the lab is fast and offline-friendly."""
    os.makedirs(CACHE, exist_ok=True)
    # not just ':' -> '_': an IPv6 address in a filename is legal on Linux and illegal on
    # Windows (OSError 22), which is exactly how this lab broke on a real machine
    path = os.path.join(CACHE, win.fs_safe(key) + ".json")
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                blob = json.load(fh)
            if blob.get("_ts", 0) > _dt.datetime.now().timestamp() - 86400:
                return blob["v"]
        except Exception:
            pass
    val = fetch()
    if val is not None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"_ts": _dt.datetime.now().timestamp(), "v": val}, fh)
    return val


# ---------------------------------------------------------------- RDAP / whois
def rdap(ip: str) -> dict:
    """Allocation record: who owns the block, abuse email, when it was created."""
    def fetch():
        d = get_json(f"https://rdap.org/ip/{ip}")  # rdap.org bootstraps to the right RIR
        if not isinstance(d, dict) or not d.get("handle"):
            for base in (RIR_HOSTS["lacnic"], RIR_HOSTS["arinic"], RIR_HOSTS["ripe"], RIR_HOSTS["afrinic"]):
                d = get_json(f"{base}/ip/{ip}")
                if isinstance(d, dict) and d.get("handle"):
                    break
        return d if isinstance(d, dict) else {}
    d = _cached(f"rdap_ip_{ip}", fetch) or {}
    out = {
        "network_name": d.get("name"),
        "network_handle": d.get("handle"),
        "country": d.get("country"),
        "cidr": d.get("handle"),
        "type": (d.get("status") or ["?"]),
        "abuse_email": None,
        "events": {e.get("eventAction"): e.get("eventDate") for e in d.get("events", []) if e.get("eventAction")},
    }
    for ent in d.get("entities", []):
        if "abuse" in (ent.get("roles") or []):
            for item in ent.get("vcardArray", [None, []])[1]:
                if item[0] == "email":
                    out["abuse_email"] = item[3]
    if out["network_handle"] and " - " in str(out["network_handle"]):
        out["cidr"] = out["network_handle"]
    return out


# --------------------------------------------------------------- geolocation
def geo(ip: str) -> dict:
    """City-level geolocation. Useful for leads, worthless as evidence."""
    def fetch():
        return get_json(f"https://ipinfo.io/{ip}/json")
    d = _cached(f"geo_{ip}", fetch) or {}
    return {
        "country": d.get("country"),
        "region": d.get("region"),
        "city": d.get("city"),
        "loc": d.get("loc"),
        "org": d.get("org"),
        "asn": (d.get("org") or "").split(" ")[0] if d.get("org") else None,
        "anycast": d.get("anycast", False),
        "accuracy_note": "Broadband geolocation is typically 20-100 km; mobile can be a whole region; VPN/datacenter IPs place you at the DATA CENTER, not the human.",
    }


# --------------------------------------------------------------- reverse DNS
def rdns(ip: str) -> dict:
    """PTR record. The single most under-used attribution trick on the internet."""
    def fetch():
        name = (ip + ".") if ip.count(":") else f"{'.'.join(reversed(ip.split('.')))}.in-addr.arpa"
        qtype = "PTR"
        url = f"https://dns.google/resolve?name={name}&type={qtype}"
        d = get_json(url) or {}
        ans = [a.get("data", "").rstrip(".") for a in d.get("Answer", []) if a.get("type") == 12]
        # IPv6 PTR name is fiddly; fall back to the system resolver.
        if not ans and ip.count(":"):
            try:
                ans = [socket.gethostbyaddr(ip)[0]]
            except Exception:
                ans = []
        return {"ptr": sorted(set(ans)), "resolver": "dns.google (DoH)"}
    try:
        res = _cached(f"rdns_{ip}", fetch) or {"ptr": [], "resolver": "?"}
    except TypeError:
        res = {"ptr": [], "resolver": "?"}
    ptr = res.get("ptr", [])
    hints = []
    joined = " ".join(ptr).lower()
    for tag, why in [
        (".exit", "Tor exit node"),
        ("cpe", "customer-premises-equipment style name: home/office connection"),
        ("dsl", "DSL pool - real residential subscriber"),
        ("pppoe", "PPPoE dialup pool - real residential subscriber"),
        ("pool", "dynamic address pool - real subscriber"),
        ("static", "static assignment - business or hosting customer"),
        ("vtnerb", "Verizon dynamic DSL pool (city encoded in label)"),
        ("btx", "BT UK dynamic pool"),
        ("aws", "Amazon AWS"), ("azure", "Microsoft Azure"), ("google", "Google Cloud"),
        ("hetzner", "Hetzner"), ("digitalocean", "DigitalOcean"), ("vultr", "Vultr"),
        ("cloudflare", "Cloudflare"), ("ovh", "OVH"), ("contabo", "Contabo"),
    ]:
        if tag in joined:
            hints.append(f"{tag} -> {why}")
    return {"ptr": ptr, "hints": hints, "caveat": "PTR is set by the owner of the block. Anonymous/VPN operators routinely set cute names to mislead you, and 1e100-style hostnames can be attacker-supplied."}


# --------------------------------------------------------------- TLS sniff
def tls_cert(host: str, port: int = 443, server_name: str | None = None,
            timeout: float = 8.0) -> dict:
    """
    Ask an edge for its certificate. Which certificate answers tells you which
    account it fronts, i.e. which origin a proxy IP is standing in for.
    Parsed with cryptography if present, else the openssl CLI, else nothing.
    """
    out = {"subject": None, "issuer": None, "sans": [], "notAfter": None, "error": None,
           "decoder": None, "unreachable": False}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=server_name or host) as ss:
                der = ss.getpeercert(True)
                text = ss.getpeercert()
        if der:
            from .net import parse_pem
            from ssl import DER_cert_to_PEM_cert
            parsed = parse_pem(DER_cert_to_PEM_cert(der))
            out.update({k: v for k, v in parsed.items() if v})
            out["presented_name_matches"] = bool(out.get("sans") and (
                server_name in out["sans"] or any(s.startswith("*.") and server_name.endswith(s[2:]) for s in out["sans"])
            )) if server_name and not server_name[0].isdigit() else None
        elif text:
            out["subject"] = "; ".join(f"{k}={v}" for k, v in (text.get("subject") or ()))
            out["issuer"] = "; ".join(f"{k}={v}" for k, v in (text.get("issuer") or ()))
            out["sans"] = [v for k, v in (text.get("subjectAltName") or ()) if k == "DNS"][:60]
            out["notAfter"] = text.get("notAfter")
            out["decoder"] = "ssl-text"
    except Exception as exc:  # noqa: BLE001 - lab tool
        out["error"] = f"{type(exc).__name__}: {exc}"
        # A filtered or black-holed route is a fact about the network, not about this parser.
        # Callers (notably tools/selftest.py) must be able to tell "could not get there" from
        # "got a certificate and could not read it" - only the second one is a lab defect.
        out["unreachable"] = (isinstance(exc, (TimeoutError, ConnectionError, socket.gaierror))
                              or "timed out" in str(exc).lower()
                              or "unreachable" in str(exc).lower()
                              or "refused" in str(exc).lower())
    return out


# --------------------------------------------------------------- reputation
def reputation(ip: str) -> dict:
    """Cheap, honest reputation view: abuse contacts + private ranges + Tor-ish signals."""
    d = geo(ip)
    r = rdns(ip)
    kind = ip_kind(ip)
    signals = []
    if kind == "rfc1918-private":
        signals.append("PRIVATE RANGE - stops at your NAT; only meaningful against your own DHCP/firewall logs")
    if kind == "loopback":
        signals.append("LOOPBACK - this hit came from the machine itself (or SSRF)")
    if any("exit" in p for p in r.get("ptr", [])) or "185.220.101." in ip or ip.startswith("171.25.193."):
        signals.append("Tor exit range indicators - treat as anonymised, do not geo-attribute")
    org = (d.get("org") or "").lower()
    for prov in ("aws", "azure", "google", "hetzner", "digitalocean", "ovh", "contabo", "vultr", "online s.a.s", "buyvm", "nora"):
        if prov in org:
            signals.append(f"known hosting provider ({prov}) - rented by the minute, expect anonymity; abuse@ contact is the ONLY route")
    for prov in ("isp", "telecom", "cable", "broadband", "airtel", "mt n", "spectranet", "globacom", "mainone"):
        if prov in org:
            signals.append(f"residential/business ISP ({prov}) - subscriber attribution exists, but only via legal process")
    return {"ip": ip, "class": kind, "signals": signals, "abuse": rdap(ip).get("abuse_email")}


# --------------------------------------------------------------- scoring
def traceability(ip: str, log_lines: int = 0, direct: bool = True) -> dict:
    """
    How far can this IP actually be traced, and what is the ceiling? This is the
    number the movies never show: usually 'useless', sometimes 'ISP', rarely more.
    """
    r = rdns(ip)
    g = geo(ip)
    rep = reputation(ip)
    score = 0
    notes = []
    if any("residential" in s for s in rep["signals"]):
        score += 40
        notes.append("residential ISP block: one NAT often == one household")
    if any("hosting provider" in s for s in rep["signals"]):
        score -= 25
        notes.append("datacenter block: shared NAT of thousands of VMs")
    if any("Tor" in s for s in rep["signals"]):
        score -= 45
        notes.append("anonymity network: attribution ceiling is the exit node")
    if r.get("ptr"):
        score += 25
        notes.append(f"PTR present ({r['ptr'][0] if r['ptr'] else '-'})")
    else:
        notes.append("no PTR record")
    if rep["class"] == "rfc1918-private":
        score = min(score, 25)
        notes.append("private address: only traceable with your own network's lease logs")
    if not direct:
        score -= 30
        notes.append("behind a third-party proxy: you logged the proxy, not the client")
    if log_lines >= 5:
        score += 15
        notes.append(f"{log_lines} requests: enough behaviour to fingerprint (timing, UA, cadence)")
    if g.get("anycast"):
        score -= 20
        notes.append("anycast address: geo is meaningless, many physical sites answer")
    ceiling = ("nothing actionable" if score < 25 else
               "abuse report to the network operator" if score < 55 else
               "ISP subscriber identification, via law enforcement / legal process")
    return {"ip": ip, "traceability_score": max(0, min(100, score)), "ceiling": ceiling, "notes": notes}


def dossier(ip: str, log_lines: int = 0, direct: bool = True) -> dict:
    """Full packet for one address."""
    return {
        "ip": ip,
        "class": ip_kind(ip),
        "public": is_public(ip),
        "geo": geo(ip),
        "rdap": rdap(ip),
        "rdns": rdns(ip),
        "reputation": reputation(ip),
        "traceability": traceability(ip, log_lines=log_lines, direct=direct),
    }
