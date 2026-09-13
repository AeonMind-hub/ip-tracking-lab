"""Tiny HTTP/JSON helpers shared by the lab tools. Standard library only."""
from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.parse
import subprocess
import urllib.request

UA = "ip-lab-education/1.0 (offline forensics exercise)"


def get_json(url: str, timeout: float = 12.0) -> dict | list | None:
    """GET + json decode, never raises. Returns None on any failure."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(400_000).decode("utf-8", "replace")
        return json.loads(raw)
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError, OSError, ValueError):
        return None


def ip_kind(ip: str) -> str:
    """Classify an address the way an investigator has to before trusting it."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "not-an-ip"
    if a.version == 6:
        return "ipv6-unique-local" if a.is_private else "ipv6-global"
    if a.is_loopback:
        return "loopback"
    if a.is_private:
        return "rfc1918-private"
    if a.is_link_local:
        return "link-local"
    if a.is_multicast or a.is_reserved:
        return "reserved"
    return "ipv4-public"


def is_public(ip: str) -> bool:
    return ip_kind(ip).endswith(("public",)) and ip_kind(ip) != "not-an-ip"


def truncate_v6(ip: str, segments: int = 4) -> str:
    """Mimic a privacy-minded log retention policy: keep only N 16-bit groups."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if a.version != 6:
        return ip
    packed = a.packed
    keep = packed[: 2 * segments] + b"\x00" * (16 - 2 * segments)
    return f"{ipaddress.IPv6Address(keep)}/{segments * 16}"


def v6_subnet(ip: str, segments: int = 4) -> str | None:
    """First N groups of an IPv6 address, i.e. the level a /64 log truncation leaves you."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if a.version != 6:
        return None
    groups = a.exploded.split(":")
    return ":".join(groups[:segments]) + "::/" + str(segments * 16)


def human_table(rows: list[list[str]], headers: list[str]) -> str:
    widths = [len(h) for h in headers]
    for r in rows:
        for i, c in enumerate(r):
            if i < len(widths):
                widths[i] = max(widths[i], len(str(c)))
    def fmt(row):
        return "  ".join(str(c).ljust(widths[i]) for i, c in enumerate(row) if i < len(widths))
    return "\n".join([fmt(headers), fmt(["-" * w for w in widths])] + [fmt(r) for r in rows])


_PEM_FIELDS = ["subject", "issuer", "dates"]


def parse_pem(pem: str) -> dict:
    """
    Decode a DER->PEM certificate without any third-party dependency.
    Prefers `cryptography`, falls back to the `openssl` CLI, and returns {} if
    neither exists - the lab must still run in a stripped container.
    """
    out: dict = {}
    try:
        from cryptography import x509  # type: ignore
        c = x509.load_pem_x509_certificate(pem.encode())
        out["subject"] = c.subject.rfc4514_string()
        out["issuer"] = c.issuer.rfc4514_string()
        out["notAfter"] = c.not_valid_after_utc.isoformat()
        try:
            ext = c.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            out["sans"] = [n for n in ext.value.get_values_for_type(x509.DNSName)][:60]
        except Exception:
            out["sans"] = []
        out["decoder"] = "cryptography"
        return out
    except Exception:
        pass
    try:
        r = subprocess.run(["openssl", "x509", "-noout", "-subject", "-issuer", "-enddate", "-ext", "subjectAltName"],
                           input=pem.encode(), capture_output=True, timeout=10)
        txt = r.stdout.decode(errors="replace")
        for line in txt.splitlines():
            line = line.strip()
            if line.startswith("subject="):
                out["subject"] = line.split("=", 1)[1]
            elif line.startswith("issuer="):
                out["issuer"] = line.split("=", 1)[1]
            elif line.startswith("notAfter="):
                out["notAfter"] = line.split("=", 1)[1]
            elif "DNS:" in line:
                out["sans"] = [x.strip().removeprefix("DNS:") for x in line.replace("X509v3 Subject Alternative Name:", "").split(",") if "DNS:" in x][:60]
        out.setdefault("sans", [])
        out["decoder"] = "openssl-cli"
    except Exception as exc:  # noqa: BLE001
        out["decoder"] = f"none ({type(exc).__name__})"
    return out
