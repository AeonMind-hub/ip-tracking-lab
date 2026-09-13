"""
Module 3 - passive fingerprinting. No packets are sent, no ports are touched:
everything here is answered by certificates, DNS and HTTP response headers.
This is what "who is actually hosting this?" really looks like in practice.
"""
from __future__ import annotations

import json
import os
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

from .net import get_json
from .tracer import tls_cert

LEAKY_HEADERS = {
    "x-backend-ip": "internal address of the origin server handed to the whole internet",
    "x-real-ip": "your nginx thinks it is helping a proxy that does not exist",
    "x-forwarded-for": "echoing a client header back proves you trust it - free spoofing bait",
    "x-debug-trace": "stack traces / request ids / internal hostnames",
    "x-amz-cf-id": "CloudFront distribution id, which maps to an AWS account",
    "x-azure-ref": "Azure front-door reference; the origin is one lookup away",
    "x-served-by": "Fastly/Varnish node name - tells you the CDN and often the POP city",
    "x-vercel-id": "Vercel project + region",
    "x-nf-request-id": "Netlify request id (region in the prefix)",
    "x-powered-by": "stack version disclosure - delete it",
    "server": "web server + version disclosure - trim it",
    "x-aspnet-version": "framework version disclosure",
    "x-drupal-cache": "cms disclosure",
    "x-generator": "cms disclosure",
    "via": "proxy chain, hop by hop",
    "cf-ray": "Cloudflare POP + ray id: correlates requests across their whole network",
    "x-iap-upstream": "Google Identity-Aware-Protection internal service name",
}


def resolve(domain: str, types: tuple[str, ...] = ("A", "AAAA", "MX", "TXT", "NS", "CNAME", "CAA")) -> dict:
    """DNS answers are the cheap window into how something is wired."""
    out: dict[str, list[str]] = {}
    for t in types:
        d = get_json(f"https://dns.google/resolve?name={urllib.parse.quote(domain)}&type={t}") or {}
        ans = [a.get("data", "").rstrip(".") for a in d.get("Answer", []) or []]
        if ans:
            out[t] = sorted(set(ans))[:12]
        elif d.get("Status") == 3:
            out[t] = ["NXDOMAIN"]
    return out


def front_of(domain: str) -> dict:
    """
    Is there a CDN in front, and if so which account? Answers:
    cert names + which edge ASN the record points at.
    """
    res: dict = {"domain": domain}
    addrs = resolve(domain, ("A", "AAAA"))
    ips = [x for x in (addrs.get("A", []) + addrs.get("AAAA", []))]
    res["addresses"] = ips[:10]
    if not ips:
        res["error"] = "no address records - either parked, filtered, or you typed the name wrong"
        return res
    ip = ips[0]
    # SNI the requested domain at that IP: the cert tells you who serves it
    cert = tls_cert(ip, 443, server_name=domain)
    res["sni_cert"] = {k: cert[k] for k in ("subject", "issuer", "notAfter", "decoder", "error") if cert.get(k)}
    sans = cert.get("sans") or []
    res["san_count"] = len(sans)
    res["wildcard_in_sans"] = [s for s in sans if s.startswith("*.")]
    # default-SNI probe on the same IP: what answers when you do not ask nicely?
    bare = tls_cert(ip, 443, server_name=ip)
    res["default_cert"] = {"subject": bare.get("subject"), "sans": (bare.get("sans") or [])[:15]}
    res["default_sans"] = (bare.get("sans") or [])[:12]
    res["default_verdict"] = ("IP answers for a set of unrelated names -> shared hosting / CDN edge, origin hidden"
                             if len((bare.get("sans") or [])) > 3 else
                             "IP answers only for this name -> likely the origin server itself, no proxy hiding it")
    who = get_json(f"https://ipinfo.io/{ip}/json") or {}
    res["edge_org"] = who.get("org")
    res["edge_loc"] = f"{who.get('city')}/{who.get('country')}"
    verdict = []
    org = (who.get("org") or "").lower()
    for name, note in [
        ("cloudflare", "Cloudflare proxy: origin IP is hidden. The cert SAN set + issuer is how you tell a CF-fronted site from a CF-registered one."),
        ("akamai", "Akamai edge"), ("fastly", "Fastly edge - x-served-by will name the POP"),
        ("amazon", "AWS (ALB/CloudFront) - the cert may reveal an internal service name"),
        ("google LLC", "Google Cloud / GFE"), ("microsoft", "Azure Front Door / App Service"),
        ("vercel", "Vercel"), ("netlify", "Netlify"), ("github", "GitHub Pages"),
        ("hetzner", "Hetzner - not a CDN, this is the origin itself"),
        ("contabo", "Contabo - raw VPS, no proxy protection"),
    ]:
        if name in org:
            verdict.append(f"{org} -> {note}")
    res["verdict"] = verdict or ["edge is not a big CDN - this IP is likely the origin itself (no proxy hiding it)"]
    return res


def headers(url: str) -> dict:
    """Pull response-side header intel (and TLS cert facts) for one URL."""
    parsed = urllib.parse.urlparse(url if "://" in url else "https://" + url)
    out = {"url": parsed.geturl(), "leaks": [], "response_headers": {}, "notes": []}
    hdrs: dict[str, str] = {}
    try:
        req = urllib.request.Request(parsed.geturl(), headers={"User-Agent": "Mozilla/5.0 (lab-probe)"})
        ctx = None
        if parsed.scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        held: dict = {}

        class _GrabHTTPS(urllib.request.HTTPSHandler):
            """Subclass the connection so we can read the peer cert afterwards."""

            def https_open(self, req):  # noqa: D102
                import http.client

                class _C(http.client.HTTPSConnection):
                    def connect(self):
                        super().connect()
                        # capture the cert while the socket is definitely still ours
                        try:
                            held["der"] = self.sock.getpeercert(True) if self.sock else None
                        except Exception:  # noqa: BLE001
                            held["der"] = None
                        held["host"] = self.host

                return self.do_open(_C, req, context=ctx)

        opener = urllib.request.build_opener(_GrabHTTPS()) if (ctx and parsed.scheme == "https") \
            else urllib.request.build_opener()
        with opener.open(req, timeout=12) as r:
            # urllib closes its connection the moment the body is consumed, so the
            # certificate is captured inside the connect() override and read here.
            der = held.get("der")
            out["status"] = r.status
            hdrs = {k.lower(): "; ".join(r.headers.get_all(k) or []) for k in set(r.headers.keys())}
            body = r.read(200_000)
            if hasattr(r, "geturl") and r.geturl() != parsed.geturl():
                out["notes"].append(f"redirected to {r.geturl()} - the final host is the real answer to 'where is this served from'")
            if parsed.scheme == "https":
                try:
                    if not der:
                        out["notes"].append("no peer certificate captured (plain HTTP? unusual TLS stack?)")
                    if der:
                        from ssl import DER_cert_to_PEM_cert
                        from .net import parse_pem
                        c = parse_pem(DER_cert_to_PEM_cert(der))
                        out["cert_subject"] = c.get("subject")
                        out["cert_issuer"] = c.get("issuer")
                        out["cert_notafter"] = c.get("notAfter")
                        out["cert_sans"] = (c.get("sans") or [])[:40]
                        out["cert_decoder"] = c.get("decoder")
                except Exception as exc:  # noqa: BLE001
                    out["notes"].append(f"cert not readable ({type(exc).__name__}); run tools/passive.py --domain for the SNI probe instead")
    except urllib.error.HTTPError as e:
        out["status"] = e.code
        hdrs = {k.lower(): "; ".join((e.headers.get_all(k) if e.headers else []) or []) for k in set((e.headers or {}).keys())}
        body = b""
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"{type(exc).__name__}: {exc}"
        return out

    out["response_headers"] = hdrs
    for h, why in LEAKY_HEADERS.items():
        if h in hdrs:
            out["leaks"].append({"header": h, "value": hdrs[h][:160], "why": why})
    cookie = hdrs.get("set-cookie", "")
    low = cookie.lower()
    if cookie and "httponly" not in low:
        out["notes"].append("session cookie without HttpOnly -> readable by JS, i.e. stealable by any XSS")
    if cookie and "secure" not in low:
        out["notes"].append("session cookie without Secure -> sendable over plaintext HTTP")
    if cookie and "samesite" in low and "strict" not in low:
        out["notes"].append("SameSite present but not Strict - CSRF reach depends on your flows")
    if hdrs.get("referrer-policy", "") == "unsafe-url":
        out["notes"].append("Referrer-Policy: unsafe-url -> full URLs (tokens, session ids in query) leak to every third party you link to")
    if not hdrs.get("strict-transport-security"):
        out["notes"].append("no HSTS - visitors can be downgraded / redirect-sniffed on first hit")
    if not hdrs.get("content-security-policy"):
        out["notes"].append("no CSP - any injected script can exfiltrate to any host, which is how 'IP leak' incidents actually happen")
    if body and (b"Traceback" in body or b"Django" in body and b"settings" in body.lower()):
        out["notes"].append("response body looks like a stack trace - internal paths, env keys and query strings just left the building")
    return out


def co_hosted(sans: list[str]) -> list[str]:
    """Other sites sharing the same certificate = same origin server or same CDN customer."""
    return sorted({s for s in sans if s and not s.startswith("*.")})


def report(domain: str | None = None, url: str | None = None, out_dir: str = "out") -> str:
    os.makedirs(out_dir, exist_ok=True)
    blob = {}
    if domain:
        blob["dns"] = resolve(domain)
        blob["front"] = front_of(domain)
        if blob["front"].get("sni_cert"):
            blob["co_hosted"] = co_hosted((tls_cert(domain, 443).get("sans") or []))
    if url:
        blob["headers"] = headers(url)
    path = os.path.join(out_dir, "passive_" + re.sub(r"\W+", "_", (domain or url or "x"))[:40] + ".json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(blob, fh, indent=2)
    return path
