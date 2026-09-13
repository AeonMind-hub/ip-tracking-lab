# 11 — What is actually done to web applications

You asked for "what hackers do with webs, everything in a place". This is that place.
All 27 classes below are planted in `apps/shop.py`, running on your laptop, and
`tools/webcheck.py` proves each one fires — then proves the fix stops it.

**The rule that keeps this usable:** you point it at `127.0.0.1` and at systems you own or
are paid to test. That is not a moral footnote — it is what makes the difference between a
skill and a crime. `LINES.md` §6 is the web-specific version of that table — same payload,
different hostname, different statute. Everything in this file runs against the lab; the
decision procedure and the jurisdiction lines are `LINES.md` §§1–5. `notes/12` is the same lens pointed at attribution ("real tracking") and
`notes/13` at devices; `LINES.md` §7 lists what neither of them builds, and why.

---

## 11.1 The order of operations

Attackers do not start with an exploit. They start with a *map*, then look for the cheapest
entry point. The same order works as a defensive checklist and as an interview answer.

| # | Step | The question being asked | In this lab |
|---|---|---|---|
| 1 | **Recon** | What exists, what is it running, who owns it? | `curl -sI`, headers and tech fingerprint (F5) |
| 2 | **Exposure** | What did they forget to lock? | `/.env`, `/debug`, `/robots.txt`, `/uploads/` (F1–F4) |
| 3 | **Input surface** | Which parameters reach code? | `/search?q=`, `/file?name=`, `/notes`, `/upload` |
| 4 | **Entry** | Can I get a foot in the door? | SQLi login bypass (A4), forged token (D2) |
| 5 | **Authority** | Can I act as someone else / as admin? | IDOR (D3), `/admin` (D4), mass assignment (E1) |
| 6 | **Business logic** | Can I make the app do something it should not? | coupon race (E4), client price (E2), CSRF (E3) |
| 7 | **Pivot** | From this request, what else can I reach? | traversal → config → secret → sign your own token |
| 8 | **Cash out** | Data, money, persistence, other systems | the UNION dump of user hashes (A2) |

Notice what is *not* on the list: zero-days. The overwhelming majority of real compromises
are step 2 and steps 4–6 against code that was never written carefully. OWASP ranks broken
access control first precisely because it is boring and everywhere.

---

## 11.2 The classes, one table, then the detail

Six families. The `id` column is what `tools/webcheck.py` prints, so you can find the row in
`out/webcheck.json` and the corresponding `# BUG:` line in `apps/shop.py`.

| id | Class | The mistake in one sentence |
|---|---|---|
| A1 | SQLi, always-true | user text was pasted into a query, so it can close the string and add conditions |
| A2 | SQLi, UNION | the query returns columns; a second `SELECT` can return *other* columns |
| A3 | SQLi, error echo | database errors reach the browser, so the injection is self-describing |
| A4 | SQLi, auth bypass | the login query is built from the inputs, so the password becomes optional |
| A5 | User enumeration | the login answers differently for "no such user" vs "bad password" |
| B1 | Reflected XSS | input is written into HTML without escaping for the HTML context |
| B2 | Stored XSS | the same, but the payload is saved and replayed to every visitor |
| B3 | Upload → same-origin HTML | uploaded bytes are served back as `text/html` from the app's own origin |
| C1 | Path traversal | the filename is used to build a path without resolving + containing it |
| C2 | Absolute-path read | the same, with the shortcut: no prefix check at all |
| D1 | Open redirect | a `next=` parameter is trusted as a path, so the app vouches for an attacker's URL |
| D2 | JWT `alg:none` / alg confusion | the token says how to check it, so the attacker chooses "don't check" |
| D3 | IDOR / BOLA | "is this a valid session?" is answered, "is this *your* record?" never is |
| D4 | Missing function-level authz | only the URL path is protected, so the admin handler trusts whatever got through |
| E1 | Mass assignment | the framework copies request fields onto the model, including `role` |
| E2 | Client-supplied price | the money number comes from the request instead of the catalogue |
| E3 | CSRF via GET | a state change answers to a GET with no token, so any page can trigger it |
| E4 | Race / TOCTOU on a coupon | the decision and the write are separated, so N requests all "see" one seat |
| F1 | Secrets in `.env` | the deployment left a readable config file |
| F2 | Debug endpoint on | `/debug` prints the signing key, paths and recent requests |
| F3 | `robots.txt` as a directory | disallowed paths are a to-do list for anyone looking for admin surface |
| F4 | Directory listing | `/uploads/` enumerates everything anyone ever uploaded |
| F5 | Verbose `Server:` / `X-Powered-By` | free version numbers, i.e. a CVE lookup shortcut |
| G1 | Unrestricted upload | the extension suffix is the whole check, and it is served back from the same origin |
| H1 | Session replay (what a stolen token buys you) | a bearer token works from any device, because nothing binds it to one |
| H2 | Session fixation | the sid is chosen by the client and never rotated when a principal changes |
| H3 | Session-table exposure | `/admin/sessions` answers to a customer: every live session plus its device profile |

### A — injection
The universal shape: **data crosses into a place where it is parsed as code.** SQL is the
oldest example, so learn it there.

*Found by:* a `'` that changes the response (500, different length, different wording,
different timing) — that is all A1/A3 need. Automated versions of the same question:
`sqlmap`, or Burp's active scanner.
*Exploited as:* always-true (`' OR 1=1--`) to skip a login, then `UNION SELECT` to pull other
tables, then `LOAD_FILE`/`xp_cmdshell`/stacked queries when the DB and OS allow it. A2 in this
lab does the UNION step and returns the users table's email+md5 columns.
*Fixed by:* bound parameters only — `product_search_safe()`. Not an allow-list of characters,
not a blacklist of `--` (that is a *second* bug: it teaches the attacker which words you filter).
Escaping is per-context and last-resort.
*Detected by:* WAFs catch the obvious syntax and nothing else; the reliable signal is the
**response-difference** and DB-side errors, plus query-shape entropy per endpoint.

### B — XSS
Same crossing, different parser: text becomes markup (or an attribute, or JS, or CSS, or a
URL). Context decides which escaping is correct, which is why "we sanitise input" is a weak
answer.

*Found by:* a payload that survives to the HTML (`<svg onload=alert(1)>`, `<img src=x
onerror=...>`); reflectors are fuzzable, stored ones need a place to save text (search history,
profile fields, support tickets, file names, error messages).
*Exploited as:* session theft, action-forcing as the victim (which is XSS + CSRF in one),
keylogging in a fake form, phishing that renders inside the real domain.
*Fixed by:* escape at render in the right context + `Content-Security-Policy` with nonces to
make injected script inert + `HttpOnly` cookies so a successful XSS cannot read the session
(the shop's vuln mode omits that flag on purpose).

B3 is the variant people forget: the payload is not in a parameter at all, it is the *file*.
`/file?name=x.html` in vuln mode answers `Content-Type: text/html`, so a script you uploaded
runs on the shop's origin with the shop's cookies. Hard mode forces `text/plain` +
`Content-Disposition: attachment` + `X-Content-Type-Options: nosniff`, which is the minimum
any download endpoint should do.
*Detected by:* CSP `Report-Only` violations, and the payload strings in your own access log.

### C — file paths
`name=../../etc/passwd` is not exotic; it is what happens when the developer used the user's
string to build a filesystem path and then `open()`ed it. LFI on PHP (`php://filter` reads,
log poisoning then include) is the same mistake with a different reader.

*Fixed by:* resolve, then prove containment (`safe_path()`: `realpath` + prefix check; never
`if ".." in name` — double-encoding and symlinks walk past that).
Better: do not take a path at all. Take an ID and look the file up server-side.

### D — access control (the one that gets companies breached)
Two questions must both be answered on every request: **who are you** (authentication) and
**is this yours / are you allowed** (authorisation). Most apps answer the first and assume the
second. D3 and D4 are that gap.

JWT specifics: the token must be verified with an algorithm *the server picks*, not one the
token declares (`alg:none`, and the RS256→HS256 confusion where the public key becomes the HMAC
secret). Pin `alg`, require `exp`, keep a server-side revocation list for logout.

*Fixed by:* check ownership in the data layer (`WHERE id=? AND owner=?`), central authorisation
middleware rather than per-route memory, deny-by-default.
*Detested by:* nothing. This class is invisible to scanners — it needs an object-per-object
comparison. That is why it is #1.

### H — sessions, and what "duplicating" one really means

Three classes, and they are the ones that turn a *page* bug into an *account*:

- **H1 replay.** XSS (B1/B2/B3) or a leaked `sid` in a Referer header hands you someone's bearer
  token. It then works from anywhere, because a token is a bearer instrument and nothing asked
  "is this the machine that got it?". Fixes, in order of value: `HttpOnly` + `Secure` +
  `SameSite=Lax` cookies (the script can no longer read it), short lifetimes with rotation, and a
  **device binding** - `bind_profile()` in `apps/shop.py` compares a hash of UA+peer against the
  profile the session was created with, which is the toy version of DPoP / mTLS / attested-device
  tokens. The log-side view is `lab/detect.py::session_split_brain`.
- **H2 fixation.** If a client may choose the session id *before* authenticating and it survives
  authentication, the attacker plants `sid=ATTACKER123` in a link, the victim logs in on it, and
  the attacker is logged in as them. The whole fix is one line: rotate the identifier when the
  principal changes. Shop returns `rotated: false` in vuln mode and `true` in hard mode, so you
  watch the line do work.
- **H3 exposure.** A session list answering to a customer is a master key: identifiers plus the
  device profiles that used them. Deny by default, and never treat an admin-shaped *path* as the
  authorisation check - that is D4 one route over.

### E — business logic and state
No signature, so no WAF rule. The bug is that the app believed something about the world that
had already changed, or believed the user.

- **E3 CSRF**: any GET that changes state can be triggered by `<img src=...>` on someone else's
  page. Fix: state changes need POST + a per-session anti-CSRF token + `SameSite=Lax` cookies.
- **E4 TOCTOU**: `if remaining>0: sleep; remaining-=1`. Ten concurrent requests all pass the
  check. Fix: do the read-modify-write inside one critical section / one
  `UPDATE ... WHERE remaining>0` / a uniqueness constraint that makes double-spend impossible.
  In the lab: 1 seat, 8 parallel redemptions → **8 winners** on vuln mode, **1** on hard mode.
- **E1 mass assignment**: the ORM happily fills `role` because it is a column. Fix: an explicit
  allowed-field list per endpoint (the same idea as object-level `permit`), never "copy the
  request into the model".
- **E2 client price**: never trust a number that determines money. Recompute from the catalogue
  inside the transaction.

### F — configuration and exposure
Half of real findings never needed an exploit: `.env` in the web root, `/debug` on in
production, a staging subdomain with no auth, a directory index of old backups, default
credentials, an S3 bucket, a `.git` directory you can `wget`.

`tools/audit.py` is the lab's version of this thinking for nginx headers; `apps/shop.py`
plants the web-app half (F1–F5) so you can see how a fingerprint becomes a shortcut.

---

## 11.3 Chaining — the part that makes it serious

Single findings are usually Low/Medium. Chains are what turn into Criticals. Three you can
walk through in the lab, in order:

1. **Fingerprint → SQLi → credentials → reuse.** F5 tells you the version; A1 confirms the
   injection; A2 exports every email + unsalted MD5 hash; those passwords get tried again on
   the VPN/mail/SSH of the same humans. In this lab the last step is a paper exercise on
   purpose (the hashes are of literal strings like `password123`).
2. **Upload → served from same origin → stored XSS** (this is `B3`, and it is verified,
   not hypothetical): G1 accepts `x.html`, `/file?name=x.html` answers `text/html`, so your
   script runs on the app's origin with its cookies. That is why uploads need: type sniffing on content (magic bytes), a generated
   name, and a separate origin or `Content-Disposition: attachment` + `X-Content-Type-Options: nosniff`.
3. **IDOR → token forgery → admin.** D3 shows object IDs are guessable. The same IDs feed D2:
   if you can mint a token with `id: 3, role: admin`, then D4 (no function-level authz) means
   `/admin` is yours. One weak check per hop; nothing dramatic; full compromise.

SSRF is the fourth one that matters and lives in `apps/app.py` (`/fetch`) rather than shop.py:
a URL fetcher with a prefix allow-list that any redirect or decimal-IP form walks around, which
in a real deployment reaches `169.254.169.254` and the cloud role's temporary credentials.
`tools/web.py --ssrf` exercises it; `notes/08` §8.2 has the write-up.

---

## 11.4 The public toolchain, by name

You asked for the tools. Know what each does and *when* it is the right one; run them only
against your own assets (a lab box, your staging, or a paid engagement). They are not installed
in this sandbox and they do not need to be — the notes explain what each is doing, which is the
part worth learning.

| Layer | Tool | What it actually does |
|---|---|---|
| Discover hosts | `subfinder`, `amass`, `crt.sh`, `dig` | names in certificate transparency logs, DNS records |
| Live + fingerprint | `httpx`, `whatweb`, `wappalyzer` | which hosts answer, what status/size/title, which stack |
| Historical surface | `waybackurls`, `gau` | URLs and parameters the site once published — where old endpoints hide |
| Parameters | `arjun`, `ParamSpider` | which request fields the app reads (mass assignment needs you to guess names) |
| Content discovery | `ffuf`, `dirb`/`gobuster`, `dirsearch` | wordlist probing for paths, backups, admin panels |
| Known patterns | `nuclei` (templates), `nikto` | signed YAML descriptions of fingerprints and CVE-shaped requests |
| Injection | `sqlmap` | grammar-aware SQLi/oracle detection; slow, loud, extremely good at what it does |
| TLS/headers | `testssl.sh`, securityheaders.com | cipher suites, cert chains, header posture |
| Tokens | `jwt_tool`, `hashcat` | JWT alg-confusion matrix; offline cracking of a stolen hash set |
| Proxy / everything | **Burp Suite** (or OWASP ZAP) | intercept, replay, diff, scan, and the manual workflow all of the above is compared against |
| Lab targets | DVWA, Juice Shop, WebGoat, PortSwigger Web Security Academy | intentionally broken apps, legal to attack |

Read it as a *pipeline*: enumerate → fingerprint → discover surface → pattern-match → manual
verification of one finding at a time in Burp. The scanner never owns the finding; the person
who can explain why it is real does. That explanation is §11.6.

---

## 11.5 The defender's mirror (this is the employable half)

Twelve controls, each of which deletes a family above. If you can argue *why* each one works,
you can interview for appsec.

1. Bound parameters everywhere; no dynamic SQL built by concatenation. (kills A1–A4)
2. Context-aware escaping at render + CSP with nonces + `HttpOnly`/`Secure`/`SameSite` cookies. (B1, B2, blunts G1)
3. Files by ID, not by path; if a path is unavoidable: `realpath` + containment, serve from a separate origin, `nosniff`. (C1, C2, G1)
4. One authz middleware; ownership in the query; deny by default; check the *function*, not the URL. (D3, D4)
5. Server-pinned token algorithm, signature verified, `exp` required, server-side revocation. (D2)
6. Allow-listed relative redirects only, and no user-controlled `Location`. (D1)
7. State changes: POST, anti-CSRF token, `SameSite`, idempotency keys. (E3)
8. Atomic read-modify-write (transaction + re-check inside, or a constraint that makes the illegal state impossible). (E4)
9. Explicit field allow-lists on every write endpoint; money computed server-side in the transaction. (E1, E2)
10. Nothing secret in the web root; debug endpoints off outside dev; `robots.txt` is a hint file, not an ACL; directory indexes off. (F1–F4)
11. Strip/version-neutralise `Server`, `X-Powered-By`, and stack traces; structured error IDs instead. (F5, A3)
12. Rate limits and lockouts **keyed on the account**, not the source IP — and alerts on the shapes: parameter surprises, response-difference, uniform cadence, distributed auth failures. `tools/triage.py --rule distributed_credential_stuffing` is that rule, implemented.

---

## 11.6 Making a finding count

A finding nobody can act on is noise, and severity is not "it is a SQL injection" — it is what
it *lets someone do*. The five-part form used by every decent report:

```
Title        Unauthenticated SQL injection in /search exposes the users table
Location     GET /search?q=            (production, all regions)
Proof        1 request + the response that shows the difference. Reproducible by a stranger.
Impact       read of email + unsalted MD5 password hash for every account; then reuse.
Fix          parameterise the LIKE; add an index-only DB user; kill the error echo.
Severity     Critical: CVSS-ish reasoning = network, no auth, no interaction, high CIA impact.
```

The "so what" test: if you cannot finish the sentence *"an attacker can now …"* with something
the business cares about (money, data, admin, other tenants), you have not finished the work.
And report through the responsible channel — a `security.txt`, a VDP/Bounty platform, or the
contract you signed. Unilateral disclosure is how a good find becomes your problem.

---

## 11.7 The lab, and the exercises

Two servers, same code, opposite posture:

```bash
python3 apps/shop.py --port 8099 --seats 1      # vulnerable, 27 planted classes, one coupon seat
python3 apps/shop.py --port 8099 --seats 1 --racers 8   # same, but the race demo cannot miss
python3 apps/shop.py --port 8098 --mode hard    # same app, every class fixed
python3 apps/shop.py --selftest                 # guard logic, no socket needed
python3 tools/webcheck.py                         # spawns both, A/B's every class, exits 1 on any mismatch
python3 tools/webcheck.py --keep                  # leaves them up so you can curl by hand
```

Two exit codes matter when it fails. `MISMATCH` means a class did not behave the way the row
above claims - that is a finding about the lab, and the whole table is worth pasting somewhere.
`UNVERIFIED` (exit 2) means the harness could not start one of its own instances: it then refuses
to print the all-clear line, because something it never measured cannot be reported as safe. The
first version ignored the answer from its own readiness probe while spawning the single-seat pair
for E4, which is exactly how a slow machine (defender scanning `python.exe`) got a bogus
`E4 MISMATCH` and a hunt for a bug that was not there. Now: 30 s of patience for a slow start,
3 s and a real error for a dead child, three attempts, and a re-measure when either side reports
`0 wins` - zero is not a possible outcome of two live servers, so it means they were not serving.

Why `--racers 8` exists: E4 is a check-then-act race, and a race only *shows* if the requests are
inside the gap at the same time. Over HTTP that is scheduler luck - on one Windows box exactly one
redemption was ever in flight, so the app printed "1 winner" for a single seat, the harness printed
`E4 ... MISMATCH`, and a broken-looking row pointed at code that was faithfully broken. Now the
vulnerable instance holds all eight arrivals at the check point and releases them together
(`_race_window`, with a timeout so a lone request never hangs), and `shop.py --selftest` asserts
the gate itself: hold-until-peer, and release-by-timeout. Both checks fail loudly if the gate is
disabled - verified by disabling it: `held 0.05s`, `FAIL`, exit 1. The vulnerable *code* is
unchanged, only the window it gets is no longer left to chance.

`tools/webcheck.py` real output (this is the verification, not a promise):

```
id  class                                                     vuln      hard   verdict
------------------------------------------------------------------------------------------------
A1  SQLi — always-true dumps the catalog                     FIRES/200       quiet/200   ok
A2  SQLi — UNION reads the users table                       FIRES/200       quiet/200   ok
A3  SQLi — error message echoed to the page                  FIRES/200       quiet/200   ok
A4  SQLi — login bypass with ' OR 1=1--                      FIRES/302       quiet/401   ok
A5  User enumeration — 404 for unknown, 401 for wrong p      FIRES/404       quiet/401   ok
B1  XSS — reflected in the search box                        FIRES/200       quiet/200   ok
B2  XSS — stored in the guestbook                            FIRES/200       quiet/200   ok
B3  Upload served as same-origin HTML (script executes)      FIRES/200       quiet/200   ok
C1  Path traversal — /etc/passwd via /file?name=             FIRES/200       quiet/404   ok
C2  Absolute path accepted by the file reader                FIRES/200       quiet/404   ok
D1  Open redirect on logout                                  FIRES/302       quiet/302   ok
D2  JWT alg=none — forged admin token accepted               FIRES/200       quiet/401   ok
D3  IDOR — one customer token reads another account          FIRES/200       quiet/401   ok
D4  Missing function-level authz — /admin with any vali      FIRES/200       quiet/403   ok
E1  Mass assignment — role=admin at registration             FIRES/200       quiet/200   ok
E2  Client-supplied price honoured                           FIRES/200       quiet/200   ok
E3  CSRF by GET — coupon spent with no token, no POST        FIRES/200       quiet/405   ok
F1  Secrets in /.env                                         FIRES/200       quiet/404   ok
F2  /debug leaks the signing key and paths                   FIRES/200       quiet/404   ok
F3  robots.txt advertises the admin surface                  FIRES/200       quiet/200   ok
F4  Directory listing on /uploads/                           FIRES/200       quiet/403   ok
F5  Server header fingerprint (fake nginx + PHP)             FIRES/200       quiet/200   ok
H1  Session replay — stolen token used from another dev      FIRES/200       quiet/401   ok
H2  Session fixation — attacker-chosen sid survives aut      FIRES/200       quiet/200   ok
H3  Session table readable by a non-admin (/admin/sessi      FIRES/200       quiet/401   ok
G1  Upload — .html accepted and served back inline           FIRES/200       quiet/415   ok
E4  Coupon race — 1 seat, 8 parallel redemptions        8 wins          1 wins   ok
------------------------------------------------------------------------------------------------
[webcheck] 27 classes checked -> /home/user/ip-lab/out/webcheck.json
[webcheck] every class fires when vulnerable and is blocked when hardened
```

Hand-curl the ones that interest you (all localhost, all against the app's own fake data):

```bash
B=http://127.0.0.1:8099      # the vulnerable instance from the block above
curl -s "$B/search?q=%27%20OR%201%3D1--"                          # A1 always-true
curl -s "$B/search?q=x%27%20UNION%20SELECT%20id%2Cemail%2C0%2Chash%20FROM%20users--"   # A2
curl -s "$B/file?name=../../../../../etc/passwd" | head -1          # C1, five levels up from out/uploads
curl -s -o /dev/null -D- "$B/logout?next=https%3A%2F%2Fevil.test"   # D1, Location: attacker host
curl -s -X POST "$B/register" -d 'email=e@shop.test&role=admin'    # E1, self-issued admin token
for i in $(seq 8); do curl -s "$B/cart/coupon?code=LAUNCH25" & done; wait   # E4: 8 winners, 1 seat
python3 -c 'import base64,json;b=lambda d:base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=");print(b({"alg":"none","typ":"JWT"})+"."+b({"sub":"boss@shop.test","id":3,"role":"admin"})+".")' \
  | xargs -I{} curl -s -H "Authorization: Bearer {}" "$B/admin"      # D2 + D4
```

**Exercises.**

12. **A/B every row.** Run `python3 tools/webcheck.py --keep`, then reproduce three rows with
    `curl` by hand on each instance. For one of them, explain why the hard-mode response is the
    correct status code and not just "different".
13. **Break the fix.** Pick a class and try to get around its guard *in hard mode* — e.g.
    `..%2f`, `....//`, an absolute path, an `upload.php`, a `//evil.test` redirect. Whatever you
    find is either a real second bypass (fix it, add an assertion to `shop.py --selftest`) or a
    lesson in why the guard is written the way it is. Record which.
14. **Write it up as a report.** Take A2 and produce §11.6's five-part form as if the app were
    a client's. Then downgrade it deliberately (e.g. "the search is cached, low impact") and
    argue back. Severity is a negotiation; be the person who can argue both sides.
15. **Detect it.** Ship the same two payloads through `tools/triage.py`'s rules by adding log
    lines to `data/target_access.log` (or generate a pcap with `tools/gen_pcap.py`). Which of
    the 27 classes are visible in an access log at all, and which are invisible without app
    telemetry? That list is the argument for WAF→RASP/agent coverage.

---

## 11.8 What this file deliberately does not cover

Being exact about the edges, so you know what you still need:

- **No server-side code execution.** B3 gives an attacker *browser* code on the app's
  origin — which is what most real upload findings actually are — but it never becomes a shell
  here: no interpreter handler, no writable template directory, no deserialization sink
  (`pickle`/`ObjectInputStream`/`ysoserial`), no `include`. Upload→RCE needs a real web server
  and a real runtime, which is the `vagrant up` box (`Vagrantfile`), not a stdlib script.
  Everything shop.py touches stays inside `out/uploads`, and the app never executes it.
- **No evasion, no persistence, no anti-forensics** — and no "how to not get caught" beyond
  `notes/10`'s point that a record always exists somewhere. `LINES.md` has the why.
- **No mass scanning of third parties**, no credential-stuffing against real identity
  providers, no person lookup from an address (modules 1–4 prove that is not yours to do).
- **API-specific classes** (BOLA at scale, GraphQL introspection/depth abuse, JWT `kid` path
  traversal, OAuth redirect_uri mistakes, algorithm-stripping in mobile clients) follow the same
  six families above with a different transport. Practice them on the Portswigger labs, and note
  that `tools/audit.py` already speaks about the header layer they inherit.
- **Cloud identity posture** (S3/blob permissions, IAM role chains, metadata services) is
  covered only as far as SSRF in `apps/app.py`; the rest is a different lab.
