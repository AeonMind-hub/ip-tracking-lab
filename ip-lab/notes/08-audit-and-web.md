# Module 8 — Audit and the web half (in scope, on yourself)

Two tools, one loop: `audit.py` reads *config* and predicts incidents; `web.py` reads
*behaviour* and proves them. The professional order is audit → fix → verify → write the
detection rule so it can't come back.

## 8.1 Audit

```bash
python3 tools/audit.py --selftest                                            # the rules are tested
python3 tools/audit.py proxy_lab/nginx/edge_naive.conf --diff proxy_lab/nginx/edge_safe.conf \
        --patch out/hardened_edge.conf
python3 tools/audit.py                      # scans /etc/nginx, /etc/apache2, Caddyfile, docker-compose.yml
python3 tools/audit.py --json out/audit.json /path/to/nginx.conf
```

Twelve rules in `tools/audit.py::RULES` (each with `why` + `fix`), plus one inline
check that has no table entry because it needs the parsed trust list, not a regex:

| rule | the shape of the future incident |
|---|---|
| `xff_forwarded_verbatim` | anyone can choose what your audit trail says |
| `real_ip_without_source` | same, via `real_ip_header` with no `set_real_ip_from` |
| `php_proxy_headers` | `trust proxy = true` / `HEADER_ALL` / `'proxies' => '*'` |
| `origin_header_disclosure` | `X-Backend-IP`, versioned `Server`, `expose_php` |
| `debug_route_public` | `/server-status`, `/debug/vars`, `/phpinfo` on a public listener |
| `log_format_no_rid` | no request id → you cannot join edge/app/db during an incident |
| `log_format_uses_xff` | the log's *client field* is a header (`log_format naive '$http_x_forwarded_for - …'` in `edge_naive.conf`) |
| `log_format_uses_xff` | the logged client field *is* a header |
| `auth_no_rate_limit` | login route, no limiter → credential stuffing |
| `cookie_flags` | session cookies without `Secure`/`HttpOnly`/`SameSite` |
| `referrer_policy` | `Referrer-Policy` unset → full URLs (with tokens, and often internal hostnames) leak to third parties |
| *inline:* `trusted_too_wide` | `set_real_ip_from 127.0.0.0/8` — the loopback trap, see `06` and the demo's :8088 |
| `retention_ipv6_mask` | a pipeline that truncates addresses before you can use them |
| `cors_wildcard_credentials` | `*` + credentials |

`--patch` emits a hardened fragment from your own findings. `--diff` is the part that
makes this a review artefact rather than a lint run — and the direction is the point:

```
$ python3 tools/audit.py proxy_lab/nginx/edge_naive.conf --diff proxy_lab/nginx/edge_safe.conf
DIFF (current -> compared config):
   fixed      2  ['log_format_uses_xff', 'xff_forwarded_verbatim']
   still open 0  none
   introduced 1  ['trusted_too_wide']   <- the candidate has this and the current does not: a REGRESSION, ask about it in the PR
```

Read that last line again: the config everyone calls "the correct one" **fixes the header
bug and introduces the trust-list bug in the same change**. A tool that only printed
"findings: 1" would have hidden that, and a reviewer who only reads the fix column
would have merged it. Two config files in this repo exist purely so that diff has
something true to say about both sides.

**Read the tool's own honesty line:** *no findings* is not a pass. Run
`bash proxy_lab/chain_demo.sh` and watch what the origin logs; that is the only way to
confirm the trust model, because a config can look correct and still have a second path
to the app (sidecar, health-checker, a `localhost` listener everyone can reach).

## 8.2 The web half — why these four and not "how to pwn a box"

```bash
python3 apps/app.py --port 8095 --mode naive &
python3 tools/web.py --port 8095 --chain-canary --canary-port 8090
```

Measured on this machine: **6/9** exercises produce a finding against `--mode naive`,
**5/9** against `--mode safe`. The single flip is the XFF exercise — proof that the proxy
mode is a *config* fix while IDOR, SSRF, the differential and the debug endpoint are *code*
bugs. Keep that split in mind for every real finding you ever write up: it decides who
owns the fix and how fast it can ship. (The `[miss]` on user enumeration is also real:
this app answers 401 + `invalid credentials` for unknown users and wrong passwords alike,
which is the correct shape — the exercise exists so you can break it and re-verify.)

Every request goes to loopback/RFC1918 and the script **refuses** a non-local host. The
four classes are the ones that (a) intersect IP/attribution work, (b) dominate real
breaches, (c) are yours to fix:

1. **IDOR** — `/api/v1/user/1` with no ownership check. Nothing "hacked", a tenant's
   data was read. Fix: authorise in the query, opaque ids, per-principal rate limits.
   (PortSwigger: *Access control vulnerabilities*, *IDOR*. Same idea as OWASP API1:2023.)
2. **SSRF** — `/fetch?url=…` → your own `/internal/metadata` (a stand-in for
   `169.254.169.254`). This is the *actual* mechanism behind most "IP leak" incidents:
   the request comes from **your server**, so CORS, browser policy and your edge WAF are
   all irrelevant. The lab's allow-list is a **string prefix**, so `tools/web.py` shows
   `localhost` and the redirect hop bypassing it while decimal/IPv6/`0.0.0.0` are
   blocked — and the exercise is to replace the block with `ssrf_guarded()` at the
   bottom of `apps/app.py` and watch every line go to "blocked". Real fix: resolve →
   validate every returned address in every family → dial the validated IP → re-validate
   on each redirect → deny-by-default egress → hop-limited/IMDSv2 metadata.
   (PortSwigger: *SSRF* + the 2024-era *blind SSRF / bisection* labs.)
3. **Parser differential** — `X-Original-URL: /admin` reaches the origin's router while
   the edge matched a harmless path. Our target also *proves the negative*: `/admin/..;/x`
   returns 404 because this app normalises; on a real stack that shape returns 200, which
   is why the note says "do that shape in a lab image, not here".
4. **Disclosure** — `/debug/vars` (`X-Backend-IP`, internal hostname, argv, env keys) and
   the 500-with-traceback. This is the "how did they know my origin?" answer 70 % of the
   time. Also: the traceback *echoed the logged IP* — a log line leaking to the client is
   an information-disclosure bug and an XFF-spoofing reward, both at once.
5. **Auth shape** — the lab's `/login` distinguishes 401 from 302, and sets no cookie
   flags. Uniform 401 + backoff on the (account, principal) pair + MFA for admin roles
   + `Secure; HttpOnly; SameSite=Lax` is the whole fix and it's ~15 lines.

## 8.3 Where to practise these for real (authorised only)

* **PortSwigger Web Security Academy** — free, legal, purpose-built, and it is literally
  the syllabus for classes 1–5 above. Do *Access control*, *SSRF*, *Web cache poisoning*,
  *Authentication*, *JWT* (a signed header is the same idea as `True-Client-IP`).
* **OWASP Juice Shop**, **DVWA**, **HackMyVM/betheme/venom** (VMs, host-only network),
  **HTB** `Dante/Lumberjack`-style starting boxes, **TryHackMe** `OWASP Top 10`,
  `Advent of Cyber`, `Ciham`, `Log Analiser`.
* **Bug bounties**: read the policy *before* the first request — in-scope hosts, rate
  limits, prohibited techniques (DoS, PII access, physical), safe-harbour terms
  (HackerOne/Bugcrowd/Intigriti each publish one). A "vulnerability" found outside scope
  is a case file *about you*.
* **Your own stack** — the highest-value option: audit it (`tools/audit.py`), fix it,
  re-run, publish the write-up with the diff. Recruiters recognise that; they do not
  recognise a screenshot of someone else's shell.

## 8.4 The four-part threat model, for any feature you build

Answer these in writing before you ship an endpoint. Every module in this lab maps back
to one of them.

1. **Who may say what?** (identity of the speaker: session, mTLS, signed header, proxy chain)
   → Modules 2, 6. This is where "who is this IP" is decided, and where it is usually lost.
2. **Whose data is it?** (ownership check at the query, not in the UI) → 8.2.1.
3. **What does it touch on your behalf?** (any user-supplied URL, path, host, S3 key,
   webhook → SSRF/LFI/XXE family) → 8.2.2.
4. **What does it say out loud when it fails?** (errors, headers, logs, stack traces,
   timing, status-code differences) → 8.2.4, `notes/02` §2.3, `audit.py`.

Then: what would I want in the log to reconstruct this in six weeks (`notes/01`), and
what is the retention/legal basis for keeping it (`notes/05`)?
