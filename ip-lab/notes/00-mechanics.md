# Module 0 — what is in this repo, what each piece does, and how it is implemented

Read this if you want the machine, not the syllabus. Everything is Python 3 stdlib only;
every number quoted below is from a run in this workspace.

```bash
python3 tools/selftest.py          # 159 checks: the lab tests its own claims
python3 tools/selftest.py --offline  # 152 + 2 skipped, when outbound TLS is filtered (Windows, corporate LAN)
python3 tools/run_all.py      # batch 1 end to end (6 stages)
bash proxy_lab/chain_demo.sh  # module 6 end to end
python3 tools/gen_pcap.py && python3 tools/triage.py   # module 7+10 (14/15 rules fire)
```

## 0.1 Shape of the thing

```
                 ┌─────────────── enrichment (public, read-only) ───────────────┐
 raw text ──┐    │  rdap.org + RIR fallbacks · ipinfo geo · DoH PTR via dns.google│
 logs/pcaps ├──> parsers ──> normalised records ──> per-IP profile ──> dossier   │
 configs  ──┘    │  (regex + struct)   (dicts/rows)    (Counter/SQL)   + score    │
                 └───────────────┬───────────────────────────────┬───────────────┘
                                 v                               v
                        incident markdown                alerts + triage notes
                        (casefile.py)                    + ack procedure
```

Four layers, and the layering is the lesson: **parse → normalise → decide → document**.
Nothing in the tree guesses; each layer's output is re-readable by the next one, and the
final artefacts are markdown/JSON you could hand to a lawyer or a reviewer.

## 0.2 `lab/` — the library

| file | what it does | how |
|---|---|---|
| `net.py` | classify an address (loopback/RFC1918/CGNAT/TC/carrier-grade/Tor exit/multicast), resolve DoH, parse certificates, cache results | `ipaddress` for all classification (no regex guessing); DoH via `https://dns.google/resolve?name=…&type=A\|PTR` because this box has no `dig`; certs read via `ssl` + an overridden `HTTPSConnection.connect()` to grab `getpeercert(True)` (DER→PEM→openssl for fields that `ssl` won't expose on 3.13); a JSON cache under `.cache/` keyed by query so repeat runs are free and offline-safe |
| `logs.py` | parse combined/nginx access logs *and* error logs; the forwarded-header trust walk; per-IP aggregation; timelines | one anchored prefix regex + positional *quoted* tails (`TAIL_NAMES`) so a stray quote can't shift columns; `real_ip()` = the whole module: **if no trust list, `remote_addr` wins and XFF is flagged as a lie; else walk right-to-left, consuming entries only while the *hop that wrote the next entry* is trusted, and treat a fully-trusted chain as "the client connected to my proxy"** |
| `tracer.py` | one address → owner, abuse contact, network name, geo, PTR, TLS cert, reputation, `traceability_score` + `ceiling` sentence | `rdap.org` returns a 302 that `urllib` won't follow into useful data, so it falls back to the four RIR endpoints directly; geo from ipinfo (city-level, `anycast` flag preserved because an anycast record is not a location); the score is a weighted sum of *evidence classes present*, and `ceiling` is one of three strings: `nothing actionable` / `abuse report to the network operator` / `ISP subscriber identification, via law enforcement / legal process` |
| `passive.py` | what's already public about a domain: subdomains from cert CT + RDAP, DNS records, response headers, a leak dictionary | no active probing at all — that's the design; `/` and a few known paths, then header/JSON diffing for `server`, `cf-ray`, `x-amp-id`, version strings |
| `canary.py` | honey tokens that tell you *something read this*, with consent gates | HMAC-signed token (`ip|ts|nonce|owner|scope`), state in `out/canary_state.json`, refuses to `issue` unless `consent` recorded who/what/scope; hits outside the scope get flagged "review then delete" |
| `pcap.py` | write a valid pcap, read it back, build flows, reassemble TCP | hand-rolled structs: global header 24 B, record 16 B, Ethernet 14, ARP 28 (`SHA[22:28] SPA[28:32] THA[32:38] TPA[38:42]` — three debugging rounds to get here), IPv4 `!BBHHHBBH4s4s`, TCP `data_off = l4[12]>>4`, flags at `l4[13]`. `PcapWriter.write()` takes a float epoch and splits sec/usec itself. `flows()` keys on the 5-tuple and counts `syn/synack/fin/rst/retrans/payload/ttl`; `reassemble()` concatenates payloads in capture order and says so in its docstring (no sequence bookkeeping — a documented lie, not a hidden one) |
| `detect.py` | the rules engine: schema, 15 rules, load flows/http, run, write alerts, triage text | SQLite (stdlib) with three tables joined on `flow_id`, so **every alert is reproducible from the pcap alone**; rules are SQL strings, so you can read the detection logic without learning a DSL; each rule carries `false_positives` + `ack` (the procedure that closes it) and `triage()` prints both — that pair is what a real detection engineering review demands of you |

## 0.3 `tools/` — the CLI layer

* **`selftest.py`** — 88 assertions across everything above: parser fixtures, the trust
  walk in 8 shapes, pcap round-trip (write → read → flows → reassembly), every detection
  rule firing on the planted capture, the audit rules against the two shipped nginx
  configs, `proxy_sim.decide()` in four modes, and a live-cert parse when the network
  allows it. It exists so that when you change something, the *documented* lesson breaks
  loudly instead of quietly.
* **`gen_dataset.py` / `dossier.py` / `casefile.py`** — a seeded incident log (737 lines,
  3 planted cases + noise), the per-address dossier with `--xff/--only-sus/--v6-rollup/
  --timeline`, and the write-up generator that emits the markdown with the ceiling sentence
  and the "what this does not say" block.
* **`probe.py` / `passive.py` / `canary.py`** — the header-forgery battery, the public-intel
  CLI, and the canary server. All of them refuse a target that isn't local. That check is
  the product, not a restriction on you.
* **`gen_pcap.py`** — one script that writes a pcap **and** an access log describing the same
  traffic, plus an answer key (`data/lab_capture_key.json`) that is computed by re-reading
  the file it just wrote. 226 flows. Planted: normal visitors, a 19-port sweep, 12 SSH
  attempts, a 7×401→302 ATO whose true client is `198.51.100.23` while the origin logs
  `10.0.0.1`, a 220 KB exfil POST, a retransmit decoy, a truncated capture, and the four
  **stealth shapes** of Module 10 (slow probe, no-jitter cadence, distributed stuffing,
  silent HTTP flow).
* **`triage.py`** — pcap + log → SQLite → 15 rules → alerts JSON + `out/triage.sqlite`,
  with `--flows-only`, `--rule`, `--re <ip> --dport <n>`, `--sigma`, `--json`.
* **`audit.py`** — 12 table rules + 1 inline check over nginx/apache/caddy/compose;
  `--diff` gives you `fixed / still open / introduced` (direction matters: it prints that
  the "safe" edge config *introduces* `trusted_too_wide`), `--patch` emits a hardened
  fragment, `--selftest` runs it against both shipped configs.
* **`webcheck.py`** — spawns `apps/shop.py` twice (`--mode vuln --seats 40`, then
  `--mode hard`), runs 23 probes against *both*, and prints `FIRES/quiet` per side. A row is
  `ok` only when the payload works on the vulnerable instance **and** is inert on the hardened
  one, so a fix that silently stopped working turns into exit 1 rather than a stale note.
  The coupon race gets its own 1-seat pair (8 parallel redemptions: 8 winners vs 1).
  `selftest.py` runs it as a subprocess and asserts `23 class rows all verdict=ok`.
* **`eyeball.py`** — the tracking demo run on yourself: a loopback server that prints the headers
  your browser volunteered, a JS panel that computes the canvas / WebGL / font-width / timezone /
  hardware set, and a `localStorage` id it wrote the first time it saw you. `profile()` scores the
  *set* of signals (weights are its own and it says so); `stability()` diffs two captures, which is
  the actual lesson: the fields that never move are what a tracker keys on. Nothing leaves
  127.0.0.1 and `/collect` refuses a cross-origin POST.
* **`phish.py`** — the analyst's read of a link or a whole `.eml`: registered-domain guess vs the
  pretty prefix, IDN/punycode and one-edit-from-a-brand labels, scheme/port/bare-IP shape,
  open-redirect parameters, then the message layer: SPF/DKIM/DMARC results, the origin-most
  `Received` hop vs the sender domain, Reply-To divergence, link text vs href, urgency and
  credential vocabulary, a form inside the mail. Score plus reasons, and a "what to do next" block.
  It is a detector only: no kit, no template, no generator - `LINES.md` §7 explains that in one row.
* **`netinv.py`** — a LAN audit with the gates in the code rather than the comments: public
  addresses are refused outright, targets must be inside ranges you pass explicitly, `--i-own-this`
  is required before a packet leaves, every probe is a GET with no cookies and never an
  `Authorization` header (it does not try credentials at all), one request per endpoint, and each
  response is sha256'd into an evidence file so the report is defensible. `--selftest` proves the
  gates, not just the parsers.
* **`web.py`** — the nine self-targeted web exercises; it refuses non-local hosts, never
  follows redirects (so a 302 is visible as a finding), and with `--scope` it routes every
  request through the signed scope file and refuses anything outside it.
* **`footprint.py`** — the OPSEC model + your machine's own record inventory (read-only) +
  live egress check. Arithmetic score, binding-constraint naming, per-hop retention/
  compellability.
* **`roe.py`** — the paperwork: scope JSON, ROE letter, get-out-of-jail card, custody log,
  `check` (allow/refuse), `sign`/`verify` (sha256 so you can prove the scope predates the
  traffic), `sweep` (allowlist fragment + SOC notification email).

## 0.4 `apps/app.py` and `proxy_lab/` — the parts you run against yourself

The target is stdlib `ThreadingHTTPServer` with three modes (`safe` = trust the socket
peer only; `naive` = believe the leftmost XFF; `cloudflare` = believe `CF-Connecting-IP`
when the peer verified, including the duplicate-header case), a `/debug/vars` leak, an
IDOR-prone object route, an `X-Original-URL` differential, an open redirect, and a
`/fetch` with a *string-prefix* allow-list that is deliberately bypassable — with
`ssrf_guarded()` at the bottom of the same file as the model answer. Every response includes
the IP it logged and *why*, because seeing the reason is the lesson.

`apps/shop.py` is the web-attack-surface playground: one `ThreadingHTTPServer`, 27 planted
classes (A injection, B XSS, C paths, D authorisation, E logic/state, F disclosure, G uploads,
H session cloning), and the fixes already written next to the bugs (`product_search_safe`,
`login_hard`, `jwt_guard`, `safe_path`, `safe_next`, `esc`, `bind_profile`, plus `CFG["atomic"]`
for the coupon). The `--mode
hard` flag routes every endpoint through those guards instead of the `# BUG:` path, which is
what makes `webcheck.py` able to A/B them without a second file. Secrets are fixed literals
(`correct-horse-battery`), the SQLite DB is `out/shop.sqlite`, uploads stay in `out/uploads`,
and it binds 127.0.0.1 only. Its `--selftest` drives the guard functions directly — no socket.  `apps/app.py` is the older, narrower target the header
modules drive: three logging policies (`safe|naive|cloudflare`) behind one pure function,
`logged_ip()`, plus the IDOR/SSRF/differential/debug routes `tools/web.py` and `tools/probe.py`
expect; `ssrf_guarded()` at the bottom is the model answer for its prefix-allow-list bug.
Design rule it adds: *a vulnerable demo is only useful if the fix is in the same file*, otherwise
you have a toy and a rumour.

`proxy_lab/proxy_sim.py` is a 200-line proxy that lets you *be* the nginx hop: `--mode
naive|correct`, `--trusted`, `--real-ip-header`, `--real-ip-recursive on|off`,
`--strip-inbound-xff`. Its decision logic is one function, `decide(peer, incoming_xff)`,
and the selftest drives that function directly — which is why the module-6 claims can't rot.
`chain_demo.sh` starts origin + relay + three edges, runs the same ATO battery through
each, diffs what every hop logged, prints the analyst verdict on the origin's log, and
audits the two nginx configs.

## 0.5 The design rules this code follows (steal these for your own tools)

1. **Every claim is a test.** If the README says a config produces a finding, there's an
   assertion. Docs rot; `RESULT: 159 checks passed` doesn't. A check that cannot run because the
   *network* is filtered must SKIP with a reason, not FAIL - `--offline` exists so that choice is
   explicit rather than accidental.
2. **Store the reason, not just the value.** `log_reason`, `X-Log-Reason`, every rule's
   `why`/`false_positives`/`ack`. An IP in a log field is a conclusion someone already made.
3. **Reproducibility over cleverness.** Alerts join on `flow_id`; a finding you can't
   re-derive from an immutable source is an opinion.
4. **Say what you didn't do.** Unverified paths (Vagrant/Docker/`nginx -t`) are named in the
   READMEs, not hidden; `reassemble()` prints its own inaccuracy.
5. **Refuse by default.** Local-only guards in every tool that sends traffic, plus
   `roe.py check` as the scope gate. A refusal you can read the reason for is better than a
   permission you have to remember.
6. **Stdlib so it runs where the incident is.** No pip, no root, no build step — the box
   you're on is the box that has the logs.
7. **Never put source under a directory your tooling may treat as build output.** Two lab apps
   lived in `target/` and silently disappeared from a restored workspace, because `target` is a
   build-dir name in most sync/backup/ignore rules. They live in `apps/` now, and `apps/app.py`
   says so in its docstring. `out/` is the same story in reverse: it is *meant* to be disposable,
   which is why everything in it is regenerable by `tools/run_all.py`.
