# Running the lab on Windows

Everything in this repo is stdlib Python 3, so there is no installer, no `pip install`, no admin
prompt and no Docker. There are exactly three Windows-specific facts to know, and all three are
handled in code:

1. the interpreter command is `py` (or `python`), not `python3`;
2. a console on a legacy code page used to die on a `→` or a `·` in a `print` - every CLI now
   calls `lab/win.py:ready()`, which reconfigures stdout/stderr to UTF-8 with `errors="replace"`;
3. file encodings on Windows come from the ANSI code page unless you say otherwise - every text
   `open()` in the lab now passes `encoding="utf-8"` explicitly, and `tools/netinv.py` sniffs the
   UTF-16 BOM that PowerShell's `>` redirect produces.

Those three are pinned by checks: `tools/selftest.py` §12b parses a Windows-format `arp -a` table,
round-trips a UTF-16 file through `read_arp_file`, asserts `sys.stdout.encoding == utf-8` after
`ready()`, lints every `.py` in the repo for an `open()` without an encoding, and asserts every
CLI installs the shim. 158 checks pass. What I could *not* do is run this on real Windows from
here - the simulation used `LC_ALL=C PYTHONUTF8=0 PYTHONIOENCODING=ascii`, which reproduces the
crash mode (an ASCII console, an ASCII default file encoding) and the whole suite passes under it,
including `tools/run_all.py` and `tools/webcheck.py`. Treat "works on Windows" as strong inference,
not a signed-off test, and tell me what breaks.

---

## 1. Install (once, five minutes)

1. Get Python 3.10 or newer from <https://www.python.org/downloads/windows/>. In the installer,
   tick **"Add python.exe to PATH"** before clicking Install. If you skip it, `py` still works
   (the launcher is installed per-user), but `python` will not.
2. Open **Windows Terminal** (PowerShell profile). Terminal, not `cmd`, because it renders the
   UTF-8 tables and code blocks properly.
3. Check:

```powershell
py -3 --version        # Python 3.12.x
py -3 -c "import sys; print(sys.executable)"
```

If `py` is not recognised, close and reopen the terminal (PATH changes only apply to new
sessions), or use the full path `C:\Users\<you>\AppData\Local\Programs\Python\Python312\python.exe`.

Optional, only for the two `.sh` demos (§8): **Git for Windows** <https://git-scm.com/download/win>.
Optional, only for the nginx/Vagrant variants you were told are unverified here: WSL2 + Vagrant +
VirtualBox.

## 2. Unzip

Extract the archive to a short path with no spaces, e.g. `C:\lab\`:

```powershell
cd $env:USERPROFILE\Downloads
Expand-Archive .\ip-tracking-lab.zip -DestinationPath C:\lab
cd C:\lab\ip-tracking-lab\ip-lab
```

You should now see `apps`, `data`, `lab`, `notes`, `out`, `proxy_lab`, `tools`, `README.md`,
`LINES.md`, `WINDOWS.md`. Stay inside `C:\lab\ip-tracking-lab\ip-lab` for everything below.
(Do not unzip into OneDrive: it locks files while syncing and the lab writes reports into `out\`.
Do not unzip *over* an old copy either - `out\` and `__pycache__` from a previous version will
confuse you.)

## 3. Prove the copy is intact

```powershell
py tools\selftest.py
```

Expect, at the end:

```
RESULT: 158 checks passed
```

Two of those 158 need outbound TLS (a certificate probe against `1.1.1.1:443`). On a machine behind a
corporate proxy, an EDR product, or an ISP that filters 443 - which is exactly what happened on the
first real-Windows run of this lab - you will instead see

```
RESULT: 155 checks passed, 2 skipped: ['TLS SNI cert parse (no usable path to 1.1.1.1:443)', ...]
```

and the exit code is still 0, because a filtered network is not a lab defect. Make that explicit with
`py tools\selftest.py --offline` (152 passed, 2 skipped, no probing at all), or point the probe
somewhere your network does allow: `LAB_TLS_HOST=github.com py tools\selftest.py`
(`$env:LAB_TLS_HOST="github.com"` in PowerShell; `LAB_TLS_PORT`, `LAB_TLS_SNI` and `LAB_TLS_TIMEOUT`
also exist). A `FAIL` on any other line is a real problem - paste it to me.

That command otherwise touches no network. If it prints fewer PASSes and some `FAIL` lines, the archive
extracted wrong or you have Python 2 on `py` - fix that before anything else. If a line says
`SKIP`, it is a network-dependent assertion and it is telling you the truth about being offline.

Then run the whole lab start to finish (this is the fastest way to see every artefact once):

```powershell
py tools\run_all.py            # ten stages, ~30 s, prints each stage's first 60 lines
```

Every stage ends in `[exit 0]`. Anything else, scroll up to that stage's output and read it -
the tools print their reasons, that is the whole design of this repo.

## 4. Optional: make the console boring

The shim handles UTF-8 already, but if you want Windows itself out of the way for the session:

```powershell
$env:PYTHONUTF8 = "1"          # PowerShell; use `set PYTHONUTF8=1` in cmd
$OutputEncoding = [Console]::OutputEncoding = [Text.UTF8Encoding]::new()
```

## 5. Module by module (PowerShell versions)

Run from `C:\lab\ip-tracking-lab\ip-lab`. The `cd` into `ip-lab` matters only for the `notes/`
reading; every tool resolves its own paths from its own location, so `py C:\lab\ip-tracking-lab\ip-lab\tools\run_all.py`
also works from any folder (verified).

```powershell
py tools\gen_dataset.py                      # 1 · the incident log, deterministic
py tools\dossier.py data\target_access.log --xff
py tools\casefile.py data\target_access.log --min-hits 5 --title "RUN-ALL / inbound triage"
py tools\passive.py --ip 102.89.44.7          # RDAP/DoH lookups; --internal to stay offline
py apps\app.py --port 8095 --mode naive       # 2 · the target app (browser: http://127.0.0.1:8095)
py tools\web.py --port 8095                   #    9 checks against it
py tools\audit.py proxy_lab\nginx\edge_naive.conf --diff proxy_lab\nginx\edge_safe.conf
py tools\webcheck.py                          # 12 · A/B all 27 web classes (needs the DB free: see §6)
py apps\shop.py --port 8096 --mode vuln       #    then open http://127.0.0.1:8096 in a browser
py tools\eyeball.py serve --port 8097          # 13 · open it, then Ctrl+C and:
py tools\eyeball.py score
py tools\phish.py corpus                       #    and: py tools\phish.py msg mail.eml
py tools\triage.py --rule beacon_periodicity   # 14 · two rules, real evidence lines
py tools\triage.py --rule session_split_brain
```

Reading order is `notes/01` → `notes/13`; each note's first lines name the command that
produces the output it quotes.

## 6. Servers, firewall, Ctrl+C

`apps\app.py`, `apps\shop.py`, `tools\eyeball.py serve` and `tools\canary.py serve` all bind
`127.0.0.1` only - nothing on your LAN or the internet can reach them, and nothing they do
leaves the machine. Windows Defender Firewall may show a prompt anyway; **Cancel/Allow both
work** (a loopback listener does not need an inbound rule). Stop a server with `Ctrl+C`; if a
port stays busy,

```powershell
netstat -ano | Select-String ":8096"          # find the PID
taskkill /PID <pid> /F                        # kill it
```

`apps\shop.py` and `tools\webcheck.py` share `out\shop.sqlite` - do not run both at once, or the
spawned instance will not answer `/healthz` (that confusion is now pinned by a test on my side,
and the error line says exactly which instance failed to start).

## 7. Your own network audit (module 14, the one that sends packets)

```powershell
arp -a > arp.txt                              # PowerShell's UTF-16 redirect is handled
py tools\netinv.py scan --arp arp.txt 192.168.1.0/24 --i-own-this
py tools\netinv.py scan --arp arp.txt 192.168.1.0/24 --i-own-this --live --report out\netinv.md
```

`ipconfig` gives you the range (look at your adapter's IPv4 address and default gateway - a
`192.168.1.x` adapter means `192.168.1.0/24`). Without `--i-own-this` the tool prints the plan
and sends nothing; public addresses are refused outright regardless of what you type. `--live`
sends one read-only `GET` per documented endpoint and never a body, a cookie or an
`Authorization` header. Expect Windows Defender / an EDR product to notice a port sweep on the
LAN: it is your own subnet, and `netinv.py` will not go beyond it - but if the machine is your
employer's, that is exactly the case where `tools\roe.py` and written permission come first
(`LINES.md` §1).

Other per-machine commands in `notes/13-device-compromise.md` are labelled with the OS they run
on. For Windows, the useful ones are:

```powershell
Get-ScheduledTask | Where-Object State -ne Disabled | Select-Object -First 30
Get-Service | Where-Object StartType -eq Automatic | Sort-Object Name | Select-Object -First 40
netstat -ano | Select-String "LISTENING"       # then: Get-Process -Id <pid>
Get-Process | Sort-Object CPU -Descending | Select-Object -First 15 Path, Id, CPU
Get-AuthenticodeSignature C:\Windows\System32\drivers\*.sys | Where-Object Status -ne Valid
```

## 8. The two shell demos (optional)

`proxy_lab/chain_demo.sh` is the three-hop header-trust demo. It runs under **Git Bash**:

```bash
cd /c/lab/ip-tracking-lab/ip-lab
PY=python bash proxy_lab/chain_demo.sh
```

`PY=python` matters: the script probes for `python3` and falls back to `python`, and Git Bash
sees whatever is on your PATH. It starts five listeners on `127.0.0.1` (8080/8081/8085/8088/8089),
prints what each hop logged, and cleans up after itself. Its leftover-port sweep reads `/proc`,
which does not exist on Windows, so it quietly skips that step - kill stray servers with
`taskkill` as in §6 if a previous run was interrupted.

`proxy_lab/socat_chain.sh` needs `socat` and is really a WSL script; run it there or skip it.
The `Vagrantfile` and `provision/target.sh` are for WSL/Linux too, and I have never executed them
in this environment - they are unverified, and `proxy_lab/README.md` says so.

## 9. PowerShell vs bash reflexes

| you want | PowerShell | bash/Git Bash |
|---|---|---|
| first N lines | `... \| Select-Object -First 20` | `... \| head -20` |
| filter | `... \| Select-String "401"` | `... \| grep 401` |
| count lines | `(Get-Content x.log).Count` | `wc -l < x.log` |
| two commands in a row | `cmd1; cmd2` | `cmd1 && cmd2` |
| open a report | `Invoke-Item out\netinv.md` | `xdg-open out/netinv.md` |

`notes/*.md` are readable in VS Code (Markdown preview) or in the browser via any Markdown viewer;
they are plain text otherwise, so `Get-Content notes\01-pipeline.md` is fine for skimming.

## 10. If it does not run

- **`Py: unable to launch...` / `python not recognized`** - reopen the terminal; if still bad,
  `where.exe py` and use the printed full path everywhere.
- **`can't open file 'tools\selftest.py'`** - you are not in `ip-lab`. `pwd` / `Get-Location`.
- **`UnicodeEncodeError`** - you are running an interpreter older than 3.7 (no `reconfigure`);
  use 3.10+, or `$env:PYTHONUTF8="1"`.
- **`[webcheck] vuln instance never answered /healthz`** - a stale server holds
  `out\shop.sqlite`, or port 8095/8096 is taken: see §6, then rerun.
- **`Address already in use`** - `netstat -ano | Select-String ":8097"` then `taskkill /PID <pid> /F`.
- **Antivirus deletes a file** - it will not: this is source, no binaries, no installers. If it
  quarantines `out\lab_capture.pcap` (a synthetic capture), restore-and-exclude the `out` folder.
- Anything else: run `py tools\selftest.py` and paste me the FAIL lines. The tools print why they
  refuse; the refusal text is the answer more often than not.

## 11. Regenerating and resetting

```powershell
Remove-Item -Recurse -Force out            # reports, sqlite, uploads, logs - all regenerable
py tools\run_all.py                          # rebuilds everything the docs quote
```

`out\` is disposable by design (`notes/00-mechanics.md` rule 7 explains why it is excluded from
archives and snapshots). Nothing else in the repo should change while you work; if it does, that
is your edit, and `py tools\selftest.py` after every one.
