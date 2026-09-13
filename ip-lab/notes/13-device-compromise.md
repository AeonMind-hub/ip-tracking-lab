# 13 — Devices: anatomy of a compromise, and how you find one

"Accessing devices" is the part of the movie that is, in real life, mostly three things:
somebody *tricked* (phishing, an install prompt, a cracked binary), something *left open*
(a router, a camera, an old SMB share, a USB), and a *piece of software that keeps running*
(persistence, a beacon, a profile). This note is the anatomy plus the detection half — the
half that is a job, and the half you can practise here.

The build-it half (an implant, a keylogger, a RAT, an exploit chain, stalkerware) is not in
this lab, for reasons that are engineering reasons as much as legal ones: `LINES.md` §7 has
the table. What you get instead is the ability to answer, in minutes, "is this device clean,
what is talking to what, and how do I know?"

---

## 13.1 The five stages, and what each one leaves behind

| Stage | How it usually lands | Artefacts on the device | Network view | Lab hook |
|---|---|---|---|---|
| 1 delivery | link, attachment, "activation tool", USB, QR, malvertising, a browser extension update | downloads dir + mark-of-the-web, AMSI/browser download events, mail rule | nothing distinctive | `tools/phish.py msg <eml>` |
| 2 execution | user double-clicks, macro enabled, signed-binary proxy, LOLBin (`certutil`, `mshta`, `regsvr32`) | process tree with a parent that makes no sense; script-block logs; new child of `winword.exe` | one short outbound burst | — |
| 3 persistence | Run key / scheduled task / service / startup folder / WMI subscription; `systemd` user unit or a cron job; macOS `launchd` plist; mobile *device-admin* or an MDM profile | the autoruns diff, `schtasks /query`, `systemctl --user list-units`, `crontab -l`, `/Library/LaunchAgents`, Settings→General→VPN & Device Management | none yet | `tools/netinv.py` (the router/DNS variant) |
| 4 command & control | HTTP(S) beacon, WebSocket, DNS-over-UDP-53 or DoH, SMTP, or a dead-drop resolver | an unfamiliar process with a socket, `netstat`/`lsof -ni`, TLS to an untrusted issuer, a self-signed chain | **periodicity** — small payload, fixed period, light jitter | `lab/detect.py::beacon_periodicity` |
| 5 objective | credential theft (LSASS, browser cookie DB, keychain), exfil (upload, DNS tunneling, a "backup" to attacker cloud), lateral (SMB, RDP, SSH keys), impact (encrypt, wipe) | the read of a secret store, a large single upload, new local admin, a mail forwarding rule | one big outbound flow, or a burst of internal connections | `triage.py` exfil + `session_split_brain` |

Two structural facts to remember, because they explain almost every real case:

- **Stage 3 and 4 are independent of stage 1.** Delete the file and the beacon stays; that is
  why "antivirus found nothing" proves nothing, and why reimaging beats cleaning.
- **The credential path is shorter than the malware path.** Most "device hacks" against
  individuals are *no device hack at all*: a password + an SMS code, then an inbox rule that
  hides the notifications. So the first three things you check on a suspected-compromised
  account are sessions, mail forwarding rules, and recovery contacts — not the hard disk.

---

## 13.2 Detecting it, by OS (the actual commands)

Windows
```powershell
Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location   # autoruns, quick pass
schtasks /query /fo LIST /v | findstr /i "Ready Running"                      # scheduled tasks
Get-Service | Where-Object {$_.StartType -eq 'Automatic' -and $_.Status -eq 'Running'} |
  Where-Object {$_.PathName -notmatch 'Windows|Microsoft'}                     # non-MS services
Get-NetTCPConnection -State Established | Where-Object {$_.RemotePort -in 443,80,53,8080,4444,9001}
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 60
wevtutil qe Security "/q:*[System[(EventID=4672 or EventID=4720 or EventID=4732)]]" /c:40 /rd:true
```
Linux
```bash
systemctl list-units --type=service --state=running | grep -v -E "systemd|dbus|cron|getty@"
ls -l /etc/systemd/system/*.wants/ ~/.config/systemd/user/ ; crontab -l ; ls /etc/cron.*
cat /etc/ld.so.preload 2>/dev/null                       # rootkit classic
ss -tunap | grep -v -E "127.0.0.1|::1"                   # who is dialling out
sudo rkhunter --check ; sudo debsecan --only-enabled      # or: lynis audit system
last -n 30 ; sudo journalctl --since "7 days ago" | grep -iE "accepted publickey|sudo:.*COMMAND"
find / -xdev -perm -4000 -type f 2>/dev/null             # SUID set, and what is new
```
Android
```
Settings → Security → Device admin apps        # what may lock/wipe/reset-password your phone
Settings → Accessibility                     # the #1 stalkerware permission on Android
Settings → Apps → ⋮ → Special access → "Install unknown apps", "Display over other apps"
Settings → Google → Security → "Find your device" + recent device activity
adb shell pm list packages -3                # third-party packages, from YOUR phone over USB
adb shell dumpsys battery | grep -i level ; adb shell dumpsys netstats | head -40
```
iOS
```
Settings → General → VPN & Device Management      # profiles / MDM enrolment - if it is there and you
                                                  # did not add it, that IS the compromise
Settings → General → About → Composition          # what build you are on; patch level matters more
Settings → Safari → Extensions                    # each one can read every page you open
Settings → Face ID & Passcode → "USB Accessories" # turn off when the phone is locked
icloud.com/find                                   # is the device where you think it is
```
Everywhere: **the browser is a device-adjacent attack surface.** Extensions run against your
authenticated sessions, and a malicious or over-permissioned extension is a persistent,
credential-reading implant that no AV sees. List them, and remove the ones that "need to read
every site" for a convenience.

---

## 13.3 If you believe you are compromised (do it in this order)

1. **Disconnect, don't wipe.** Wi-Fi off / cable out. Do not reset, do not "factory" yet, do not
   delete the suspicious file. The artefacts are how you learn what happened, and if a person is
   watching, wiping tells them you know (see step 6).
2. **Take a snapshot of the state you can see:** the command outputs from §13.2, screenshots,
   the SHA-256 of anything odd (`sha256sum file`), and the timestamps. `tools/roe.py log
   --artifact <file>` is this exact custody pattern.
3. **Fix credentials from a different, known-clean machine** — password, then *sign out all
   sessions*, then app-based MFA (TOTP/passkeys, not SMS), then check recovery email/phone.
4. **Check the quiet backdoors on the account**: mail forwarding rules, "other mail accounts",
   OAuth app grants, API tokens, active sessions with device names. This is where 80% of
   "hacked" cases actually live.
5. **Then reimage.** A machine that ran untrusted code is not trustworthy again by removal; the
   cost of a clean reinstall is hours, the cost of a missed persistence mechanism is months.
   Restore files from a backup made *before* the incident, and treat every restored binary as
   suspect.
6. **If the adversary is a person close to you** (partner, family member, an "admin" at work):
   assume every input on that device is read, every microphone is live, and any account you sign
   into from it is surrendered. Change passwords *only* on a device they cannot touch, do it in
   a location where a hardware key logger makes no sense, and involve a specialist —
   `LINES.md` §4 has the if-you-are-contacted procedure; a domestic-violence organisation or a
   CERT can advise on evidence you can still use later. This is the scenario where "just scan
   with antivirus" is actively dangerous advice.
7. **Report where reporting works**: your org's SOC/CISO first (if it is a work device), then
   the platform (Microsoft/Google/Apple abuse forms carry the artefacts you kept), then NITDA/
   CERTN_UG and the EFCC for anything with money or threats in it, per `notes/12` §12.3.

---

## 13.4 The devices on the network around you

The two most commonly-owned "devices" for an individual are not a laptop: it is the **router**
(DNS settings changed, admin exposed to WAN, firmware from 2019, UPnP mapping whatever it likes)
and the **camera/smart gadget** (RTSP with no auth, a snapshot endpoint that answers to
anyone, firmware that will never update). `tools/netinv.py` audits exactly that, read-only, on
addresses you declare yours:

```
arp -a | python3 tools/netinv.py scan --arp - 192.168.1.0/24 --i-own-this --live
python3 tools/netinv.py audit --in out/netinv_evidence.json --report out/netinv.md
```

On Windows the pipe is awkward and `arp -a` looks different (dashes in the MAC, an `Interface:`
line, and one multicast/broadcast row per adapter), so save it to a file instead — `py`-style
commands and the code that copes with all of it are in `WINDOWS.md` §7:

```
arp -a > arp.txt
py tools\netinv.py scan --arp arp.txt 192.168.1.0/24 --i-own-this --live
```

`parse_arp` accepts colon or dash MACs and normalises to colons; `plan` drops the multicast and
broadcast rows so they never become targets; `read_arp_file` sniffs the UTF-16 BOM that
PowerShell's `>` writes, because reading that as UTF-8 gives you an empty table and a confident
report about zero devices.

Its guardrails are the interesting part, because they are what a professional tool looks like:
public addresses are refused outright (`netinv` will not aim at an IP outside your ranges even
with the flag), `--i-own-this` is required for a packet to leave, every probe is a GET with no
cookies and never an `Authorization` header — *it does not test credentials at all* — and each
response is hashed into an evidence file so your report can be defended afterwards. Design
rules like these are the difference between "a hacker tool" and "an assessment tool", and you
can copy them into anything you build.

The fix list it produces is boring and correct: change the admin password, turn off remote/WAN
management, disable UPnP, put gadgets on an IoT VLAN with no LAN access, patch or retire.

---

## 13.5 Exercises

16. **Beacon, then break it.** `python3 tools/gen_pcap.py && python3 tools/triage.py --rule
    beacon_periodicity`. Note the printed `cv_squared` for `10.0.0.88 -> 203.0.113.9:443`. Now
    edit `tools/gen_pcap.py` so the jitter is ±25 s instead of ±9 s and re-run: at what point does
    the rule stop firing, and why is "add jitter" a mediocre evasion but a great detection-tuning
    exercise? (You are building the detector's threshold, not an implant — that is the
    professional version of the same curiosity.)
17. **Find the cloned session.** `--rule session_split_brain` fires on `sid=S777`. Add a third
    visit for the same sid from a *different IP but the same UA* and confirm the rule stays quiet
    — then explain, in three sentences, why requiring both signals to move is what keeps this
    rule out of your on-call rota at 3 a.m.
18. **Track yourself once, on purpose.** Run `tools/eyeball.py serve`, visit it twice from your
    normal browser and once from a private window, then `diff` the captures. Which fields moved,
    which did not, and what would you have to change to make the *identity* hash move? Compare
    your answer with `notes/12` §12.5's list and with `tools/footprint.py`'s score — that
    disagreement is the real lesson about how much "cleaning up" buys you.
19. **Audit your own network.** Run §13.4's two commands on your home Wi-Fi (this is your
    equipment; the tool refuses anything else). Write down the three findings you would fix this
    week, then fix them, and re-run to see the count drop. That diff is as portfolio-ready as
    any config patch.
20. **Triage a phish.** Take the most recent "your account will be suspended" mail in your own
    inbox, save it as `.eml` (show original), and run `python3 tools/phish.py msg mail.eml`.
    Then run it on a genuine transactional mail from a company you use. If the scores are not
    obviously distinguishable, look at which signals were missing rather than at the number —
    and note that a *clean* score on a look-alike domain with a real certificate is exactly why
    out-of-band verification is the control, not the heuristic.
21. **Write the detection.** Pick one row of §13.1 stage 3 for your own OS and add a rule to
    `lab/detect.py` that would see it in the lab's data (a new autorun, a new device on the
    network, a first-seen destination port). Run `python3 tools/selftest.py`. If your rule needs
    data the lab does not collect, say which collector would — that gap, stated precisely, is
    the most common thing a detection-engineering interview is actually asking about.
