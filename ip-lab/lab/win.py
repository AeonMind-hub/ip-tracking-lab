"""One small Windows shim, imported by every CLI in this lab.

Two things go wrong on a Windows console that never go wrong on macOS or Linux, and both are
purely cosmetic-but-fatal: the console's code page is usually cp850/cp1252, so a `print("->")`
or a box-drawing table can raise UnicodeEncodeError before any work happens; and a file opened
without an explicit encoding inherits that same code page, so a report written here and read
back on a Linux box is mojibake. `ready()` fixes the first, and every writer in the lab now
passes encoding="utf-8" explicitly to fix the second.

There is a third function here, `fs_safe`, because a real Windows run found a third class of
bug this lab had: a cache file named from an IPv6 address (`rdns_2001:db8::1.json`). ':' is a legal
character in a Linux filename and an illegal one on Windows, so two stages of `run_all.py` died
with `OSError: [Errno 22] Invalid argument` on a machine that was otherwise passing everything -
and no amount of testing on the author's own OS would have shown it.

Everything else here stays deliberately dumb: `ready()` touches the two stream objects and nothing
else, and if reconfigure is unavailable (Python < 3.7) or the stream is already a pipe with its own
encoding, it does nothing. Nothing in the lab depends on it succeeding - it only turns
"UnicodeEncodeError at line 1" into "the arrow renders as a question mark".
"""

from __future__ import annotations

import hashlib
import re
import sys


def ready() -> None:
    """Make stdout/stderr UTF-8 and non-raising. Safe to call more than once."""
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):        # closed, redirected weirdly, or not a TextIOWrapper
            pass


_ILLEGAL = re.compile(r'''[<>:"/\\|?*\x00-\x1f]''')
_RESERVED = {"CON", "PRN", "AUX", "NUL",
             *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


def fs_safe(name: str, maxlen: int = 100) -> str:
    """Make *name* legal as a filename on Windows as well as Linux.

    Used for anything the lab names a file after: an IP address, a hostname, a lookup key. Legal
    names come back untouched so existing cache files stay valid; a name that had to change gets a
    short hash of the original appended, so `a::b` and `a__b` cannot quietly land on the same file.
    `CON`/`NUL`/`COM1` are reserved on Windows even with an extension, and a trailing dot or space
    is silently dropped by the shell, so both are handled here too.
    """
    stem = _ILLEGAL.sub("_", name).rstrip(". ")
    if len(stem) > maxlen:
        stem = stem[:maxlen].rstrip(". ")
    if stem.split(".")[0].upper() in _RESERVED:
        stem = "_" + stem
    if stem != name:
        stem = stem + "-" + hashlib.sha1(name.encode("utf-8", "replace")).hexdigest()[:8]
    return stem or "x"


def python_cmd() -> str:
    """What to type at a prompt to run *this* interpreter: `py` on Windows, `python3` elsewhere."""
    return "py" if sys.platform == "win32" else "python3"


if __name__ == "__main__":
    ready()
    print("platform:", sys.platform, "| python:", sys.version.split()[0], "| prompt:", python_cmd())
    print("unicode smoke test: → · é Å Ê ‹ › █ ▓ ─ ✅ (if you can read this line, the console is fine)")
    for probe in ("2001:4488:1060:1c4a::1", "rdns_2001:db8::1", 'a<b>|c"d*e?f', "CON", "x" * 140):
        print(f"  fs_safe({probe[:28]!r:32s}) -> {fs_safe(probe)}")
