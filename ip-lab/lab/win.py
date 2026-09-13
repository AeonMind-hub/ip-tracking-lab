"""One small Windows shim, imported by every CLI in this lab.

Two things go wrong on a Windows console that never go wrong on macOS or Linux, and both are
purely cosmetic-but-fatal: the console's code page is usually cp850/cp1252, so a `print("->")`
or a box-drawing table can raise UnicodeEncodeError before any work happens; and a file opened
without an explicit encoding inherits that same code page, so a report written here and read
back on a Linux box is mojibake. `ready()` fixes the first, and every writer in the lab now
passes encoding="utf-8" explicitly to fix the second.

It is deliberately the least clever thing in the repo: it touches the two stream objects and
nothing else. If reconfigure is unavailable (Python < 3.7) or the stream is already a pipe with
its own encoding, it does nothing. Nothing in the lab depends on it succeeding - it only turns
"UnicodeEncodeError at line 1" into "the arrow renders as a question mark".
"""

from __future__ import annotations

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


def python_cmd() -> str:
    """What to type at a prompt to run *this* interpreter: `py` on Windows, `python3` elsewhere."""
    return "py" if sys.platform == "win32" else "python3"


if __name__ == "__main__":
    ready()
    print("platform:", sys.platform, "| python:", sys.version.split()[0], "| prompt:", python_cmd())
    print("unicode smoke test: → · é Å Ê ‹ › █ ▓ ─ ✅ (if you can read this line, the console is fine)")
