"""Whether a secrets file is readable by anyone but its owner.

Every skill's ``doctor`` checks that ``~/.vmware-<skill>/.env`` is 0600, because
that file holds the per-target passwords. The check was written as
``mode & (S_IRWXG | S_IRWXO)`` with the remedy ``chmod 600 <path>``, and on
Windows all three parts of that are wrong:

* NTFS has no POSIX mode bits. ``os.stat`` synthesises 0o666 for any writable
  file, so the check fails on a file nobody else can read.
* ``os.chmod`` on Windows only toggles the read-only attribute. The command
  exits 0 and changes nothing -- measured on Windows Server 2025, round 3:
  ``before: 644`` / ``chmod 600 exit=0`` / ``after: 644``.
* So ``doctor`` printed a red line on every run with a remedy that could not
  clear it. A permanent red is a red nobody reads.

The answer is not to pass quietly. "Nobody else can read this" and "this
platform cannot tell me" are different facts, and a secrets check that reports
the second as the first is worse than no check. :func:`check_secret_file`
returns three states, and ``UNKNOWN`` carries what the operator should look at
instead.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

#: ``ok`` — owner-only. ``too_open`` — group or other has access.
#: ``unknown`` — this platform does not express the answer in mode bits.
Verdict = Literal["ok", "too_open", "unknown", "missing"]

#: POSIX mode bits are meaningful where ``os.chmod`` actually enforces them.
#: ``os.name`` rather than ``sys.platform`` so Cygwin/MSYS builds, which do
#: honour the bits, are treated as POSIX.
POSIX_PERMISSIONS = os.name == "posix"


@dataclass(frozen=True)
class SecretFileCheck:
    """The verdict, the mode it was based on, and what to tell the operator."""

    verdict: Verdict
    path: Path
    mode: int | None
    message: str

    @property
    def is_failure(self) -> bool:
        """Only a *demonstrated* exposure fails. ``unknown`` is reported, not failed.

        Failing on ``unknown`` is what produced the permanent red: it turns "I
        cannot check" into "you are exposed", and the accompanying remedy does
        not work, so there is no way for the operator to make it green.
        """
        return self.verdict in ("too_open", "missing")


def check_secret_file(path: Path | str) -> SecretFileCheck:
    """Report whether ``path`` is owner-only, or say why that is not knowable."""
    p = Path(path).expanduser()
    try:
        mode = p.stat().st_mode
    except FileNotFoundError:
        return SecretFileCheck(
            "missing",
            p,
            None,
            f"Not found: {p} — passwords are read from here. Create it, then "
            f"restrict it to your account ({_remedy(p)}).",
        )
    except OSError as exc:
        return SecretFileCheck(
            "unknown", p, None, f"Could not stat {p}: {exc}"
        )

    if not POSIX_PERMISSIONS:
        return SecretFileCheck(
            "unknown",
            p,
            stat.S_IMODE(mode),
            f"{p} exists. This platform does not express file permissions as "
            f"POSIX mode bits, so whether other accounts can read it cannot be "
            f"checked here — and `chmod 600` would not change it either. Confirm "
            f"in the file's Properties > Security that only your account and "
            f"SYSTEM/Administrators have access, or run: {_remedy(p)}",
        )

    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        return SecretFileCheck(
            "too_open",
            p,
            stat.S_IMODE(mode),
            f"Permissions too open ({oct(stat.S_IMODE(mode))}) — other users on "
            f"this host can read your passwords. Run: {_remedy(p)}",
        )
    return SecretFileCheck(
        "ok", p, stat.S_IMODE(mode), f"Found, permissions 600: {p}"
    )


def _remedy(path: Path) -> str:
    """The command that actually restricts the file on this platform."""
    if POSIX_PERMISSIONS:
        return f"chmod 600 {path}"
    # icacls is the Windows equivalent that does something. /inheritance:r drops
    # inherited ACEs first, otherwise the grant is added alongside them and the
    # file stays as readable as the directory it sits in.
    return f'icacls "{path}" /inheritance:r /grant:r "%USERNAME%:F"'
