"""A secrets-permission check must not turn "cannot tell" into "you are exposed".

Round 3, finding 3.5. On Windows Server 2025 the ``.env`` check failed on every
run and the remedy it printed did nothing::

    before: 644
    chmod 600  exit=0        <- reports success
    after : 644              <- unchanged
    doctor: FAIL  Permissions too open (0o666) ... Run: chmod 600 ...

NTFS has no POSIX mode bits and ``os.chmod`` there only toggles the read-only
attribute, so the check could not pass, could not be fixed, and printed red on
every run of every skill's doctor. One root cause, three symptoms: a permanent
failure, an inert instruction, and a failing test (``AIops
test_autoencode_preserves_0600_permissions``, 438 != 384).

Passing quietly on Windows would be the other half of the same mistake -- this
file holds the passwords. So there are three verdicts, and only a demonstrated
exposure is a failure.
"""

from __future__ import annotations

import os
import stat

import pytest

from vmware_policy import fsperms
from vmware_policy.fsperms import check_secret_file


@pytest.fixture
def env_file(tmp_path):
    f = tmp_path / ".env"
    f.write_text("VMWARE_VC1_PASSWORD=x\n", encoding="utf-8")
    return f


@pytest.mark.skipif(not fsperms.POSIX_PERMISSIONS, reason="needs POSIX mode bits")
def test_group_readable_is_still_a_failure(env_file):
    os.chmod(env_file, 0o640)
    check = check_secret_file(env_file)
    assert check.verdict == "too_open"
    assert check.is_failure
    assert "chmod 600" in check.message


@pytest.mark.skipif(not fsperms.POSIX_PERMISSIONS, reason="needs POSIX mode bits")
def test_owner_only_passes(env_file):
    os.chmod(env_file, 0o600)
    check = check_secret_file(env_file)
    assert check.verdict == "ok"
    assert not check.is_failure


def test_a_platform_without_mode_bits_reports_unknown_not_exposed(env_file, monkeypatch):
    """The Windows path, forced. This is the finding, and it must not be a failure."""
    monkeypatch.setattr(fsperms, "POSIX_PERMISSIONS", False)
    if fsperms.POSIX_PERMISSIONS is False and os.name == "posix":
        os.chmod(env_file, 0o644)  # the mode Windows synthesises

    check = check_secret_file(env_file)
    assert check.verdict == "unknown"
    assert not check.is_failure, (
        "an unanswerable question was reported as a failure — this is the "
        "permanent red that no remedy could clear"
    )


def test_the_unknown_message_does_not_tell_the_user_to_run_chmod(env_file, monkeypatch):
    """The instruction has to be one that changes something on that platform.

    The message may still *mention* chmod -- saying it would not help is useful
    -- but the command it hands over must not be it.
    """
    monkeypatch.setattr(fsperms, "POSIX_PERMISSIONS", False)
    check = check_secret_file(env_file)
    assert "icacls" in check.message
    assert "Run: chmod" not in check.message
    assert fsperms._remedy(env_file).startswith("icacls")


def test_unknown_still_says_the_question_was_asked(env_file, monkeypatch):
    """Silence would be the other half of the mistake: this file holds passwords."""
    monkeypatch.setattr(fsperms, "POSIX_PERMISSIONS", False)
    msg = check_secret_file(env_file).message
    assert "cannot be checked" in msg


def test_a_missing_file_is_a_failure_everywhere(tmp_path, monkeypatch):
    monkeypatch.setattr(fsperms, "POSIX_PERMISSIONS", False)
    check = check_secret_file(tmp_path / "absent.env")
    assert check.verdict == "missing"
    assert check.is_failure, "no password file at all is a real problem on any OS"


@pytest.mark.skipif(not fsperms.POSIX_PERMISSIONS, reason="needs POSIX mode bits")
def test_the_posix_verdict_is_not_weakened_by_the_windows_branch(env_file):
    """Control: the fix must not have made every platform answer 'unknown'."""
    os.chmod(env_file, 0o666)
    assert check_secret_file(env_file).verdict == "too_open"
    assert stat.S_IMODE(env_file.stat().st_mode) == 0o666
