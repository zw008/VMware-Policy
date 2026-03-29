"""Prompt-injection defense: strip control characters and truncate untrusted text.

Consolidated from 22 duplicate ``_sanitize()`` implementations across 7 VMware skills.
All skills should import from here instead of defining their own copy.
"""

from __future__ import annotations

import re

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def sanitize(text: str, max_len: int = 500) -> str:
    """Strip C0/C1 control characters (except newline/tab) and truncate.

    Args:
        text: Untrusted text from vSphere/NSX/Aria API responses.
        max_len: Maximum length after truncation. Default 500.

    Returns:
        Cleaned, truncated string safe for LLM consumption.
    """
    return _CONTROL_CHAR_RE.sub("", str(text)[:max_len])
