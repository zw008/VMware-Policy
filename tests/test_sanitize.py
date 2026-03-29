"""Tests for vmware_policy.sanitize."""

import pytest

from vmware_policy.sanitize import sanitize


@pytest.mark.unit
class TestSanitize:
    def test_strips_control_chars(self):
        assert sanitize("hello\x00world") == "helloworld"
        assert sanitize("a\x0b\x0cb") == "ab"
        assert sanitize("\x7f\x80\x9f") == ""

    def test_preserves_newline_and_tab(self):
        assert sanitize("line1\nline2") == "line1\nline2"
        assert sanitize("col1\tcol2") == "col1\tcol2"

    def test_truncates_to_max_len(self):
        long_text = "a" * 1000
        assert len(sanitize(long_text)) == 500
        assert len(sanitize(long_text, max_len=100)) == 100

    def test_handles_non_string_input(self):
        assert sanitize(12345) == "12345"
        assert sanitize(None) == "None"

    def test_empty_string(self):
        assert sanitize("") == ""

    def test_unicode_preserved(self):
        assert sanitize("中文测试") == "中文测试"
        assert sanitize("émojis 🎉") == "émojis 🎉"
