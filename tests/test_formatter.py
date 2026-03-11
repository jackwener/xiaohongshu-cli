"""Unit tests for formatter (no network required)."""

from xhs_cli.formatter import coerce_int, extract_note_id, format_count


class TestFormatCount:
    def test_small_number(self):
        assert format_count(123) == "123"

    def test_wan(self):
        assert format_count(12345) == "1.2万"

    def test_yi(self):
        assert format_count(123456789) == "1.2亿"

    def test_string_input(self):
        assert format_count("5678") == "5678"

    def test_string_large(self):
        assert format_count("50000") == "5.0万"


class TestCoerceInt:
    def test_int_input(self):
        assert coerce_int(3) == 3

    def test_string_input(self):
        assert coerce_int("42") == 42

    def test_invalid_string_falls_back(self):
        assert coerce_int("10+") == 0


class TestExtractNoteId:
    def test_plain_id(self):
        assert extract_note_id("abc123def") == "abc123def"

    def test_explore_url(self):
        result = extract_note_id("https://www.xiaohongshu.com/explore/abc123def")
        assert result == "abc123def"

    def test_url_with_params(self):
        result = extract_note_id("https://www.xiaohongshu.com/explore/abc123?xsec_token=xxx")
        assert result == "abc123"

    def test_discovery_url(self):
        result = extract_note_id("https://www.xiaohongshu.com/discovery/item/abc123")
        assert result == "abc123"

    def test_trailing_slash(self):
        result = extract_note_id("https://www.xiaohongshu.com/explore/abc123/")
        assert result == "abc123"
