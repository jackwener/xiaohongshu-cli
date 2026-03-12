"""Tests for CLI commands using Click's test runner."""

import yaml
from click.testing import CliRunner

from xhs_cli.cli import cli
from xhs_cli.exceptions import NoCookieError, SessionExpiredError, UnsupportedOperationError

runner = CliRunner()


class TestCliBasic:
    """Test CLI basics without requiring cookies."""

    def test_version(self):
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0." in result.output  # dynamic version from importlib.metadata

    def test_help(self):
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "xhs" in result.output
        assert "search" in result.output
        assert "read" in result.output

    def test_search_help(self):
        result = runner.invoke(cli, ["search", "--help"])
        assert result.exit_code == 0
        assert "keyword" in result.output.lower() or "KEYWORD" in result.output

    def test_read_help(self):
        result = runner.invoke(cli, ["read", "--help"])
        assert result.exit_code == 0

    def test_login_help(self):
        result = runner.invoke(cli, ["login", "--help"])
        assert result.exit_code == 0

    def test_status_help(self):
        result = runner.invoke(cli, ["status", "--help"])
        assert result.exit_code == 0

    def test_all_commands_registered(self):
        result = runner.invoke(cli, ["--help"])
        commands_expected = [
            # Auth
            "login", "status", "logout", "whoami",
            # Reading
            "search", "read", "comments", "sub-comments", "user", "user-posts",
            "feed", "hot", "topics", "search-user", "my-notes",
            "notifications", "unread",
            # Interactions
            "like", "favorite", "unfavorite", "comment", "reply", "delete-comment",
            # Social
            "follow", "unfollow", "favorites",
            # Creator
            "post", "delete",
        ]
        for cmd in commands_expected:
            assert cmd in result.output, f"Command '{cmd}' not found in CLI help"

    def test_whoami_help(self):
        result = runner.invoke(cli, ["whoami", "--help"])
        assert result.exit_code == 0

    def test_hot_help(self):
        result = runner.invoke(cli, ["hot", "--help"])
        assert result.exit_code == 0
        assert "category" in result.output.lower()

    def test_unread_help(self):
        result = runner.invoke(cli, ["unread", "--help"])
        assert result.exit_code == 0

    def test_my_notes_help(self):
        result = runner.invoke(cli, ["my-notes", "--help"])
        assert result.exit_code == 0

    def test_status_auto_yaml_when_stdout_is_not_tty(self, monkeypatch):
        monkeypatch.setenv("OUTPUT", "auto")
        monkeypatch.setattr(
            "xhs_cli.commands.auth.run_client_action",
            lambda ctx, action: {"nickname": "Alice", "red_id": "alice001"},
        )

        result = runner.invoke(cli, ["status"])

        assert result.exit_code == 0
        payload = yaml.safe_load(result.output)
        assert payload["ok"] is True
        assert payload["schema_version"] == "1"
        assert payload["data"]["authenticated"] is True
        assert payload["data"]["user"]["name"] == "Alice"

    def test_whoami_auto_yaml_when_stdout_is_not_tty(self, monkeypatch):
        monkeypatch.setenv("OUTPUT", "auto")
        monkeypatch.setattr(
            "xhs_cli.commands.auth.run_client_action",
            lambda ctx, action: {"nickname": "Alice", "red_id": "alice001", "user_id": "u-1"},
        )

        result = runner.invoke(cli, ["whoami"])

        assert result.exit_code == 0
        payload = yaml.safe_load(result.output)
        assert payload["ok"] is True
        assert payload["data"]["user"]["username"] == "alice001"

    def test_read_error_yaml_when_not_logged_in(self, monkeypatch):
        monkeypatch.setenv("OUTPUT", "auto")
        monkeypatch.setattr(
            "xhs_cli.commands._common.get_cookies",
            lambda source, force_refresh=False: (_ for _ in ()).throw(NoCookieError(source)),
        )

        result = runner.invoke(cli, ["read", "abc", "--yaml"])

        assert result.exit_code != 0
        payload = yaml.safe_load(result.output)
        assert payload["ok"] is False
        assert payload["error"]["code"] == "not_authenticated"

    def test_status_reports_not_authenticated_when_session_expired(self, monkeypatch):
        monkeypatch.setenv("OUTPUT", "auto")

        def fake_run_client_action(ctx, action):
            raise SessionExpiredError()

        monkeypatch.setattr("xhs_cli.commands.auth.run_client_action", fake_run_client_action)

        result = runner.invoke(cli, ["status", "--yaml"])

        assert result.exit_code != 0
        payload = yaml.safe_load(result.output)
        assert payload["ok"] is False
        assert payload["error"]["code"] == "not_authenticated"

    def test_logout_supports_structured_output(self):
        from xhs_cli.commands import auth

        original_clear_cookies = auth.clear_cookies
        auth.clear_cookies = lambda: None
        try:
            result = runner.invoke(cli, ["logout", "--yaml"])
        finally:
            auth.clear_cookies = original_clear_cookies

        assert result.exit_code == 0
        payload = yaml.safe_load(result.output)
        assert payload["ok"] is True
        assert payload["data"]["logged_out"] is True

    def test_delete_reports_unsupported_operation(self, monkeypatch):
        monkeypatch.setattr(
            "xhs_cli.commands.creator.run_client_action",
            lambda ctx, action: (_ for _ in ()).throw(
                UnsupportedOperationError("Delete note is currently unavailable from the public web API.")
            ),
        )

        result = runner.invoke(cli, ["delete", "note-123", "--yes", "--yaml"])

        assert result.exit_code != 0
        payload = yaml.safe_load(result.output)
        assert payload["ok"] is False
        assert payload["error"]["code"] == "unsupported_operation"

    def test_comments_rich_output_handles_string_reply_counts(self, monkeypatch):
        monkeypatch.setenv("OUTPUT", "rich")
        monkeypatch.setattr(
            "xhs_cli.commands.reading.run_client_action",
            lambda ctx, action: {
                "comments": [
                    {
                        "user_info": {"nickname": "tester"},
                        "content": "hello",
                        "like_count": "12",
                        "sub_comment_count": "2",
                    }
                ]
            },
        )

        result = runner.invoke(cli, ["comments", "note-123"])

        assert result.exit_code == 0
        assert "tester" in result.output
        assert "2 replies" in result.output


FAKE_NOTE_RESPONSE = {
    "items": [
        {
            "note_card": {
                "title": "Test Note",
                "desc": "body",
                "user": {"nickname": "Author"},
                "interact_info": {
                    "liked_count": "100",
                    "collected_count": "50",
                    "comment_count": "10",
                    "share_count": "5",
                },
                "tag_list": [],
                "image_list": [],
            }
        }
    ]
}

FAKE_SEARCH_RESPONSE = {
    "items": [
        {
            "id": "note_abc",
            "xsec_token": "tok_abc",
            "note_card": {
                "title": "搜索结果一",
                "user": {"nickname": "Author1"},
                "interact_info": {"liked_count": "10"},
                "type": "image",
            },
        },
        {
            "id": "note_def",
            "xsec_token": "tok_def",
            "note_card": {
                "title": "搜索结果二",
                "user": {"nickname": "Author2"},
                "interact_info": {"liked_count": "20"},
                "type": "video",
            },
        },
    ],
    "has_more": False,
}


class TestReadByShortIndex:
    """Test `xhs read <N>` short-index feature."""

    def test_read_help_mentions_index(self):
        result = runner.invoke(cli, ["read", "--help"])
        assert result.exit_code == 0
        assert "index" in result.output.lower()

    def test_read_index_not_found_when_no_cache(self, monkeypatch, tmp_path):
        monkeypatch.setattr("xhs_cli.cookies.get_index_cache_path", lambda: tmp_path / "index_cache.json")
        monkeypatch.setattr("xhs_cli.commands.reading.get_note_by_index",
                            lambda idx: None)

        result = runner.invoke(cli, ["read", "5"])
        assert result.exit_code != 0
        assert "5" in result.output or "5" in (result.exception and str(result.exception) or "")

    def test_read_index_resolves_to_note_id(self, monkeypatch):
        monkeypatch.setattr(
            "xhs_cli.commands.reading.get_note_by_index",
            lambda idx: {"note_id": "note_abc", "xsec_token": "tok_abc"} if idx == 1 else None,
        )

        called = {}

        def fake_run_client_action(ctx, action):
            from unittest.mock import MagicMock
            mock_client = MagicMock()
            mock_client.get_note_detail.return_value = FAKE_NOTE_RESPONSE
            action(mock_client)
            call_args = mock_client.get_note_detail.call_args
            called["note_id"] = call_args.args[0]
            called["xsec_token"] = call_args.kwargs.get("xsec_token")
            return FAKE_NOTE_RESPONSE

        monkeypatch.setattr("xhs_cli.commands._common.run_client_action", fake_run_client_action)

        result = runner.invoke(cli, ["read", "1", "--yaml"])
        assert result.exit_code == 0
        payload = yaml.safe_load(result.output)
        assert payload["ok"] is True
        assert called["note_id"] == "note_abc"
        assert called["xsec_token"] == "tok_abc"

    def test_read_index_out_of_range_gives_usage_error(self, monkeypatch):
        monkeypatch.setattr(
            "xhs_cli.commands.reading.get_note_by_index",
            lambda idx: None,
        )

        result = runner.invoke(cli, ["read", "999"])
        assert result.exit_code != 0
        assert "999" in result.output

    def test_save_index_from_items_extracts_note_ids(self, monkeypatch):
        from xhs_cli.commands.reading import _save_index_from_items

        saved = []
        monkeypatch.setattr("xhs_cli.commands.reading.save_note_index", lambda items: saved.append(items))

        _save_index_from_items(FAKE_SEARCH_RESPONSE)

        assert len(saved) == 1
        assert saved[0][0]["note_id"] == "note_abc"
        assert saved[0][1]["note_id"] == "note_def"

    def test_save_index_from_items_preserves_tokens(self, monkeypatch):
        from xhs_cli.commands.reading import _save_index_from_items

        saved = []
        monkeypatch.setattr("xhs_cli.commands.reading.save_note_index", lambda items: saved.append(items))

        _save_index_from_items(FAKE_SEARCH_RESPONSE)

        assert saved[0][0]["xsec_token"] == "tok_abc"
        assert saved[0][1]["xsec_token"] == "tok_def"

    def test_save_index_from_items_skips_empty_response(self, monkeypatch):
        from xhs_cli.commands.reading import _save_index_from_items

        saved = []
        monkeypatch.setattr("xhs_cli.commands.reading.save_note_index", lambda items: saved.append(items))

        _save_index_from_items({"items": []})

        assert saved == []  # nothing saved for empty results
