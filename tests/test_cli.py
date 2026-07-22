"""Tests for CLI commands using Click's test runner."""

import pytest
import yaml
from click.testing import CliRunner

from xhs_cli.cli import cli
from xhs_cli.exceptions import NoCookieError, SessionExpiredError, UnsupportedOperationError

runner = CliRunner()

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

    def test_search_rich_output_shortens_visible_links(self, monkeypatch):
        monkeypatch.setenv("OUTPUT", "rich")
        monkeypatch.setattr(
            "xhs_cli.commands.reading.handle_command",
            lambda ctx, action, render, as_json, as_yaml: render({
                "items": [
                    {
                        "id": "69ad061d000000002603326d",
                        "xsec_token": "very-long-token-value",
                        "note_card": {
                            "title": "测试标题",
                            "user": {"nickname": "tester"},
                            "interact_info": {"liked_count": "12"},
                            "type": "normal",
                        },
                    }
                ],
                "has_more": False,
            }),
        )

        result = runner.invoke(cli, ["search", "openclaw"])

        assert result.exit_code == 0
        assert "search_result/69ad061d" in result.output
        assert "very-long-token-value" not in result.output

    def test_feed_rich_output_shortens_visible_links(self, monkeypatch):
        monkeypatch.setenv("OUTPUT", "rich")
        monkeypatch.setattr(
            "xhs_cli.commands.reading.handle_command",
            lambda ctx, action, render, as_json, as_yaml: render({
                "items": [
                    {
                        "id": "69ad061d000000002603326d",
                        "xsec_token": "another-very-long-token",
                        "note_card": {
                            "title": "推荐内容",
                            "user": {"nickname": "tester"},
                            "interact_info": {"liked_count": "9"},
                        },
                    }
                ]
            }),
        )

        result = runner.invoke(cli, ["feed"])

        assert result.exit_code == 0
        assert "explore/69ad061d" in result.output
        assert "another-very-long-token" not in result.output

    def test_read_help_mentions_short_index(self):
        result = runner.invoke(cli, ["read", "--help"])
        assert result.exit_code == 0
        assert "index" in result.output.lower()

    def test_comments_help_mentions_short_index(self):
        result = runner.invoke(cli, ["comments", "--help"])
        assert result.exit_code == 0
        assert "index" in result.output.lower()

    def test_read_index_resolves_note_context(self, monkeypatch):
        monkeypatch.setattr(
            "xhs_cli.note_refs.get_note_by_index",
            lambda idx: {
                "note_id": "note-abc",
                "xsec_token": "token-abc",
                "xsec_source": "pc_search",
            } if idx == 1 else None,
        )

        called = {}

        class FakeClient:
            def get_note_detail(self, note_id, **kwargs):
                called["note_id"] = note_id
                called["kwargs"] = kwargs
                return FAKE_NOTE_RESPONSE

        def fake_handle_command(ctx, action, render, as_json, as_yaml):
            action(FakeClient())
            return None

        monkeypatch.setattr("xhs_cli.commands.reading.handle_command", fake_handle_command)

        result = runner.invoke(cli, ["read", "1"])

        assert result.exit_code == 0
        assert called["note_id"] == "note-abc"
        assert called["kwargs"]["xsec_token"] == "token-abc"
        assert called["kwargs"]["xsec_source"] == "pc_search"

    def test_comments_index_resolves_note_context(self, monkeypatch):
        monkeypatch.setattr(
            "xhs_cli.note_refs.get_note_by_index",
            lambda idx: {
                "note_id": "note-abc",
                "xsec_token": "token-abc",
                "xsec_source": "pc_search",
            } if idx == 1 else None,
        )

        called = {}

        class FakeClient:
            def get_comments(self, note_id, cursor="", **kwargs):
                called["note_id"] = note_id
                called["cursor"] = cursor
                called["kwargs"] = kwargs
                return {"comments": []}

        def fake_run_client_action(ctx, action):
            return action(FakeClient())

        monkeypatch.setattr("xhs_cli.commands.reading.run_client_action", fake_run_client_action)

        result = runner.invoke(cli, ["comments", "1", "--yaml"])

        assert result.exit_code == 0
        assert called["note_id"] == "note-abc"
        assert called["kwargs"]["xsec_token"] == "token-abc"
        assert called["kwargs"]["xsec_source"] == "pc_search"

    def test_read_index_not_found_returns_usage_error(self, monkeypatch):
        monkeypatch.setattr("xhs_cli.note_refs.get_note_by_index", lambda idx: None)

        result = runner.invoke(cli, ["read", "999"])

        assert result.exit_code != 0
        assert "999" in result.output

    def test_search_empty_results_clear_previous_index(self, monkeypatch):
        from xhs_cli.note_refs import save_index_from_items

        saved = []
        monkeypatch.setattr("xhs_cli.note_refs.save_note_index", lambda items: saved.append(items))

        save_index_from_items({"items": []}, xsec_source="pc_search")

        assert saved == [[]]

    def test_user_posts_saves_index_entries(self, monkeypatch):
        saved = []
        monkeypatch.setattr("xhs_cli.note_refs.save_note_index", lambda items: saved.append(items))

        def fake_handle_command(ctx, action, render, as_json, as_yaml):
            class FakeClient:
                def get_user_notes(self, user_id, cursor=""):
                    return {
                        "notes": [
                            {"note_id": "note-1"},
                            {"note_id": "note-2", "xsec_token": "ignored"},
                        ],
                        "has_more": False,
                        "cursor": "",
                    }

            data = action(FakeClient())
            render(data)
            return None

        monkeypatch.setattr("xhs_cli.commands.reading.handle_command", fake_handle_command)

        result = runner.invoke(cli, ["user-posts", "user-1"])

        assert result.exit_code == 0
        assert saved == [[
            {"note_id": "note-1", "xsec_token": "", "xsec_source": ""},
            {"note_id": "note-2", "xsec_token": "ignored", "xsec_source": ""},
        ]]

    @pytest.mark.parametrize(
        ("command", "extra_args", "method_name"),
        [
            ("like", [], "like_note"),
            ("like", ["--undo"], "unlike_note"),
            ("favorite", [], "favorite_note"),
            ("unfavorite", [], "unfavorite_note"),
        ],
    )
    def test_short_index_resolves_for_note_actions(self, monkeypatch, command, extra_args, method_name):
        monkeypatch.setattr(
            "xhs_cli.note_refs.get_note_by_index",
            lambda idx: {
                "note_id": "note-abc",
                "xsec_token": "token-abc",
                "xsec_source": "pc_search",
            } if idx == 1 else None,
        )

        called = {}

        class FakeClient:
            def __getattr__(self, name):
                if name != method_name:
                    raise AttributeError(name)

                def _call(note_id):
                    called["method"] = name
                    called["note_id"] = note_id
                    return {"ok": True}

                return _call

        def fake_handle_command(ctx, action, render, as_json, as_yaml):
            action(FakeClient())
            return None

        monkeypatch.setattr("xhs_cli.commands.interactions.handle_command", fake_handle_command)

        result = runner.invoke(cli, [command, "1", *extra_args])

        assert result.exit_code == 0
        assert called == {"method": method_name, "note_id": "note-abc"}

    def test_short_index_resolves_for_comment(self, monkeypatch):
        monkeypatch.setattr(
            "xhs_cli.note_refs.get_note_by_index",
            lambda idx: {
                "note_id": "note-abc",
                "xsec_token": "token-abc",
                "xsec_source": "pc_search",
            } if idx == 1 else None,
        )

        called = {}

        class FakeClient:
            def post_comment(self, note_id, content):
                called["note_id"] = note_id
                called["content"] = content
                return {"ok": True}

        def fake_handle_command(ctx, action, render, as_json, as_yaml):
            action(FakeClient())
            return None

        monkeypatch.setattr("xhs_cli.commands.interactions.handle_command", fake_handle_command)

        result = runner.invoke(cli, ["comment", "1", "-c", "hello"])

        assert result.exit_code == 0
        assert called == {"note_id": "note-abc", "content": "hello"}

    def test_short_index_resolves_for_reply(self, monkeypatch):
        monkeypatch.setattr(
            "xhs_cli.note_refs.get_note_by_index",
            lambda idx: {
                "note_id": "note-abc",
                "xsec_token": "token-abc",
                "xsec_source": "pc_search",
            } if idx == 1 else None,
        )

        called = {}

        class FakeClient:
            def reply_comment(self, note_id, comment_id, content):
                called["note_id"] = note_id
                called["comment_id"] = comment_id
                called["content"] = content
                return {"ok": True}

        def fake_handle_command(ctx, action, render, as_json, as_yaml):
            action(FakeClient())
            return None

        monkeypatch.setattr("xhs_cli.commands.interactions.handle_command", fake_handle_command)

        result = runner.invoke(cli, ["reply", "1", "--comment-id", "c-1", "-c", "hello"])

        assert result.exit_code == 0
        assert called == {"note_id": "note-abc", "comment_id": "c-1", "content": "hello"}

    def test_favorites_saves_index_entries(self, monkeypatch):
        saved = []
        monkeypatch.setattr("xhs_cli.note_refs.save_note_index", lambda items: saved.append(items))
        monkeypatch.setattr("xhs_cli.commands.social._resolve_user_id", lambda ctx, user_id: "user-1")

        def fake_handle_command(ctx, action, render, as_json, as_yaml):
            class FakeClient:
                def get_user_favorites(self, user_id, cursor=""):
                    return {
                        "notes": [
                            {"note_id": "note-1"},
                            {"id": "note-2", "xsec_token": "token-2"},
                        ],
                        "has_more": False,
                        "cursor": "",
                    }

            data = action(FakeClient())
            render(data)
            return None

        monkeypatch.setattr("xhs_cli.commands.social.handle_command", fake_handle_command)

        result = runner.invoke(cli, ["favorites"])

        assert result.exit_code == 0
        assert saved == [[
            {"note_id": "note-1", "xsec_token": "", "xsec_source": ""},
            {"note_id": "note-2", "xsec_token": "token-2", "xsec_source": ""},
        ]]

    def test_my_notes_saves_index_entries(self, monkeypatch):
        saved = []
        monkeypatch.setattr("xhs_cli.note_refs.save_note_index", lambda items: saved.append(items))

        def fake_handle_command(ctx, action, render, as_json, as_yaml):
            class FakeClient:
                def get_creator_note_list(self, page=0):
                    return {
                        "note_list": [
                            {"note_id": "note-1"},
                            {"id": "note-2"},
                        ]
                    }

            data = action(FakeClient())
            render(data)
            return None

        monkeypatch.setattr("xhs_cli.commands.creator.handle_command", fake_handle_command)

        result = runner.invoke(cli, ["my-notes"])

        assert result.exit_code == 0
        assert saved == [[
            {"note_id": "note-1", "xsec_token": "", "xsec_source": ""},
            {"note_id": "note-2", "xsec_token": "", "xsec_source": ""},
        ]]
