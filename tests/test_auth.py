"""Tests for auth profile enrichment helpers."""

from xhs_cli.commands import auth


class _GuestOnlyClient:
    def get_self_info(self):
        return {"user_id": "u-1", "guest": True}

    def get_user_info(self, user_id: str):
        assert user_id == "u-1"
        return {
            "basic_info": {
                "nickname": "Alice",
                "red_id": "alice001",
                "desc": "hello",
            },
            "interactions": [],
        }


class _BrokenDetailClient:
    def get_self_info(self):
        return {"user_id": "u-2", "guest": True}

    def get_user_info(self, user_id: str):
        raise RuntimeError(f"boom: {user_id}")


def test_fetch_current_user_profile_enriches_guest_identity():
    info = auth._fetch_current_user_profile(_GuestOnlyClient())

    assert info["user_id"] == "u-1"
    assert info["guest"] is True
    assert info["basic_info"]["user_id"] == "u-1"
    assert info["basic_info"]["nickname"] == "Alice"


def test_fetch_current_user_profile_falls_back_when_detail_lookup_fails():
    info = auth._fetch_current_user_profile(_BrokenDetailClient())

    assert info == {"user_id": "u-2", "guest": True}


def test_xhs_user_payload_reads_nested_basic_info():
    payload = auth._xhs_user_payload(
        {
            "user_id": "u-1",
            "basic_info": {
                "nickname": "Alice",
                "red_id": "alice001",
                "ip_location": "上海",
                "desc": "hello",
            },
        }
    )

    assert payload == {
        "id": "u-1",
        "name": "Alice",
        "username": "alice001",
        "nickname": "Alice",
        "red_id": "alice001",
        "ip_location": "上海",
        "desc": "hello",
    }
