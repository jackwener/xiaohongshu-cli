"""Short-link direct-message codec (no network).

The wire layout is pinned by a byte-exact regression fixture: the server accepts
or rejects a message on its exact byte layout, so a refactor that changes the
encoding must fail loudly here rather than at send time.
"""

from __future__ import annotations

import pytest

from xhs_cli.im_codec import (
    _CHUNK_BYTES,
    _MODULUS,
    CONTENT_TYPE_TEXT,
    _varint,
    encode_chat_message,
    encrypt_payload,
)

# Captured from a message the server accepted; regenerating it must be
# deterministic and byte-identical.
FIXTURE_ARGS = {
    "local_mid": "11111111-2222-3333-4444-555555555555",
    "timestamp_ms": 1789000000000,
    "sender_id": "a" * 24,
    "receiver_id": "b" * 24,
    "content": "test",
}
FIXTURE_HEX = (
    "08014a730a2431313131313131312d323232322d333333332d343434342d353535"
    "3535353535353535351080c4d6c588341a00221861616161616161616161616161"
    "61616161616161616161612a186262626262626262626262626262626262626262"
    "626262623204746573743801420048005a006001"
)


class TestVarint:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (0, b"\x00"),
            (1, b"\x01"),
            (127, b"\x7f"),
            (128, b"\x80\x01"),
            (300, b"\xac\x02"),
            (1789000000000, b"\x80\xc4\xd6\xc5\x88\x34"),
        ],
    )
    def test_known_encodings(self, value, expected):
        assert _varint(value) == expected

    def test_rejects_negative(self):
        with pytest.raises(ValueError, match="negative"):
            _varint(-1)


class TestEncodeChatMessage:
    def test_matches_accepted_byte_layout(self):
        assert encode_chat_message(**FIXTURE_ARGS).hex() == FIXTURE_HEX

    def test_is_deterministic(self):
        assert encode_chat_message(**FIXTURE_ARGS) == encode_chat_message(**FIXTURE_ARGS)

    def test_default_valued_fields_are_emitted_not_omitted(self):
        """本传输不省略默认值；省略会改变字节布局，服务端会拒。"""
        payload = encode_chat_message(**FIXTURE_ARGS)
        assert b"\x1a\x00" in payload, "empty token (field 3) must occupy a tag"
        assert b"\x42\x00" in payload, "empty nickname (field 8) must occupy a tag"
        assert b"\x48\x00" in payload, "group_chat=0 (field 9) must be explicit"
        assert b"\x5a\x00" in payload, "empty ref_id (field 11) must occupy a tag"

    def test_command_field_10_is_never_emitted(self):
        payload = encode_chat_message(**FIXTURE_ARGS)
        assert b"\x52" not in payload, "field 10 has no meaning for plain text"

    def test_carries_participants_and_content(self):
        payload = encode_chat_message(**{**FIXTURE_ARGS, "content": "hello 世界"})
        assert b"a" * 24 in payload
        assert b"b" * 24 in payload
        assert "hello 世界".encode() in payload

    def test_multibyte_content_uses_utf8_length(self):
        payload = encode_chat_message(**{**FIXTURE_ARGS, "content": "世界"})
        # 2 chars -> 6 UTF-8 bytes; field 6 tag is 0x32.
        assert b"\x32\x06" + "世界".encode() in payload


class TestEncryptPayload:
    def test_key_is_1024_bit(self):
        assert _MODULUS.bit_length() == 1024
        assert _CHUNK_BYTES == 117

    @pytest.mark.parametrize(
        ("size", "blocks"),
        [(1, 1), (_CHUNK_BYTES, 1), (_CHUNK_BYTES + 1, 2), (_CHUNK_BYTES * 2, 2)],
    )
    def test_output_is_block_aligned(self, size, blocks):
        out = encrypt_payload(b"x" * size)
        assert len(out) == blocks * 128

    def test_padding_is_randomized(self):
        payload = encode_chat_message(**FIXTURE_ARGS)
        assert encrypt_payload(payload) != encrypt_payload(payload)

    def test_real_payload_spans_two_blocks(self):
        assert len(encrypt_payload(encode_chat_message(**FIXTURE_ARGS))) == 256

    def test_empty_payload_produces_no_blocks(self):
        assert encrypt_payload(b"") == b""


def test_content_type_text_constant():
    assert CONTENT_TYPE_TEXT == 1
