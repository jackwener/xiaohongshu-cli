"""Codec for Xiaohongshu's short-link direct-message transport.

A direct message can be delivered over plain HTTP instead of the IM WebSocket:
the payload is a protobuf ``ChatSendMessage`` envelope, RSA-encrypted and POSTed
to ``/api/im/web/short_link/send_message``.  No WebSocket handshake is involved,
which is why this CLI uses that route.

Implemented from published specifications:

* protobuf wire format — varints and length-delimited fields
  (https://protobuf.dev/programming-guides/encoding/)
* RSAES-PKCS1-v1_5 — RFC 8017 §7.2.1, applied by ``pycryptodome`` rather than
  by hand

The two inputs that cannot come from a specification are the server's public key
and the field numbers of the message.  Both are observable facts about the wire
format rather than program logic, and both are recorded below alongside the
layout they describe.

Note that this envelope emits its default-valued fields explicitly: an empty
``token`` / ``nickname`` / ``ref_id`` still occupies a tag with length 0, and
``group_chat`` is sent as an explicit ``0``.  Proto3 encoders normally omit
defaults; this transport does not, and acceptance depends on the exact byte
layout, so ``encode_chat_message`` reproduces it.
"""

from __future__ import annotations

from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA

# Server-side public key for the short-link sender (1024-bit).
_MODULUS = int(
    "d321555d67813eace010dc27e72ab14876a9b671c7d58d3c9c2064cd60f7e9f7"
    "9ad3799657b35a1b7654d82725408a71549d5ade11e74bbf1ec39b549ed32116"
    "affd4f6b03f2c9c44d91f84157b159a8a225150916e2716cc82dc8fd62385e5a"
    "01c83b784c139462a1dd45d47d96ebb4f5068c42b3de8590123a03565a9e5aed",
    16,
)
_EXPONENT = 65537
_PUBLIC_KEY = RSA.construct((_MODULUS, _EXPONENT))

# RFC 8017 §7.2.1: a PKCS#1 v1.5 block spends 11 bytes on the header and the
# minimum padding, so a k-byte key carries at most k-11 bytes of plaintext.
_CHUNK_BYTES = _PUBLIC_KEY.size_in_bytes() - 11

# ``ChatSendMessage`` field numbers.  Field 10 (a command sub-message) exists in
# the format but is unused for plain text, so it is never emitted.
_MID = 1
_TIMESTAMP = 2
_TOKEN = 3
_SENDER = 4
_RECEIVER = 5
_CONTENT = 6
_CONTENT_TYPE = 7
_NICKNAME = 8
_GROUP_CHAT = 9
_REF_ID = 11
_TRIGGER_SOURCE = 12

# Outer envelope: a discriminator followed by the message itself.
_ENVELOPE_KIND = 1
_ENVELOPE_BODY = 9
_ENVELOPE_KIND_SEND = 1

_WIRE_VARINT = 0
_WIRE_LENGTH_DELIMITED = 2

# Values the web client always sends for a plain text message.
_TRIGGER_SOURCE_DEFAULT = 1
CONTENT_TYPE_TEXT = 1


def _varint(value: int) -> bytes:
    """Encode a non-negative integer as a protobuf base-128 varint."""
    if value < 0:
        raise ValueError(f"varint cannot encode a negative value: {value}")
    chunks = bytearray()
    remaining = value
    while True:
        seven_bits = remaining & 0x7F
        remaining >>= 7
        chunks.append(seven_bits | (0x80 if remaining else 0x00))
        if not remaining:
            return bytes(chunks)


def _tag(field_number: int, wire_type: int) -> bytes:
    return _varint((field_number << 3) | wire_type)


def _varint_field(field_number: int, value: int) -> bytes:
    return _tag(field_number, _WIRE_VARINT) + _varint(value)


def _bytes_field(field_number: int, raw: bytes) -> bytes:
    return _tag(field_number, _WIRE_LENGTH_DELIMITED) + _varint(len(raw)) + raw


def _text_field(field_number: int, value: str) -> bytes:
    return _bytes_field(field_number, value.encode("utf-8"))


def encode_chat_message(
    *,
    local_mid: str,
    timestamp_ms: int,
    sender_id: str,
    receiver_id: str,
    content: str,
    content_type: int = CONTENT_TYPE_TEXT,
) -> bytes:
    """Build the protobuf payload for one outgoing direct message.

    ``local_mid`` is a client-generated tracking id.  The server issues its own
    message id in the response, and that is the only delivery proof.
    """
    body = b"".join((
        _text_field(_MID, local_mid),
        _varint_field(_TIMESTAMP, timestamp_ms),
        _text_field(_TOKEN, ""),
        _text_field(_SENDER, sender_id),
        _text_field(_RECEIVER, receiver_id),
        _text_field(_CONTENT, content),
        _varint_field(_CONTENT_TYPE, content_type),
        _text_field(_NICKNAME, ""),
        _varint_field(_GROUP_CHAT, 0),
        _text_field(_REF_ID, ""),
        _varint_field(_TRIGGER_SOURCE, _TRIGGER_SOURCE_DEFAULT),
    ))
    return (
        _varint_field(_ENVELOPE_KIND, _ENVELOPE_KIND_SEND)
        + _bytes_field(_ENVELOPE_BODY, body)
    )


def encrypt_payload(payload: bytes) -> bytes:
    """RSA-encrypt the payload in key-sized blocks.

    PKCS#1 v1.5 caps one block below the key size, so a longer payload is split
    and the ciphertext blocks are concatenated, matching the web client.
    """
    cipher = PKCS1_v1_5.new(_PUBLIC_KEY)
    return b"".join(
        cipher.encrypt(payload[offset:offset + _CHUNK_BYTES])
        for offset in range(0, len(payload), _CHUNK_BYTES)
    )
