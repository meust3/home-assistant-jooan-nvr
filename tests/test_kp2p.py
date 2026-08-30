from __future__ import annotations

import asyncio
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from jooan_discovery.kp2p import (
    API_MAGIC,
    AUTH_FIELD_CIPHER_KEY,
    FRAME_MAGIC,
    IOT_DATA_PRIOR,
    IOT_MAGIC,
    _api_packet,
    _auth_payload,
    _iot_packet,
    _parse_api,
    _parse_frame,
    _Session,
)
from jooan_discovery.security import Credentials


class _FakeWebSocket:
    def __init__(self, messages: list[bytes]) -> None:
        self.messages = iter(messages)

    async def recv(self) -> bytes:
        return next(self.messages)


def test_kp2p_packet_headers_round_trip() -> None:
    api = _api_packet(30, 7, b"payload")
    assert struct.unpack_from("<I", api)[0] == API_MAGIC
    assert _parse_api(api) == (30, 0, b"payload")
    iot = _iot_packet(19, 42, api)
    assert iot.startswith(IOT_MAGIC)
    assert struct.unpack_from("<I", iot, 16)[0] == 42
    assert struct.unpack_from("<I", iot, 28)[0] == len(api)


def test_kp2p_credential_encryption_matches_device_algorithm() -> None:
    credentials = Credentials("admin", "camera-password")
    payload = _auth_payload(credentials)
    assert len(payload) == 64
    assert b"admin" not in payload
    assert b"camera-password" not in payload
    decryptor = Cipher(algorithms.AES(AUTH_FIELD_CIPHER_KEY), modes.ECB()).decryptor()
    decrypted = decryptor.update(payload) + decryptor.finalize()
    assert decrypted[:32].rstrip(b"\0") == b"admin"
    assert decrypted[32:].rstrip(b"\0") == b"camera-password"


def test_parse_kp2p_video_frame_metadata() -> None:
    p2p_header = struct.pack("<IIIIQ", FRAME_MAGIC, 1, 0, 3, 0)
    live_header = struct.pack("<II", 1, 4)
    video_parameters = b"H265\0\0\0\0" + struct.pack("<IIII", 15, 2304, 1296, 0)
    frame = _parse_frame(p2p_header + live_header + video_parameters + b"\0" * 8 + b"abc")
    assert frame is not None
    assert frame.channel == 4
    assert frame.codec == "H265"
    assert frame.frame_rate == 15
    assert (frame.width, frame.height) == (2304, 1296)
    assert frame.data_size == 3


def test_priority_iot_data_can_carry_api_response() -> None:
    api = _api_packet(11, 1, b"")
    message = _iot_packet(IOT_DATA_PRIOR, 42, api)
    session = _Session(_FakeWebSocket([message]), sid=42, timeout=1)

    kind, value = asyncio.run(session.receive_api_or_frame(1))

    assert kind == "api"
    assert value == (11, 0, b"")
