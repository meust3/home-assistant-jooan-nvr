from __future__ import annotations

import asyncio
import struct
from unittest.mock import MagicMock, patch

import pytest
from aiohttp import WSMsgType
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from custom_components.jooan_nvr.kp2p import (
    AUTH_FIELD_CIPHER_KEY,
    API_MAGIC,
    FRAME_MAGIC,
    IOT_DATA_PRIOR,
    Kp2pError,
    Kp2pLiveStream,
    _api_packet,
    _auth_payload,
    _iot_packet,
    _parse_video_frame,
    _Session,
)


class _Message:
    type = WSMsgType.BINARY

    def __init__(self, data: bytes) -> None:
        self.data = data


class _WebSocket:
    def __init__(self, messages: list[bytes]) -> None:
        self.messages = iter(messages)

    async def receive(self):  # type: ignore[no-untyped-def]
        return _Message(next(self.messages))


class _HangingCloseWebSocket:
    async def close(self) -> None:
        await asyncio.Event().wait()


class _HangingProtocol:
    async def send_api(self, command: int, payload: bytes) -> None:
        del command, payload
        await asyncio.Event().wait()


def test_ha_kp2p_encryption_matches_recorder_algorithm() -> None:
    payload = _auth_payload("admin", "")
    decryptor = Cipher(algorithms.AES(AUTH_FIELD_CIPHER_KEY), modes.ECB()).decryptor()
    decrypted = decryptor.update(payload) + decryptor.finalize()
    assert decrypted[:32].rstrip(b"\0") == b"admin"
    assert decrypted[32:] == b"\0" * 32


def test_ha_kp2p_extracts_annex_b_video() -> None:
    p2p_header = struct.pack("<IIIIQ", FRAME_MAGIC, 1, 0, 2, 0)
    live_header = struct.pack("<II", 1, 4)
    parameters = b"H265\0\0\0\0" + struct.pack("<IIII", 15, 2304, 1296, 0) + b"\0" * 8
    media = b"\0\0\0\x01\x40\x01video"

    frame = _parse_video_frame(p2p_header + live_header + parameters + media)

    assert frame is not None
    assert frame.channel == 4
    assert frame.codec == "H265"
    assert (frame.width, frame.height) == (2304, 1296)
    assert frame.data == media


def test_priority_packet_carries_authentication_response() -> None:
    api = _api_packet(11, 1, b"")
    websocket = _WebSocket([_iot_packet(IOT_DATA_PRIOR, 42, api)])
    session = _Session(websocket, sid=42, timeout=1)  # type: ignore[arg-type]

    kind, value = asyncio.run(session.receive_api_or_frame())

    assert kind == "api"
    assert value == (11, 0, b"")
    assert struct.unpack_from("<I", api)[0] == API_MAGIC


@pytest.mark.asyncio
async def test_stream_close_is_bounded_and_cancels_keepalive() -> None:
    stream = Kp2pLiveStream(MagicMock(), "192.168.77.10", 10000, "admin", "", 0, 1)
    keepalive = asyncio.create_task(asyncio.Event().wait())
    stream._keepalive_task = keepalive  # noqa: SLF001
    stream._session = _HangingProtocol()  # type: ignore[assignment]  # noqa: SLF001
    stream._websocket = _HangingCloseWebSocket()  # type: ignore[assignment]  # noqa: SLF001

    with patch("custom_components.jooan_nvr.kp2p.CLOSE_TIMEOUT", 0.01):
        await asyncio.wait_for(stream.async_close(), timeout=0.2)

    assert keepalive.cancelled()
    assert stream._session is None  # noqa: SLF001
    assert stream._websocket is None  # noqa: SLF001


@pytest.mark.asyncio
async def test_websocket_error_without_exception_is_protocol_error() -> None:
    websocket = MagicMock()
    websocket.receive = MagicMock(
        return_value=asyncio.Future()
    )  # replaced below with an awaitable result
    message = _Message(b"")
    message.type = WSMsgType.ERROR
    websocket.receive.return_value.set_result(message)
    websocket.exception.return_value = None
    session = _Session(websocket, sid=1, timeout=0.1)

    with pytest.raises(Kp2pError, match="WebSocket error"):
        await session.receive_iot()
