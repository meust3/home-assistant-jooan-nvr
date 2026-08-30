"""Bounded local KP2P WebSocket stream validation for the proven NVR protocol."""

from __future__ import annotations

import asyncio
import secrets
import struct
import time
from dataclasses import dataclass
from typing import Any

import websockets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from websockets.exceptions import WebSocketException

from .models import Kp2pEvidence, Kp2pStreamEvidence
from .security import Credentials

ARQ_OPEN = bytes.fromhex("d9ffcc028c38eed2d199ac6026947fae")
ARQ_OPEN_RESPONSE = bytes.fromhex("96d5390d12fcbe8f4790d932ccd849f3")
ARQ_DATA = bytes.fromhex("cefaeffe")
IOT_MAGIC = bytes.fromhex("abbccdde")
API_MAGIC = 0x4B503250
FRAME_MAGIC = 0x4652414D
FRAME_MAGIC2 = 0x4652414E
# Fixed wire-format compatibility constant, not a device/account credential. The
# recorder still authenticates the user-supplied local username and password.
AUTH_FIELD_CIPHER_KEY = b"~!JUAN*&Vision-="

IOT_OPEN_REQ = 20
IOT_OPEN_RES = 21
IOT_DATA = 19
IOT_DATA_PRIOR = 43
API_AUTH_REQ = 10
API_AUTH_RSP = 11
API_LIVE_REQ = 30
API_LIVE_RSP = 31
LIVE_STOP = 1
LIVE_START = 2


class Kp2pError(Exception):
    """Local KP2P protocol failure."""


class Kp2pAuthenticationError(Kp2pError):
    """Credentials were rejected by the recorder."""


@dataclass(slots=True)
class _Frame:
    channel: int
    frame_type: int
    codec: str | None
    frame_rate: float | None
    width: int | None
    height: int | None
    data_size: int
    audio_codec: str | None = None


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _i32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<i", data, offset)[0]


def _iot_packet(command: int, sid: int, payload: bytes, *, error_code: int = 0) -> bytes:
    header = bytearray(32)
    header[0:4] = IOT_MAGIC
    struct.pack_into("<I", header, 4, command)
    header[8:12] = b"\x00\x00\x00\x01"
    struct.pack_into("<I", header, 16, sid)
    struct.pack_into("<i", header, 24, error_code)
    struct.pack_into("<I", header, 28, len(payload))
    return bytes(header) + payload


def _api_packet(command: int, ticket: int, payload: bytes, *, result: int = 0) -> bytes:
    return struct.pack("<IIIIiI", API_MAGIC, 1, ticket, command, result, len(payload)) + payload


def _encrypt_field(value: str) -> bytes:
    encoded = value.encode("utf-8")
    if len(encoded) >= 32:
        raise ValueError("KP2P credentials must be shorter than 32 UTF-8 bytes")
    padded = encoded.ljust(32, b"\0")
    encryptor = Cipher(algorithms.AES(AUTH_FIELD_CIPHER_KEY), modes.ECB()).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def _auth_payload(credentials: Credentials) -> bytes:
    return _encrypt_field(credentials.username) + _encrypt_field(credentials.password)


def _live_payload(channel: int, stream_id: int, command: int) -> bytes:
    return struct.pack("<III", channel, stream_id, command)


def _parse_api(data: bytes) -> tuple[int, int, bytes]:
    if len(data) < 24 or _u32(data, 0) != API_MAGIC:
        raise Kp2pError("invalid KP2P API packet")
    command = _u32(data, 12)
    result = _i32(data, 16)
    size = _u32(data, 20)
    if size > len(data) - 24:
        raise Kp2pError("truncated KP2P API payload")
    return command, result, data[24 : 24 + size]


def _ascii_field(data: bytes) -> str | None:
    value = data.split(b"\0", 1)[0].decode("ascii", errors="replace").strip()
    return value or None


def _parse_frame(data: bytes) -> _Frame | None:
    if len(data) < 32:
        return None
    offset = 0
    magic = _u32(data, offset)
    if magic == FRAME_MAGIC2:
        if len(data) < 72:
            return None
        offset += 40
        magic = _u32(data, offset)
    if magic != FRAME_MAGIC or len(data) < offset + 32:
        return None
    head_type = _u32(data, offset + 8)
    if head_type != 0:  # live frames only
        return None
    offset += 24
    frame_type = _u32(data, offset)
    channel = _u32(data, offset + 4)
    offset += 8
    if len(data) < offset + 24:
        return None
    codec = _ascii_field(data[offset : offset + 8])
    if frame_type == 0:
        sample_rate = _u32(data, offset + 8)
        sample_width = _u32(data, offset + 12)
        channels = _u32(data, offset + 16)
        payload_offset = offset + 32
        return _Frame(
            channel=channel,
            frame_type=frame_type,
            codec=None,
            frame_rate=None,
            width=sample_rate,
            height=sample_width,
            data_size=max(len(data) - payload_offset, 0),
            audio_codec=f"{codec or 'audio'}/{sample_rate}/{sample_width}/{channels}",
        )
    if frame_type not in {1, 2}:
        return None
    frame_rate = _u32(data, offset + 8)
    width = _u32(data, offset + 12)
    height = _u32(data, offset + 16)
    payload_offset = offset + 32
    return _Frame(
        channel=channel,
        frame_type=frame_type,
        codec=codec,
        frame_rate=float(frame_rate) if frame_rate else None,
        width=width or None,
        height=height or None,
        data_size=max(len(data) - payload_offset, 0),
    )


class _Session:
    def __init__(self, websocket: Any, sid: int, timeout: float) -> None:
        self.websocket = websocket
        self.sid = sid
        self.timeout = timeout
        self.ticket = 0

    async def send_iot(self, command: int, payload: bytes) -> None:
        packet = _iot_packet(command, self.sid, payload)
        await self.websocket.send(ARQ_DATA + struct.pack("<I", len(packet)))
        await self.websocket.send(packet)

    async def send_api(self, command: int, payload: bytes) -> None:
        self.ticket += 1
        await self.send_iot(IOT_DATA, _api_packet(command, self.ticket, payload))

    async def receive_iot(self, timeout: float | None = None) -> tuple[int, int, bytes]:
        deadline = asyncio.get_running_loop().time() + (timeout or self.timeout)
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError("timed out waiting for KP2P data")
            message = await asyncio.wait_for(self.websocket.recv(), remaining)
            if isinstance(message, str):
                continue
            data = bytes(message)
            if data.startswith(ARQ_DATA):
                continue
            if len(data) < 32 or not data.startswith(IOT_MAGIC):
                continue
            command = _u32(data, 4)
            error_code = _i32(data, 24)
            size = _u32(data, 28)
            if size > len(data) - 32:
                raise Kp2pError("truncated IOT payload")
            return command, error_code, data[32 : 32 + size]

    async def receive_api_or_frame(self, timeout: float) -> tuple[str, Any]:
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise TimeoutError("timed out waiting for KP2P API/frame data")
            command, error_code, payload = await self.receive_iot(remaining)
            # The recorder's own browser client accepts both ordinary and
            # priority data packets here.  Authentication replies from some
            # firmware builds arrive as priority data even though requests
            # are sent as ordinary data.
            if command not in {IOT_DATA, IOT_DATA_PRIOR}:
                continue
            if error_code:
                raise Kp2pError(f"IOT error {error_code}")
            if len(payload) >= 4 and _u32(payload, 0) == API_MAGIC:
                return "api", _parse_api(payload)
            frame = _parse_frame(payload)
            if frame:
                return "frame", frame

    async def authenticate(self, credentials: Credentials) -> None:
        await self.send_api(API_AUTH_REQ, _auth_payload(credentials))
        while True:
            kind, value = await self.receive_api_or_frame(self.timeout)
            if kind != "api":
                continue
            command, result, _ = value
            if command != API_AUTH_RSP:
                continue
            if result != 0:
                raise Kp2pAuthenticationError(f"KP2P authentication failed ({result})")
            return

    async def validate_stream(
        self,
        channel: int,
        stream_id: int,
        *,
        sample_seconds: float,
    ) -> Kp2pStreamEvidence:
        result = Kp2pStreamEvidence(
            channel=channel,
            stream_id=stream_id,
            stream="main" if stream_id == 0 else "sub",
        )
        started = time.perf_counter()
        opened = False
        try:
            await self.send_api(API_LIVE_REQ, _live_payload(channel, stream_id, LIVE_START))
            while True:
                kind, value = await self.receive_api_or_frame(self.timeout)
                if kind != "api":
                    continue
                command, open_result, payload = value
                if command != API_LIVE_RSP or len(payload) < 12:
                    continue
                response_channel, response_stream, live_command = struct.unpack_from(
                    "<III", payload
                )
                if (
                    response_channel == channel
                    and response_stream == stream_id
                    and live_command == LIVE_START
                ):
                    result.open_result = open_result
                    if open_result != 0:
                        result.error = f"open stream failed ({open_result})"
                        return result
                    opened = True
                    break

            sampling_started = time.perf_counter()
            video_bytes = 0
            first_video: float | None = None
            while time.perf_counter() - sampling_started < sample_seconds:
                remaining = sample_seconds - (time.perf_counter() - sampling_started)
                try:
                    kind, value = await self.receive_api_or_frame(max(remaining, 0.1))
                except TimeoutError:
                    break
                if kind != "frame" or value.channel != channel:
                    continue
                frame: _Frame = value
                if frame.frame_type == 0:
                    result.audio_frames += 1
                    result.audio_codec = result.audio_codec or frame.audio_codec
                    continue
                if first_video is None:
                    first_video = time.perf_counter()
                    result.startup_latency_ms = round((first_video - started) * 1000)
                result.video_frames += 1
                video_bytes += frame.data_size
                result.codec = result.codec or frame.codec
                result.frame_rate = result.frame_rate or frame.frame_rate
                if frame.width and frame.height:
                    result.resolution = result.resolution or f"{frame.width}x{frame.height}"
            elapsed = time.perf_counter() - sampling_started
            if result.video_frames:
                result.confirmed = True
                result.bitrate = round(video_bytes * 8 / elapsed) if elapsed > 0 else None
            else:
                result.error = "stream opened but no video frame arrived"
        except (Kp2pError, TimeoutError, OSError) as err:
            result.error = f"{type(err).__name__}: {err}"
        finally:
            if opened:
                await self._close_stream(channel, stream_id)
        return result

    async def _close_stream(self, channel: int, stream_id: int) -> None:
        try:
            await self.send_api(API_LIVE_REQ, _live_payload(channel, stream_id, LIVE_STOP))
            deadline = asyncio.get_running_loop().time() + 1.0
            while asyncio.get_running_loop().time() < deadline:
                kind, value = await self.receive_api_or_frame(
                    deadline - asyncio.get_running_loop().time()
                )
                if kind != "api":
                    continue
                command, _, payload = value
                if command == API_LIVE_RSP and len(payload) >= 12:
                    response_channel, response_stream, live_command = struct.unpack_from(
                        "<III", payload
                    )
                    if (response_channel, response_stream, live_command) == (
                        channel,
                        stream_id,
                        LIVE_STOP,
                    ):
                        return
        except Kp2pError, TimeoutError, OSError:
            return


async def validate_kp2p_streams(
    address: str,
    port: int,
    credentials: Credentials,
    channels: list[int],
    *,
    stream_ids: tuple[int, ...] = (0, 1),
    timeout: float = 5.0,
    sample_seconds: float = 1.5,
) -> Kp2pEvidence:
    """Authenticate once, briefly sample bounded streams, and close every opened stream."""
    evidence = Kp2pEvidence(endpoint=f"ws://{address}:{port}")
    sid = secrets.randbelow(9999) + 1
    try:
        async with websockets.connect(
            evidence.endpoint,
            open_timeout=timeout,
            close_timeout=1,
            ping_interval=None,
            max_size=8 * 1024 * 1024,
            proxy=None,
        ) as websocket:
            await websocket.send(ARQ_OPEN + struct.pack("<I", sid))
            response = await asyncio.wait_for(websocket.recv(), timeout)
            if isinstance(response, str) or bytes(response) != ARQ_OPEN_RESPONSE:
                raise Kp2pError("ARQ connection handshake was rejected")
            session = _Session(websocket, sid, timeout)
            await session.send_iot(IOT_OPEN_REQ, struct.pack("<II", sid, 0))
            while True:
                command, error_code, _ = await session.receive_iot(timeout)
                if command != IOT_OPEN_RES:
                    continue
                if error_code:
                    raise Kp2pError(f"IOT open failed ({error_code})")
                break
            await session.authenticate(credentials)
            evidence.authenticated = True
            for channel in channels:
                for stream_id in stream_ids:
                    evidence.streams.append(
                        await session.validate_stream(
                            channel,
                            stream_id,
                            sample_seconds=sample_seconds,
                        )
                    )
    except Kp2pAuthenticationError as err:
        evidence.errors.append(str(err))
    except (Kp2pError, TimeoutError, OSError, WebSocketException) as err:
        evidence.errors.append(f"{type(err).__name__}: {err}")
    return evidence
