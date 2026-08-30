from __future__ import annotations

import asyncio

import pytest

from jooan_discovery.probes import describe_rtsp_path, eseecloud_paths, probe_rtsp_service

pytestmark = pytest.mark.usefixtures("socket_enabled")


def test_eseecloud_path_enumeration() -> None:
    paths = eseecloud_paths(8)
    assert len(paths) == 16
    assert paths[0] == ("ch0_0.264", 0, "main")
    assert paths[1] == ("ch0_1.264", 0, "sub")
    assert paths[-1] == ("ch7_1.264", 7, "sub")


async def test_rtsp_options_and_sdp_detection() -> None:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        request = await reader.read(8192)
        if request.startswith(b"OPTIONS"):
            response = (
                b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: MockNVR\r\n"
                b"Public: OPTIONS, DESCRIBE\r\nContent-Length: 0\r\n\r\n"
            )
        else:
            body = (
                b"v=0\r\nm=video 0 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n"
                b"a=framesize:96 2304-1296\r\na=framerate:15\r\n"
                b"m=audio 0 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n"
            )
            response = (
                b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nContent-Type: application/sdp\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\n\r\n"
                + body
            )
        writer.write(response)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        options = await probe_rtsp_service("127.0.0.1", port, timeout=0.2)
        stream = await describe_rtsp_path(
            "127.0.0.1", port, "ch0_0.264", channel=0, stream="main", timeout=0.2
        )
    assert options.confirmed
    assert options.server == "MockNVR"
    assert "DESCRIBE" in options.methods
    assert stream.confirmed
    assert stream.codec == "H264"
    assert stream.audio_codec == "PCMA"
    assert stream.resolution == "2304x1296"
    assert stream.frame_rate == 15


async def test_rtsp_authentication_requirement_is_detected() -> None:
    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await reader.read(8192)
        writer.write(
            b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\n"
            b'WWW-Authenticate: Digest realm="NVR", nonce="abc"\r\n\r\n'
        )
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        result = await describe_rtsp_path("127.0.0.1", port, "ch0_0.264", timeout=0.2)
    assert result.status == 401
    assert result.auth_type == "digest"
    assert not result.confirmed
