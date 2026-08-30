from __future__ import annotations

import asyncio
import base64
import json

import pytest

from jooan_discovery.netsdk import investigate_netsdk
from jooan_discovery.probes import http_get_json
from jooan_discovery.security import Credentials

pytestmark = pytest.mark.usefixtures("socket_enabled")


async def _api_server() -> tuple[asyncio.AbstractServer, int]:
    expected = b"Basic " + base64.b64encode(b"admin:camera-password")

    async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        request = await reader.read(65536)
        request_line = request.split(b"\r\n", 1)[0]
        if b"Authorization: " + expected not in request:
            response = (
                b'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm="nginx"\r\n'
                b"Content-Length: 0\r\nConnection: close\r\n\r\n"
            )
        else:
            if b"/netsdk/Stat/DeviceInfo" in request_line:
                data = {"Model": "Mock NVR", "MAX_CHN": 8, "CloudID": "sensitive-cloud-id"}
            elif b"/netsdk/Channel " in request_line:
                data = [{"Channel": index} for index in range(8)]
            else:
                data = []
            body = json.dumps(data).encode()
            response = (
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                + str(len(body)).encode()
                + b"\r\nConnection: close\r\n\r\n"
                + body
            )
        writer.write(response)
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    return server, server.sockets[0].getsockname()[1]


async def test_netsdk_authentication_required() -> None:
    server, port = await _api_server()
    async with server:
        result = await investigate_netsdk("127.0.0.1", port, timeout=0.2)
    assert result.auth_required
    assert result.auth_type == "basic"
    assert not result.authenticated


async def test_netsdk_channel_enumeration_and_redaction() -> None:
    server, port = await _api_server()
    async with server:
        result = await investigate_netsdk(
            "127.0.0.1",
            port,
            credentials=Credentials("admin", "camera-password"),
            timeout=0.2,
        )
    assert result.authenticated
    assert result.channel_count == 8
    assert len(result.results["channels"]) == 8
    assert result.results["device_information"]["CloudID"] == "***"
    assert "camera-password" not in repr(result)


async def test_http_connection_failure_is_reported() -> None:
    status, headers, data, error = await http_get_json("127.0.0.1", 1, "/nope", timeout=0.05)
    assert status is None
    assert headers == {}
    assert data is None
    assert error
