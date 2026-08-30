"""Rate-limited ICMP, TCP, HTTP(S), and RTSP probes."""

from __future__ import annotations

import asyncio
import hashlib
import html
import json
import os
import platform
import re
import socket
import ssl
import time
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from contextlib import suppress
from typing import Any
from urllib.parse import urlsplit

from .models import HttpEvidence, RtspEvidence, ServiceEvidence
from .security import Credentials, redact_url

DEFAULT_PORTS = (80, 81, 443, 554, 8000, 8080, 8081, 8899, 9000, 34567)
HTTP_PORTS = {80, 81, 443, 8000, 8080, 8081, 8899, 9000, 34567}
_TITLE_RE = re.compile(r"(?is)<title[^>]*>(.*?)</title>")
_SCRIPT_RE = re.compile(r"""(?is)<script[^>]+src=["']([^"']+)["']""")
_STATUS_RE = re.compile(r"^(?:HTTP/\d(?:\.\d)?|RTSP/\d(?:\.\d)?)\s+(\d{3})")
_AUTH_PARAM_RE = re.compile(r'(\w+)=(?:"([^"]*)"|([^,\s]+))')


async def _close_writer(writer: asyncio.StreamWriter | None) -> None:
    if writer is None:
        return
    writer.close()
    with suppress(Exception):
        await writer.wait_closed()


async def tcp_connect(address: str, port: int, timeout: float) -> bool:
    writer: asyncio.StreamWriter | None = None
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(address, port), timeout)
        return True
    except TimeoutError, OSError:
        return False
    finally:
        await _close_writer(writer)


async def scan_tcp_ports(
    addresses: Iterable[str],
    ports: Iterable[int] = DEFAULT_PORTS,
    *,
    timeout: float = 0.45,
    concurrency: int = 128,
) -> dict[str, list[ServiceEvidence]]:
    semaphore = asyncio.Semaphore(concurrency)
    results: dict[str, list[ServiceEvidence]] = {}

    async def probe(address: str, port: int) -> None:
        async with semaphore:
            if await tcp_connect(address, port, timeout):
                results.setdefault(address, []).append(ServiceEvidence(port=port))

    await asyncio.gather(*(probe(address, port) for address in addresses for port in ports))
    for services in results.values():
        services.sort(key=lambda item: item.port)
    return results


async def ping_host(address: str, timeout: float = 0.8) -> bool:
    system = platform.system()
    milliseconds = max(int(timeout * 1000), 100)
    if system == "Windows":
        args = ("ping", "-n", "1", "-w", str(milliseconds), address)
    elif system == "Darwin":
        args = ("ping", "-c", "1", "-W", str(milliseconds), address)
    else:
        args = ("ping", "-c", "1", "-W", str(max(1, int(timeout))), address)
    try:
        process = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
        )
        return await process.wait() == 0
    except FileNotFoundError, OSError:
        return False


async def ping_hosts(
    addresses: Iterable[str], *, timeout: float = 0.8, concurrency: int = 48
) -> set[str]:
    semaphore = asyncio.Semaphore(concurrency)
    responsive: set[str] = set()

    async def one(address: str) -> None:
        async with semaphore:
            if await ping_host(address, timeout):
                responsive.add(address)

    await asyncio.gather(*(one(address) for address in addresses))
    return responsive


async def reverse_hostname(address: str, timeout: float = 1.0) -> str | None:
    try:
        result = await asyncio.wait_for(asyncio.to_thread(socket.gethostbyaddr, address), timeout)
        return result[0].rstrip(".")
    except TimeoutError, OSError:
        return None


def _parse_response(payload: bytes) -> tuple[int | None, dict[str, str], bytes]:
    header, separator, body = payload.partition(b"\r\n\r\n")
    if not separator:
        header, _, body = payload.partition(b"\n\n")
    lines = header.decode("iso-8859-1", errors="replace").replace("\r\n", "\n").split("\n")
    status_match = _STATUS_RE.match(lines[0]) if lines else None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    return (int(status_match.group(1)) if status_match else None), headers, body


async def _raw_request(
    address: str,
    port: int,
    request: bytes,
    *,
    timeout: float,
    use_tls: bool = False,
    max_bytes: int = 131072,
) -> tuple[bytes, dict[str, Any] | None]:
    writer: asyncio.StreamWriter | None = None
    context: ssl.SSLContext | None = None
    if use_tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                address, port, ssl=context, server_hostname=address if use_tls else None
            ),
            timeout,
        )
        writer.write(request)
        await asyncio.wait_for(writer.drain(), timeout)
        chunks: list[bytes] = []
        size = 0
        expected_size: int | None = None
        while size < max_bytes:
            try:
                chunk = await asyncio.wait_for(reader.read(min(32768, max_bytes - size)), timeout)
            except TimeoutError:
                break
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            assembled = b"".join(chunks)
            if expected_size is None and b"\r\n\r\n" in assembled:
                header, _, _ = assembled.partition(b"\r\n\r\n")
                match = re.search(rb"(?im)^Content-Length:\s*(\d+)\s*$", header)
                if match:
                    expected_size = len(header) + 4 + int(match.group(1))
            if expected_size is not None and size >= expected_size:
                break
        tls: dict[str, Any] | None = None
        if use_tls:
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object:
                der = ssl_object.getpeercert(binary_form=True)
                tls = {
                    "version": ssl_object.version(),
                    "cipher": ssl_object.cipher()[0] if ssl_object.cipher() else None,
                    "certificate_sha256": hashlib.sha256(der).hexdigest() if der else None,
                }
        return b"".join(chunks), tls
    finally:
        await _close_writer(writer)


def _auth_type(header: str | None) -> str | None:
    if not header:
        return None
    return header.split(maxsplit=1)[0].strip().lower()


_WEB_INDICATORS = {
    "jooan": "JOOAN",
    "eseecloud": "EseeCloud",
    "eseelogin": "EseeLogin",
    "esee_login": "EseeLogin asset",
    "nvr163": "NVR163",
    "dvr163": "DVR163",
    "kp2p_js": "KP2P local web module",
    "netsdk": "Netsdk local API",
    "/cgi-bin/gw.cgi": "/cgi-bin/gw.cgi",
    "cgi-bin/flv.cgi": "/cgi-bin/flv.cgi",
}


def _find_web_indicators(content: bytes) -> list[str]:
    lowered = content.decode(errors="replace").lower()
    return [label for token, label in _WEB_INDICATORS.items() if token in lowered]


async def _probe_static_web_assets(
    address: str,
    port: int,
    body: bytes,
    *,
    timeout: float,
    use_tls: bool,
) -> list[str]:
    """Fingerprint a bounded set of same-device static scripts referenced by the landing page."""
    text = body.decode(errors="replace")
    indicators = set(_find_web_indicators(body))
    asset_paths: list[str] = []
    for source in _SCRIPT_RE.findall(text):
        parsed = urlsplit(source)
        if parsed.scheme or parsed.netloc:
            continue
        path = "/" + parsed.path.lstrip("./")
        if path not in asset_paths:
            asset_paths.append(path)
    total = 0
    for path in asset_paths[:6]:
        if total >= 2_000_000:
            break
        request = (
            f"GET {path} HTTP/1.1\r\nHost: {address}\r\n"
            "User-Agent: jooan-discovery/0.1\r\nConnection: close\r\n\r\n"
        ).encode()
        try:
            payload, _ = await _raw_request(
                address,
                port,
                request,
                timeout=timeout,
                use_tls=use_tls,
                max_bytes=min(1_100_000, 2_000_000 - total),
            )
        except TimeoutError, OSError, ssl.SSLError:
            continue
        asset_status, _, asset_body = _parse_response(payload)
        if asset_status == 200:
            total += len(asset_body)
            indicators.update(_find_web_indicators(asset_body))
    return sorted(indicators)


async def probe_http(address: str, port: int, timeout: float = 2.0) -> HttpEvidence:
    use_tls = port == 443
    scheme = "https" if use_tls else "http"
    url = f"{scheme}://{address}:{port}/"
    request = (
        f"GET / HTTP/1.1\r\nHost: {address}\r\nUser-Agent: jooan-discovery/0.1\r\n"
        "Accept: text/html,*/*;q=0.1\r\nConnection: close\r\n\r\n"
    ).encode()
    try:
        payload, tls = await _raw_request(address, port, request, timeout=timeout, use_tls=use_tls)
        status, headers, body = _parse_response(payload)
        text = body.decode(errors="replace")
        title_match = _TITLE_RE.search(text)
        title = None
        if title_match:
            title = " ".join(html.unescape(title_match.group(1)).split())[:300]
        evidence = HttpEvidence(
            url=url,
            status=status,
            server=headers.get("server"),
            title=title,
            auth_type=_auth_type(headers.get("www-authenticate")),
            content_type=headers.get("content-type"),
            tls=tls,
        )
        if status == 200 and "html" in headers.get("content-type", "").lower():
            evidence.indicators = await _probe_static_web_assets(
                address,
                port,
                body,
                timeout=timeout,
                use_tls=use_tls,
            )
            if evidence.indicators and any("login" in item.lower() for item in evidence.indicators):
                evidence.auth_type = evidence.auth_type or "application-form"
        if status is not None and status < 500:
            favicon_request = (
                f"GET /favicon.ico HTTP/1.1\r\nHost: {address}\r\n"
                "User-Agent: jooan-discovery/0.1\r\nConnection: close\r\n\r\n"
            ).encode()
            with suppress(TimeoutError, OSError, ssl.SSLError):
                favicon_payload, _ = await _raw_request(
                    address, port, favicon_request, timeout=timeout, use_tls=use_tls
                )
                favicon_status, _, favicon = _parse_response(favicon_payload)
                if favicon_status == 200 and favicon:
                    evidence.favicon_sha256 = hashlib.sha256(favicon).hexdigest()
        return evidence
    except (TimeoutError, OSError, ssl.SSLError) as err:
        return HttpEvidence(url=url, error=f"{type(err).__name__}: {err}")


async def probe_http_services(
    address: str, ports: Iterable[int], *, timeout: float = 2.0
) -> list[HttpEvidence]:
    return await asyncio.gather(
        *(probe_http(address, port, timeout) for port in ports if port in HTTP_PORTS)
    )


async def fetch_upnp_description(
    location: str, *, allowed_addresses: set[str], timeout: float = 2.0
) -> dict[str, str]:
    """Fetch UPnP metadata only when LOCATION resolves to an already allowed LAN address."""
    try:
        parsed = urlsplit(location)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return {"description_error": "unsupported LOCATION URL"}
        resolved = {
            item[4][0]
            for item in await asyncio.to_thread(socket.getaddrinfo, parsed.hostname, None)
            if item[0] == socket.AF_INET
        }
        if not resolved or not resolved.issubset(allowed_addresses):
            return {"description_error": "LOCATION host is outside scanned LAN addresses"}
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        request = (
            f"GET {path} HTTP/1.1\r\nHost: {parsed.hostname}\r\n"
            "User-Agent: jooan-discovery/0.1\r\nConnection: close\r\n\r\n"
        ).encode()
        payload, _ = await _raw_request(
            parsed.hostname, port, request, timeout=timeout, use_tls=parsed.scheme == "https"
        )
        status, _, body = _parse_response(payload)
        if status != 200:
            return {"description_error": f"HTTP {status}"}
        root = ET.fromstring(body)
        wanted = {
            "friendlyName",
            "manufacturer",
            "manufacturerURL",
            "modelDescription",
            "modelName",
            "modelNumber",
            "serialNumber",
            "deviceType",
        }
        details = {
            node.tag.rsplit("}", 1)[-1]: node.text.strip()
            for node in root.iter()
            if node.tag.rsplit("}", 1)[-1] in wanted and node.text
        }
        return details
    except (TimeoutError, OSError, ssl.SSLError, ValueError, ET.ParseError) as err:
        return {"description_error": f"{type(err).__name__}: {err}"}


def _parse_auth_challenge(value: str) -> tuple[str, dict[str, str]]:
    scheme, _, parameters = value.partition(" ")
    return scheme.lower(), {
        match.group(1).lower(): match.group(2) if match.group(2) is not None else match.group(3)
        for match in _AUTH_PARAM_RE.finditer(parameters)
    }


def _digest_authorization(
    challenge: str, credentials: Credentials, method: str, uri: str, nonce_count: int = 1
) -> str | None:
    scheme, params = _parse_auth_challenge(challenge)
    if scheme != "digest" or not params.get("realm") or not params.get("nonce"):
        return None
    algorithm = params.get("algorithm", "MD5").upper()
    if algorithm not in {"MD5", "MD5-SESS"}:
        return None

    def digest(value: str) -> str:
        # MD5 is required by the legacy RTSP Digest protocol, not used for storage.
        return hashlib.md5(value.encode()).hexdigest()  # noqa: S324

    cnonce = os.urandom(8).hex()
    ha1 = digest(f"{credentials.username}:{params['realm']}:{credentials.password}")
    if algorithm == "MD5-SESS":
        ha1 = digest(f"{ha1}:{params['nonce']}:{cnonce}")
    ha2 = digest(f"{method}:{uri}")
    qop_values = [item.strip() for item in params.get("qop", "").split(",")]
    qop = "auth" if "auth" in qop_values else None
    nc = f"{nonce_count:08x}"
    if qop:
        response = digest(f"{ha1}:{params['nonce']}:{nc}:{cnonce}:{qop}:{ha2}")
    else:
        response = digest(f"{ha1}:{params['nonce']}:{ha2}")
    fields = [
        f'username="{credentials.username}"',
        f'realm="{params["realm"]}"',
        f'nonce="{params["nonce"]}"',
        f'uri="{uri}"',
        f'response="{response}"',
        f"algorithm={algorithm}",
    ]
    if params.get("opaque"):
        fields.append(f'opaque="{params["opaque"]}"')
    if qop:
        fields.extend((f"qop={qop}", f"nc={nc}", f'cnonce="{cnonce}"'))
    return "Digest " + ", ".join(fields)


def _basic_authorization(credentials: Credentials) -> str:
    import base64

    token = base64.b64encode(f"{credentials.username}:{credentials.password}".encode()).decode()
    return f"Basic {token}"


async def rtsp_request(
    address: str,
    port: int,
    method: str,
    path: str,
    *,
    credentials: Credentials | None = None,
    timeout: float = 2.0,
) -> tuple[int | None, dict[str, str], bytes, int, str | None, bool]:
    normalized_path = path if path.startswith("/") else f"/{path}"
    uri = f"rtsp://{address}:{port}{normalized_path}"

    def request(authorization: str | None = None, cseq: int = 1) -> bytes:
        lines = [
            f"{method} {uri} RTSP/1.0",
            f"CSeq: {cseq}",
            "User-Agent: jooan-discovery/0.1",
            "Accept: application/sdp",
        ]
        if authorization:
            lines.append(f"Authorization: {authorization}")
        return ("\r\n".join(lines) + "\r\n\r\n").encode()

    started = time.perf_counter()
    payload, _ = await _raw_request(address, port, request(), timeout=timeout)
    status, headers, body = _parse_response(payload)
    is_rtsp = payload.lstrip().upper().startswith(b"RTSP/")
    auth_type = _auth_type(headers.get("www-authenticate"))
    if is_rtsp and status == 401 and credentials and headers.get("www-authenticate"):
        challenge = headers["www-authenticate"]
        scheme, _ = _parse_auth_challenge(challenge)
        authorization = (
            _digest_authorization(challenge, credentials, method, uri)
            if scheme == "digest"
            else _basic_authorization(credentials)
            if scheme == "basic"
            else None
        )
        if authorization:
            payload, _ = await _raw_request(
                address, port, request(authorization, cseq=2), timeout=timeout
            )
            status, headers, body = _parse_response(payload)
            is_rtsp = payload.lstrip().upper().startswith(b"RTSP/")
    latency = round((time.perf_counter() - started) * 1000)
    return status, headers, body, latency, auth_type, is_rtsp


def _parse_sdp(body: bytes) -> dict[str, Any]:
    text = body.decode(errors="replace")
    audio_codecs: list[str] = []
    video_codecs: list[str] = []
    result: dict[str, Any] = {}
    for line in text.replace("\r\n", "\n").split("\n"):
        if line.startswith("a=framesize:"):
            value = line.partition(" ")[2].replace("-", "x")
            if value:
                result["resolution"] = value
        elif line.startswith("a=framerate:"):
            with suppress(ValueError):
                result["frame_rate"] = float(line.partition(":")[2])
        elif "x-dimensions:" in line.lower():
            result["resolution"] = line.partition(":")[2].strip().replace(",", "x")
        elif line.startswith("b=AS:"):
            with suppress(ValueError):
                result["bitrate"] = int(line.partition(":")[2]) * 1000
    # rtpmap lines often follow m=, so classify once more by media sections.
    current_media: str | None = None
    for line in text.replace("\r\n", "\n").split("\n"):
        if line.startswith("m="):
            current_media = line[2:].split(maxsplit=1)[0]
        elif line.startswith("a=rtpmap:"):
            codec = line.partition(" ")[2].split("/", 1)[0]
            if current_media == "video" and codec:
                video_codecs.append(codec)
            elif current_media == "audio" and codec:
                audio_codecs.append(codec)
    if video_codecs:
        result["codec"] = video_codecs[0].upper()
    if audio_codecs:
        result["audio_codec"] = audio_codecs[0].upper()
    return result


async def probe_rtsp_service(
    address: str,
    port: int,
    *,
    credentials: Credentials | None = None,
    timeout: float = 2.0,
) -> RtspEvidence:
    try:
        status, headers, _, latency, auth_type, is_rtsp = await rtsp_request(
            address, port, "OPTIONS", "/", credentials=credentials, timeout=timeout
        )
        methods = [item.strip() for item in headers.get("public", "").split(",") if item.strip()]
        return RtspEvidence(
            port=port,
            path="/",
            status=status,
            server=headers.get("server"),
            auth_type=auth_type,
            methods=methods,
            startup_latency_ms=latency,
            confirmed=is_rtsp and status is not None,
            error=None if is_rtsp else "non-RTSP response",
        )
    except (TimeoutError, OSError, ssl.SSLError) as err:
        return RtspEvidence(port=port, path="/", status=None, error=f"{type(err).__name__}: {err}")


async def describe_rtsp_path(
    address: str,
    port: int,
    path: str,
    *,
    credentials: Credentials | None = None,
    channel: int | None = None,
    stream: str | None = None,
    timeout: float = 3.0,
) -> RtspEvidence:
    uri = f"rtsp://{address}:{port}/{path.lstrip('/')}"
    try:
        status, headers, body, latency, auth_type, is_rtsp = await rtsp_request(
            address, port, "DESCRIBE", path, credentials=credentials, timeout=timeout
        )
        metadata = _parse_sdp(body) if status == 200 else {}
        return RtspEvidence(
            port=port,
            path=f"/{path.lstrip('/')}",
            status=status,
            server=headers.get("server"),
            auth_type=auth_type,
            channel=channel,
            stream=stream,
            codec=metadata.get("codec"),
            resolution=metadata.get("resolution"),
            frame_rate=metadata.get("frame_rate"),
            bitrate=metadata.get("bitrate"),
            audio_codec=metadata.get("audio_codec"),
            startup_latency_ms=latency,
            uri=redact_url(uri),
            confirmed=is_rtsp and status == 200 and bool(body),
            error=None if is_rtsp else "non-RTSP response",
        )
    except (TimeoutError, OSError, ssl.SSLError) as err:
        return RtspEvidence(
            port=port,
            path=f"/{path.lstrip('/')}",
            status=None,
            channel=channel,
            stream=stream,
            uri=redact_url(uri),
            error=f"{type(err).__name__}: {err}",
        )


def eseecloud_paths(channel_count: int = 8) -> list[tuple[str, int, str]]:
    return [
        (f"ch{channel}_{quality}.264", channel, "main" if quality == 0 else "sub")
        for channel in range(channel_count)
        for quality in (0, 1)
    ]


async def http_get_json(
    address: str,
    port: int,
    path: str,
    *,
    credentials: Credentials | None = None,
    timeout: float = 3.0,
) -> tuple[int | None, dict[str, str], Any | None, str | None]:
    """Issue a read-only JSON GET; authorization never leaves this in-memory request."""
    headers = [
        f"GET /{path.lstrip('/')} HTTP/1.1",
        f"Host: {address}",
        "User-Agent: jooan-discovery/0.1",
        "Accept: application/json",
        "Connection: close",
    ]
    if credentials:
        headers.append(f"Authorization: {_basic_authorization(credentials)}")
    request = ("\r\n".join(headers) + "\r\n\r\n").encode()
    try:
        payload, _ = await _raw_request(
            address, port, request, timeout=timeout, max_bytes=2_000_000
        )
        status, response_headers, body = _parse_response(payload)
        parsed = json.loads(body) if body else None
        return status, response_headers, parsed, None
    except json.JSONDecodeError as err:
        return status, response_headers, None, f"invalid JSON: {err}"
    except (TimeoutError, OSError) as err:
        return None, {}, None, f"{type(err).__name__}: {err}"


async def probe_websocket(
    address: str, port: int, *, timeout: float = 2.0
) -> tuple[bool, str | None]:
    """Perform only the standard WebSocket HTTP upgrade handshake."""
    import base64

    key = base64.b64encode(os.urandom(16)).decode()
    request = (
        f"GET / HTTP/1.1\r\nHost: {address}:{port}\r\nUpgrade: websocket\r\n"
        f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    ).encode()
    try:
        payload, _ = await _raw_request(address, port, request, timeout=timeout)
        status, headers, _ = _parse_response(payload)
        return status == 101 and headers.get("upgrade", "").lower() == "websocket", headers.get(
            "server"
        )
    except TimeoutError, OSError:
        return False, None
