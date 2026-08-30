"""Small, read-only ONVIF SOAP investigator with HTTP Digest and WS-Security support."""

from __future__ import annotations

import asyncio
import base64
import datetime as dt
import hashlib
import os
import ssl
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any

from .models import OnvifEvidence
from .security import Credentials, redact_url

SOAP = "http://www.w3.org/2003/05/soap-envelope"
DEVICE = "http://www.onvif.org/ver10/device/wsdl"
MEDIA = "http://www.onvif.org/ver10/media/wsdl"
SCHEMA = "http://www.onvif.org/ver10/schema"
EVENTS = "http://www.onvif.org/ver10/events/wsdl"
WSA = "http://www.w3.org/2005/08/addressing"
WSNT = "http://docs.oasis-open.org/wsn/b-2"


class OnvifError(Exception):
    """Base ONVIF investigation error."""


class OnvifAuthenticationRequired(OnvifError):
    """The endpoint requires credentials or rejected supplied credentials."""


class OnvifConnectivityError(OnvifError):
    """The endpoint could not be reached."""


@dataclass(slots=True)
class SoapResponse:
    status: int
    body: bytes
    root: ET.Element


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _text(node: ET.Element | None) -> str | None:
    return node.text.strip() if node is not None and node.text else None


def _first(root: ET.Element, name: str) -> ET.Element | None:
    return next((node for node in root.iter() if _local(node.tag) == name), None)


def _ws_security(credentials: Credentials) -> str:
    created = dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    nonce = os.urandom(16)
    digest = hashlib.sha1(  # noqa: S324 - mandated by ONVIF UsernameToken Profile
        nonce + created.encode() + credentials.password.encode()
    ).digest()
    password_digest = base64.b64encode(digest).decode()
    encoded_nonce = base64.b64encode(nonce).decode()
    from xml.sax.saxutils import escape

    return f"""<wsse:Security s:mustUnderstand="1"
 xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
 xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
 <wsse:UsernameToken>
  <wsse:Username>{escape(credentials.username)}</wsse:Username>
  <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{password_digest}</wsse:Password>
  <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{encoded_nonce}</wsse:Nonce>
  <wsu:Created>{created}</wsu:Created>
 </wsse:UsernameToken>
</wsse:Security>"""


def _envelope(body: str, credentials: Credentials | None = None, header: str = "") -> bytes:
    security = _ws_security(credentials) if credentials else ""
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="{SOAP}">
 <s:Header>{security}{header}</s:Header>
 <s:Body>{body}</s:Body>
</s:Envelope>'''.encode()


def _soap_call_sync(
    endpoint: str,
    action: str,
    body: str,
    credentials: Credentials | None,
    timeout: float,
    header: str = "",
) -> SoapResponse:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    handlers: list[Any] = [urllib.request.HTTPSHandler(context=context)]
    if credentials:
        manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        manager.add_password(None, endpoint, credentials.username, credentials.password)
        handlers.append(urllib.request.HTTPDigestAuthHandler(manager))
        handlers.append(urllib.request.HTTPBasicAuthHandler(manager))
    opener = urllib.request.build_opener(*handlers)
    request = urllib.request.Request(
        endpoint,
        data=_envelope(body, credentials, header),
        method="POST",
        headers={
            "Content-Type": f'application/soap+xml; charset=utf-8; action="{action}"',
            "User-Agent": "jooan-discovery/0.1",
        },
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            payload = response.read(2_000_000)
            status = response.status
    except urllib.error.HTTPError as err:
        payload = err.read(2_000_000)
        if err.code in {401, 403}:
            raise OnvifAuthenticationRequired(f"HTTP {err.code}") from err
        if payload:
            try:
                fault = ET.fromstring(payload)
                reason = _text(_first(fault, "Text")) or _text(_first(fault, "Reason"))
            except ET.ParseError:
                reason = None
            raise OnvifError(f"HTTP {err.code}: {reason or 'SOAP fault'}") from err
        raise OnvifError(f"HTTP {err.code}") from err
    except (urllib.error.URLError, TimeoutError, OSError) as err:
        raise OnvifConnectivityError(
            str(err.reason if isinstance(err, urllib.error.URLError) else err)
        ) from err
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as err:
        raise OnvifError(f"invalid XML response ({len(payload)} bytes)") from err
    fault = _first(root, "Fault")
    if fault is not None:
        reason = _text(_first(fault, "Text")) or _text(_first(fault, "Reason")) or "SOAP fault"
        if "auth" in reason.lower() or "notauthorized" in reason.lower():
            raise OnvifAuthenticationRequired(reason)
        raise OnvifError(reason)
    return SoapResponse(status=status, body=payload, root=root)


async def soap_call(
    endpoint: str,
    action: str,
    body: str,
    credentials: Credentials | None,
    timeout: float = 4.0,
    header: str = "",
) -> SoapResponse:
    return await asyncio.to_thread(
        _soap_call_sync, endpoint, action, body, credentials, timeout, header
    )


def _capabilities(root: ET.Element) -> dict[str, str]:
    found: dict[str, str] = {}
    for node in root.iter():
        if _local(node.tag) != "XAddr" or not node.text:
            continue
        parent_name = "Unknown"
        for parent in root.iter():
            if node in list(parent):
                parent_name = _local(parent.tag)
                break
        found[parent_name] = redact_url(node.text.strip())
    return found


def _profile(node: ET.Element) -> dict[str, Any]:
    item: dict[str, Any] = {"token": node.attrib.get("token")}
    name = _text(_first(node, "Name"))
    if name:
        item["name"] = name
    encoder = _first(node, "VideoEncoderConfiguration")
    if encoder is not None:
        encoding = _text(_first(encoder, "Encoding"))
        width = _text(_first(encoder, "Width"))
        height = _text(_first(encoder, "Height"))
        rate = _text(_first(encoder, "FrameRateLimit"))
        bitrate = _text(_first(encoder, "BitrateLimit"))
        if encoding:
            item["codec"] = encoding
        if width and height:
            item["resolution"] = f"{width}x{height}"
        if rate:
            item["frame_rate"] = rate
        if bitrate:
            item["bitrate_kbps"] = bitrate
    source = _first(node, "VideoSourceConfiguration")
    if source is not None:
        source_token = _text(_first(source, "SourceToken"))
        if source_token:
            item["source_token"] = source_token
    return {key: value for key, value in item.items() if value is not None}


def _video_source(node: ET.Element) -> dict[str, Any]:
    item: dict[str, Any] = {"token": node.attrib.get("token")}
    width = _text(_first(node, "Width"))
    height = _text(_first(node, "Height"))
    frame_rate = _text(_first(node, "Framerate"))
    if width and height:
        item["resolution"] = f"{width}x{height}"
    if frame_rate:
        item["frame_rate"] = frame_rate
    return {key: value for key, value in item.items() if value is not None}


async def investigate_onvif(
    endpoint: str,
    *,
    credentials: Credentials | None = None,
    discovered_by: str = "probe",
    test_events: bool = False,
    timeout: float = 4.0,
) -> OnvifEvidence:
    """Run read-only ONVIF calls; optionally create a short PullPoint subscription."""
    result = OnvifEvidence(endpoint=redact_url(endpoint), discovered_by=discovered_by)
    try:
        response = await soap_call(
            endpoint,
            f"{DEVICE}/GetDeviceInformation",
            f'<tds:GetDeviceInformation xmlns:tds="{DEVICE}"/>',
            credentials,
            timeout,
        )
        result.reachable = True
        for field in ("Manufacturer", "Model", "FirmwareVersion", "SerialNumber", "HardwareId"):
            value = _text(_first(response.root, field))
            if value:
                result.device_information[field] = value
    except OnvifAuthenticationRequired as err:
        result.auth_required = True
        result.errors.append(f"GetDeviceInformation: authentication required ({err})")
        return result
    except OnvifError as err:
        result.errors.append(f"GetDeviceInformation: {err}")
        return result

    try:
        response = await soap_call(
            endpoint,
            f"{DEVICE}/GetCapabilities",
            f'<tds:GetCapabilities xmlns:tds="{DEVICE}">'
            "<tds:Category>All</tds:Category></tds:GetCapabilities>",
            credentials,
            timeout,
        )
        result.capabilities = _capabilities(response.root)
    except OnvifError as err:
        result.errors.append(f"GetCapabilities: {err}")

    media_endpoint = result.capabilities.get("Media") or endpoint
    try:
        response = await soap_call(
            media_endpoint,
            f"{MEDIA}/GetProfiles",
            f'<trt:GetProfiles xmlns:trt="{MEDIA}"/>',
            credentials,
            timeout,
        )
        result.profiles = [
            _profile(node) for node in response.root.iter() if _local(node.tag) == "Profiles"
        ]
    except OnvifError as err:
        result.errors.append(f"GetProfiles: {err}")

    try:
        response = await soap_call(
            media_endpoint,
            f"{MEDIA}/GetVideoSources",
            f'<trt:GetVideoSources xmlns:trt="{MEDIA}"/>',
            credentials,
            timeout,
        )
        result.video_sources = [
            _video_source(node)
            for node in response.root.iter()
            if _local(node.tag) == "VideoSources"
        ]
    except OnvifError as err:
        result.errors.append(f"GetVideoSources: {err}")

    for profile in result.profiles:
        token = profile.get("token")
        if not token:
            continue
        try:
            response = await soap_call(
                media_endpoint,
                f"{MEDIA}/GetStreamUri",
                f'''<trt:GetStreamUri xmlns:trt="{MEDIA}" xmlns:tt="{SCHEMA}">
 <trt:StreamSetup><tt:Stream>RTP-Unicast</tt:Stream>
 <tt:Transport><tt:Protocol>RTSP</tt:Protocol></tt:Transport></trt:StreamSetup>
 <trt:ProfileToken>{token}</trt:ProfileToken></trt:GetStreamUri>''',
                credentials,
                timeout,
            )
            uri = _text(_first(response.root, "Uri"))
            if uri:
                result.stream_uris.append({"profile_token": token, "uri": redact_url(uri)})
        except OnvifError as err:
            result.errors.append(f"GetStreamUri({token}): {err}")

    events_endpoint = result.capabilities.get("Events")
    result.event_service = bool(events_endpoint)
    if events_endpoint:
        try:
            response = await soap_call(
                events_endpoint,
                f"{EVENTS}/GetEventProperties",
                f'<tev:GetEventProperties xmlns:tev="{EVENTS}"/>',
                credentials,
                timeout,
            )
            topics: set[str] = set()
            topic_set = _first(response.root, "TopicSet")
            if topic_set is not None:
                for node in topic_set.iter():
                    name = _local(node.tag)
                    if (
                        "motion" in name.lower()
                        or "video" in name.lower()
                        or "alarm" in name.lower()
                    ):
                        topics.add(name)
            result.event_topics = sorted(topics)
            if test_events:
                result.pullpoint_supported = await _test_pullpoint(
                    events_endpoint, credentials, timeout, result.errors
                )
        except OnvifError as err:
            result.errors.append(f"GetEventProperties: {err}")

    result.ptz_service = bool(result.capabilities.get("PTZ"))
    return result


async def _test_pullpoint(
    endpoint: str,
    credentials: Credentials | None,
    timeout: float,
    errors: list[str],
) -> bool:
    """Create a one-minute subscription; no PTZ/config/device state is changed."""
    try:
        await soap_call(
            endpoint,
            f"{EVENTS}/CreatePullPointSubscription",
            f'''<tev:CreatePullPointSubscription xmlns:tev="{EVENTS}">
 <tev:InitialTerminationTime>PT1M</tev:InitialTerminationTime>
</tev:CreatePullPointSubscription>''',
            credentials,
            timeout,
        )
        return True
    except OnvifError as err:
        errors.append(f"CreatePullPointSubscription: {err}")
        return False
