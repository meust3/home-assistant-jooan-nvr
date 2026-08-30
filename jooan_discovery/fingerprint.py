"""Multi-evidence NVR fingerprint scoring."""

from __future__ import annotations

from .models import HostRecord


def _evidence_text(host: HostRecord) -> str:
    values: list[str] = [host.hostname or "", host.vendor or ""]
    for item in host.http:
        values.extend((item.server or "", item.title or "", item.url))
        values.extend(item.indicators)
    for item in host.rtsp:
        values.extend((item.server or "", item.path, item.codec or ""))
    for item in host.onvif:
        values.extend(item.device_information.values())
        values.extend(item.capabilities.values())
        values.extend(profile.get("name", "") for profile in item.profiles)
    for item in host.local_api:
        values.append(str(item.results))
    for item in host.ssdp:
        values.extend(str(value) for value in item.values())
    for item in host.mdns:
        values.extend((str(item.get("name", "")), str(item.get("value", ""))))
    return " ".join(values).lower()


def score_host(host: HostRecord) -> HostRecord:
    """Score identity; an ordinary web or RTSP port is never decisive on its own."""
    text = _evidence_text(host)
    reasons: list[tuple[int, str]] = []

    if "jooan" in text:
        reasons.append((55, "explicit JOOAN identity in protocol metadata"))
    if "eseecloud" in text or "esee cloud" in text:
        reasons.append((50, "explicit EseeCloud identity in protocol metadata"))
    if "eseelogin" in text or "esee login" in text:
        reasons.append((35, "EseeLogin application assets found on the local web service"))
    if "nvr163" in text or "dvr163" in text:
        reasons.append((25, "NVR163/DVR163 recorder application identifier found"))
    if "kp2p local web module" in text:
        reasons.append((10, "KP2P local recorder web module found"))
    if any(
        token in text
        for token in ("network video recorder", " nvr", "nvr ", "digital video recorder")
    ):
        reasons.append((15, "NVR/DVR identity in device metadata"))
    if any(token in text for token in ("xiongmai", "xmeye")):
        reasons.append((12, "related CCTV ecosystem identifier observed"))
    if host.vendor and any(token in host.vendor.lower() for token in ("jooan", "juan", "xiongmai")):
        reasons.append((22, f"MAC vendor is {host.vendor}"))
    if any(item.discovered_by == "ONVIF WS-Discovery" for item in host.onvif):
        reasons.append((8, "ONVIF endpoint discovered"))
    if any(item.reachable for item in host.onvif):
        reasons.append((8, "ONVIF Device service responded"))
    if any(item.confirmed and item.path == "/" for item in host.rtsp):
        reasons.append((8, "RTSP protocol response confirmed"))
    streams = [item for item in host.rtsp if item.confirmed and item.path != "/"]
    if streams:
        reasons.append((35, f"{len(streams)} RTSP stream path(s) returned SDP"))
    if any(item.confirmed and item.path.startswith("/ch") for item in streams):
        reasons.append((25, "EseeCloud-style /chN_Q.264 stream pattern confirmed"))
    kp2p_streams = [
        stream for protocol in host.kp2p for stream in protocol.streams if stream.confirmed
    ]
    if kp2p_streams:
        reasons.append((35, f"{len(kp2p_streams)} local KP2P stream mapping(s) returned video"))
    if 34567 in host.open_ports and reasons:
        reasons.append((3, "legacy CCTV service port 34567 is open (weak evidence)"))
    if (
        reasons
        and 554 in host.open_ports
        and any(port in host.open_ports for port in (80, 81, 8000, 8080))
    ):
        reasons.append((4, "combined web and RTSP services (weak evidence)"))

    deduplicated: list[tuple[int, str]] = []
    seen: set[str] = set()
    for points, reason in reasons:
        if reason not in seen:
            seen.add(reason)
            deduplicated.append((points, reason))
    score = min(sum(points for points, _ in deduplicated), 100)
    explicit_identity = "jooan" in text or "eseecloud" in text or "esee cloud" in text
    confirmed_stream = any(item.confirmed and item.path != "/" for item in host.rtsp) or bool(
        kp2p_streams
    )
    if explicit_identity and confirmed_stream:
        confidence = "CONFIRMED"
    elif score >= 65:
        confidence = "HIGH CONFIDENCE"
    elif score > 0:
        confidence = "HYPOTHESIS"
    else:
        confidence = "NOT SUPPORTED"
    host.score = score
    host.confidence = confidence
    host.score_reasons = [f"+{points}: {reason}" for points, reason in deduplicated]
    return host


def merits_deep_probe(host: HostRecord) -> bool:
    """Conservative gate: require protocol/device evidence or a CCTV service combination."""
    ports = set(host.open_ports)
    return bool(
        host.score >= 8
        or host.onvif
        or any(item.confirmed for item in host.rtsp)
        or (554 in ports and bool(ports & {80, 81, 8000, 8080, 8081, 8899, 9000, 34567}))
    )
