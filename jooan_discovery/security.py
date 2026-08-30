"""Credential handling and recursive artifact redaction."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import SplitResult, urlsplit, urlunsplit

REDACTED = "***"
SENSITIVE_KEYS = {
    "authorization",
    "cloudid",
    "cloud_id",
    "cloudpassword",
    "cloud_password",
    "cloudusername",
    "cloud_username",
    "cookie",
    "device_id",
    "deviceid",
    "devid",
    "eseeid",
    "guid",
    "hardware_id",
    "hardwareid",
    "hwid",
    "nonce",
    "password",
    "passwd",
    "secret",
    "serial_token",
    "token",
    "uid",
}
_URL_RE = re.compile(r"(?P<scheme>rtsps?|https?)://(?P<userinfo>[^/@\s]+)@", re.I)
_AUTH_RE = re.compile(r"(?i)(authorization\s*:\s*)([^\r\n]+)")
_LEGACY_PASSWORD_RE = re.compile(r"(?i)(_password=)([^_/?&\s]+)")
_STRUCTURED_SECRET_RE = re.compile(
    r"""(?ix)
    (?P<prefix>
      ["']?(?:cloud_?id|cloud_?password|cloud_?username|device_?id|devid|eseeid|
      guid|hardware_?id|hwid|nonce|passwd|password|secret|token|uid)["']?
      \s*[:=]\s*["']
    )
    (?P<value>[^"']*)
    (?P<suffix>["'])
    """
)


@dataclass(slots=True)
class Credentials:
    username: str
    password: str


def redact_url(value: str) -> str:
    """Redact URL userinfo without damaging non-URL strings."""
    try:
        parsed = urlsplit(value)
    except ValueError:
        parsed = SplitResult("", "", value, "", "")
    if parsed.scheme.lower() in {"http", "https", "rtsp", "rtsps"} and "@" in parsed.netloc:
        host = parsed.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = f":{parsed.port}" if parsed.port else ""
        username = parsed.username or ""
        netloc = f"{username}:{REDACTED}@{host}{port}"
        value = urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))
    value = _URL_RE.sub(
        lambda m: f"{m.group('scheme')}://{m.group('userinfo').split(':', 1)[0]}:{REDACTED}@", value
    )
    value = _AUTH_RE.sub(lambda m: f"{m.group(1)}{REDACTED}", value)
    value = _LEGACY_PASSWORD_RE.sub(lambda m: f"{m.group(1)}{REDACTED}", value)
    return _STRUCTURED_SECRET_RE.sub(
        lambda match: f"{match.group('prefix')}{REDACTED}{match.group('suffix')}", value
    )


def redact(value: Any, key: str | None = None) -> Any:
    """Recursively redact sensitive fields and credentials embedded in strings."""
    if key and key.lower() in SENSITIVE_KEYS:
        return REDACTED
    if isinstance(value, str):
        return redact_url(value)
    if isinstance(value, Mapping):
        return {str(k): redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return [redact(item) for item in value]
    return value
