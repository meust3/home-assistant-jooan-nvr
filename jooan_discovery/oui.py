"""Best-effort offline MAC OUI lookup using databases already on the host."""

from __future__ import annotations

import os
import re
import shutil
from functools import lru_cache
from pathlib import Path

from manuf import manuf

_NMAP_RE = re.compile(r"^([0-9A-Fa-f]{6})\s+(.+?)\s*$")
_MANUF_RE = re.compile(r"^([0-9A-Fa-f:]{8})(?:/\d+)?\s+([^\t]+)")


def _database_paths() -> list[Path]:
    paths = [
        Path("/usr/share/nmap/nmap-mac-prefixes"),
        Path("/usr/local/share/nmap/nmap-mac-prefixes"),
        Path("/usr/share/wireshark/manuf"),
        Path("/usr/share/ieee-data/oui.txt"),
    ]
    nmap = shutil.which("nmap")
    if nmap:
        paths.extend(
            [
                Path(nmap).with_name("nmap-mac-prefixes"),
                Path(nmap).parent / "share" / "nmap" / "nmap-mac-prefixes",
            ]
        )
    program_files = os.environ.get("PROGRAMFILES")
    if program_files:
        paths.extend(
            [
                Path(program_files) / "Nmap" / "nmap-mac-prefixes",
                Path(program_files) / "Wireshark" / "manuf",
            ]
        )
    return paths


@lru_cache(maxsize=1)
def load_oui_database() -> dict[str, str]:
    vendors: dict[str, str] = {}
    for path in _database_paths():
        if not path.is_file():
            continue
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                match = _NMAP_RE.match(stripped)
                if match:
                    vendors.setdefault(match.group(1).upper(), match.group(2).strip())
                    continue
                match = _MANUF_RE.match(stripped)
                if match:
                    prefix = match.group(1).replace(":", "").upper()
                    vendors.setdefault(prefix, match.group(2).strip())
        except OSError:
            continue
    return vendors


def lookup_vendor(mac: str | None) -> str | None:
    if not mac:
        return None
    normalized = mac.replace(":", "").replace("-", "").upper()
    if len(normalized) < 6:
        return None
    local_result = load_oui_database().get(normalized[:6])
    if local_result:
        return local_result
    result = _manuf_parser().get_all(mac)
    return result.manuf_long or result.manuf


def has_oui_database() -> bool:
    return bool(load_oui_database()) or _manuf_parser() is not None


@lru_cache(maxsize=1)
def _manuf_parser() -> manuf.MacParser:
    # The package ships an offline Wireshark-style database; update=False prevents network access.
    return manuf.MacParser(update=False)
