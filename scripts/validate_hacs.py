"""Validate the repository's HACS integration layout and release metadata."""

from __future__ import annotations

import json
import re
import struct
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DOMAIN = "jooan_nvr"
VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")


def _load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _png_size(path: Path) -> tuple[int, int]:
    payload = path.read_bytes()[:24]
    if len(payload) != 24 or payload[:8] != b"\x89PNG\r\n\x1a\n" or payload[12:16] != b"IHDR":
        raise SystemExit(f"{path.relative_to(REPOSITORY_ROOT)} is not a valid PNG")
    return struct.unpack(">II", payload[16:24])


def main() -> None:
    custom_components = REPOSITORY_ROOT / "custom_components"
    integrations = sorted(
        path.name
        for path in custom_components.iterdir()
        if path.is_dir() and not path.name.startswith("__")
    )
    assert integrations == [DOMAIN], f"expected exactly {DOMAIN}, found {integrations}"

    component = custom_components / DOMAIN
    manifest = _load_json(component / "manifest.json")
    required = {
        "domain",
        "name",
        "version",
        "documentation",
        "issue_tracker",
        "codeowners",
        "config_flow",
        "integration_type",
        "iot_class",
        "requirements",
    }
    missing = required - manifest.keys()
    assert not missing, f"manifest keys missing: {sorted(missing)}"
    assert manifest["domain"] == DOMAIN
    assert manifest["integration_type"] == "hub"
    assert manifest["iot_class"] == "local_polling"
    assert isinstance(manifest["version"], str) and VERSION_PATTERN.fullmatch(manifest["version"])

    hacs = _load_json(REPOSITORY_ROOT / "hacs.json")
    assert hacs["name"] == "JOOAN NVR"
    assert isinstance(hacs.get("homeassistant"), str)
    assert "content_in_root" not in hacs
    assert "zip_release" not in hacs
    assert "hide_default_branch" not in hacs

    brand = component / "brand"
    icon_size = _png_size(brand / "icon.png")
    logo_size = _png_size(brand / "logo.png")
    assert icon_size == (256, 256), f"icon.png must be 256x256, found {icon_size}"
    assert logo_size[0] > logo_size[1]
    assert 128 <= min(logo_size) <= 256
    print(f"HACS layout passed for {DOMAIN} {manifest['version']}")


if __name__ == "__main__":
    main()
