"""Build a deterministic manual-install ZIP for one release."""

from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
COMPONENT = REPOSITORY_ROOT / "custom_components" / "jooan_nvr"
FIXED_TIMESTAMP = (2026, 1, 1, 0, 0, 0)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version")
    parser.add_argument("--output-dir", type=Path, default=REPOSITORY_ROOT / "dist")
    args = parser.parse_args()

    manifest = json.loads((COMPONENT / "manifest.json").read_text(encoding="utf-8"))
    manifest_version = manifest["version"]
    version = args.version or manifest_version
    if version != manifest_version:
        raise SystemExit(
            f"requested version {version} does not match manifest version {manifest_version}"
        )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    archive = args.output_dir / f"jooan-nvr-v{version}.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as output:
        for source in sorted(COMPONENT.rglob("*")):
            if not source.is_file() or "__pycache__" in source.parts or source.suffix == ".pyc":
                continue
            info = zipfile.ZipInfo(source.relative_to(REPOSITORY_ROOT).as_posix(), FIXED_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            output.writestr(info, source.read_bytes(), compresslevel=9)

    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    checksum = archive.with_suffix(f"{archive.suffix}.sha256")
    checksum.write_text(f"{digest}  {archive.name}\n", encoding="ascii", newline="\n")
    print(archive)
    print(checksum)
    print(digest)


if __name__ == "__main__":
    main()
