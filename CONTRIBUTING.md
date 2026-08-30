# Contributing

Bug reports, compatibility results, documentation fixes, and focused pull requests
are welcome. This is an interoperability project, so evidence and privacy discipline
matter as much as code.

## Before opening an issue

Use the matching issue form. Attach Home Assistant diagnostics when possible instead
of raw logs or captures. Remove passwords, Authorization headers, public addresses,
NVR UID/HWID values, MAC addresses, camera identifiers, footage, and exact household
location. Never upload firmware, vendor application bundles, or proprietary binaries.

Security vulnerabilities belong in a private report described in [SECURITY.md](SECURITY.md).

## Development environment

Use Python 3.14.2 or newer on Linux, or a Linux container from another operating
system.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check .
python -m ruff format --check .
python -m compileall -q custom_components jooan_discovery tests scripts
python scripts/validate_isolation.py
python scripts/validate_hacs.py
```

Tests must be deterministic and must not contact a real recorder. Use mocks and small,
synthetic media fixtures. Do not commit packet captures, generated device reports,
logs, or real video.

## Pull requests

- Keep runtime integration dependencies inside `custom_components/jooan_nvr` or
  declare genuinely external requirements in `manifest.json`.
- Preserve read-only behavior unless a proposal has been discussed first.
- Add tests for behavior changes, especially cancellation and redaction paths.
- Update documentation and `CHANGELOG.md` when behavior visible to users changes.
- Confirm the manifest version is changed only as part of a release.
- Accept the [Code of Conduct](CODE_OF_CONDUCT.md).

Contributions must be original or legally redistributable. Do not copy vendor source,
logos, web bundles, firmware, decompiled binaries, or camera samples.
