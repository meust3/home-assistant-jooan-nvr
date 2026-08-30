# JOOAN NVR for Home Assistant

[![Tests](https://github.com/meust3/home-assistant-jooan-nvr/actions/workflows/tests.yml/badge.svg)](https://github.com/meust3/home-assistant-jooan-nvr/actions/workflows/tests.yml)
[![HACS validation](https://github.com/meust3/home-assistant-jooan-nvr/actions/workflows/hacs.yml/badge.svg)](https://github.com/meust3/home-assistant-jooan-nvr/actions/workflows/hacs.yml)
[![Home Assistant validation](https://github.com/meust3/home-assistant-jooan-nvr/actions/workflows/hassfest.yml/badge.svg)](https://github.com/meust3/home-assistant-jooan-nvr/actions/workflows/hassfest.yml)

[![Open your Home Assistant instance and add this repository to HACS](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=meust3&repository=home-assistant-jooan-nvr&category=integration)

A local-only Home Assistant custom integration for camera feeds and read-only status
from compatible JOOAN/EseeCloud NVRs. It does not require an EseeCloud account or
cloud service.

The repository also retains `jooan_discovery`, a conservative development and
diagnostic tool. The HACS-installed integration is entirely self-contained in
`custom_components/jooan_nvr` and does not import that tool.

## Compatibility and confirmed behavior

The tested recorder is a JOOAN `JA-8108-W` eight-channel NVR. Its confirmed local
architecture is:

| Capability | Confirmed behavior |
| --- | --- |
| Metadata and state | Read-only local Netsdk HTTP API using HTTP Basic authentication |
| Live video | Recorder-local KP2P WebSocket service |
| Camera topology | Private wireless camera network managed by the NVR |
| Channels | All eight configured channels are represented in Home Assistant |
| Physically stream-tested | Cameras 2 and 5 (recorder channel IDs 1 and 4) |
| Tested codec | H.265/HEVC main and substreams, remuxed without transcoding |
| RTSP | No standard RTSP service was confirmed |
| ONVIF | No standard ONVIF service was confirmed |
| Motion | No reliable local event transition was proven; no motion entity is included |

The NVR remains required because it bridges the cameras' private wireless network.
This project is not replacement NVR software, does not replace or reformat the NVR
HDD, and does not change recording or camera configuration.

## How streaming works

On demand, the integration authenticates to the NVR's local KP2P service, requests
the selected channel, strips the proprietary frame header, and remuxes the unchanged
H.264 or H.265 elementary stream into timestamped MPEG-TS. Home Assistant receives a
credential-free URL from a listener bound only to `127.0.0.1`.

The integration does not decode or transcode video and does not keep every channel
open. It has no FFmpeg subprocess of its own; Home Assistant's `stream` integration
handles client delivery. This release does not provide Frigate recording.

## Install with HACS

This repository is a HACS custom repository; it is not submitted to the default HACS
store.

1. Open HACS in Home Assistant.
2. Open the top-right menu and select **Custom repositories**.
3. Enter `https://github.com/meust3/home-assistant-jooan-nvr`.
4. Select category **Integration**, then add the repository.
5. Open **JOOAN NVR** in HACS and select **Download**.
6. Select the latest published release and complete the download.
7. Restart Home Assistant.
8. Open **Settings → Devices & services → Add integration**.
9. Search for **JOOAN NVR**.

See [the detailed HACS guide](docs/HACS_INSTALL.md) for update and rollback steps.

### Manual installation

Download `jooan-nvr-vX.Y.Z.zip` from the matching GitHub Release and verify it with
the accompanying `.sha256` file. Extract it into the Home Assistant configuration
directory so the final path is:

```text
/config/custom_components/jooan_nvr/manifest.json
```

Restart Home Assistant, then add **JOOAN NVR** from **Settings → Devices & services**.

## Configure the NVR

Enter the NVR's LAN hostname or address, HTTP port (normally `80`), local username,
and local password. These are recorder credentials, not EseeCloud account
credentials. Blank-password devices are supported, but configuring a proper local
password on the recorder is strongly recommended.

The flow validates the recorder and shows the detected channel count and online
channels before saving. Start with **Sub / low bandwidth**, then validate Cameras 2
and 5 first because those are the channels physically stream-tested during
development. Change quality later from the integration's **Configure** dialog:

- **Sub / low bandwidth** (default)
- **Main / high quality**

Changing quality reloads the config entry without creating duplicate entities.

## Devices and entities

Home Assistant creates one parent NVR device and one child device per configured
channel, linked through `via_device`. Each of the eight channels can be created even
when it is offline. Each channel has:

- a camera entity;
- a diagnostic connected binary sensor;
- a recorder-reported recording-state binary sensor.

Offline entities remain present and become available again after the NVR or channel
recovers. No motion entity is created because no reliable local motion-event source
has been proven.

## H.264 and H.265 clients

Both H.264 and H.265 remux paths have synthetic automated coverage. The current
recorder supplied H.265 on the physically validated channels, and the integration
preserves that codec. Playback therefore depends on HEVC support in the Home
Assistant client, browser, operating system, and media path. Try the substream first.
A client without HEVC support needs a separate local transcoding layer; the
integration itself does not transcode.

## Diagnostics and privacy

Open the integration entry in **Settings → Devices & services** and select
**Download diagnostics**. Diagnostics redact credentials, recorder address, recorder
and camera MAC addresses, and the stable device identifier. They do not contain an
Authorization header or credential-bearing stream URL.

Before posting an issue, inspect the file and redact household location, public
addresses, NVR UID/HWID, camera identifiers, and any unexpected private data. Attach
Home Assistant diagnostics rather than raw debug dumps, captures, or camera footage.

The integration communicates only with the configured recorder and Home Assistant's
loopback interface. It does not use telemetry, an EseeCloud account, or a cloud API.
Credentials remain in Home Assistant's config-entry storage and never appear in the
local stream URL.

## Update, rollback, remove

To update, wait for HACS to detect a new GitHub Release (or select **Update
information**), download it, restart Home Assistant, and validate integration startup
and an advancing stream.

To roll back, open the repository in HACS, choose **Redownload**, select a previous
available release, restart Home Assistant, and validate it. Restoring a Home Assistant
backup is the fallback. Config entries and credentials are separate from the
HACS-installed source files.

To remove the integration, delete its config entry from **Settings → Devices &
services**, remove it in HACS (or manually delete
`/config/custom_components/jooan_nvr`), and restart Home Assistant. This does not
alter the NVR, its HDD, or its recordings.

## Troubleshooting

- **Not discovered:** manual setup always works. Confirm Home Assistant can reach the
  NVR's HTTP and local KP2P ports.
- **Cannot connect:** verify the LAN address, HTTP port, VLAN/firewall policy, and
  local recorder credentials. Use **Reconfigure** after an address change.
- **Camera unavailable:** the NVR can be online while an individual wireless channel
  is offline. Check the channel's **Connected** entity.
- **Stream opens but no picture appears:** select the substream and check HEVC support.
  Also confirm Home Assistant's `stream` integration loaded and loopback TCP is
  allowed in the runtime.
- **No camera IPs on the home LAN:** this is expected for the tested topology; connect
  Home Assistant to the NVR, not its isolated camera network.

More detail is in [Troubleshooting](docs/TROUBLESHOOTING.md).

## Development

Home Assistant 2026.8 uses Python 3.14; this project targets Python 3.14.2 or newer.
All automated protocol tests use mocks or synthetic media and never contact a real
NVR.

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check .
python -m ruff format --check .
python -m compileall -q custom_components jooan_discovery tests scripts
python scripts/validate_isolation.py
python scripts/validate_hacs.py
python scripts/build_release.py --version 0.1.0
```

The isolation check copies only `custom_components/jooan_nvr`, starts Python in
isolated mode without the repository on `PYTHONPATH`, and imports every integration
module. See [Contributing](CONTRIBUTING.md) and [the release procedure](docs/RELEASING.md).

## Standalone diagnostic tool

The optional scanner probes only directly connected private networks selected by the
user, rate-limits active requests, and never brute-forces credentials. Reports go to
the ignored `artifacts/` directory and are recursively redacted.

```bash
python -m jooan_discovery scan --artifacts artifacts
python -m jooan_discovery scan --artifacts artifacts --username admin --prompt-credentials
```

The password prompt does not echo and accepts an empty password. There is no command
line password argument. Never publish generated reports without reviewing them.

## Limitations

- Only the JOOAN `JA-8108-W` has been tested.
- Only Cameras 2 and 5 were physically online and stream-validated during development.
- H.265 playback remains client-dependent.
- No standard RTSP or ONVIF service was confirmed on the tested recorder.
- No motion-event mechanism is proven.
- The NVR remains required as the wireless camera bridge and recorder.
- This release does not replace NVR recording, HDD functionality, or Frigate.

## Disclaimer

This is an unofficial, community-developed interoperability project. It is not
affiliated with, endorsed by, or supported by JOOAN or EseeCloud. Use it only with
equipment and networks you are authorised to access.

Released under the [MIT License](LICENSE).
