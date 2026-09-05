# Changelog

All notable changes use [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project follows [Semantic Versioning](https://semver.org/).

## [0.1.2]

### Fixed

- Restore camera and channel entity registration on Home Assistant 2026.9 by
  replacing the deprecated `via_device` relationship with `via_device_id`.
- Preserve all existing channel and camera unique IDs so renamed entities, dashboard
  cards, and automations reattach without migration.
- Add Home Assistant 2026.9 config-entry and device-hierarchy regression coverage
  while retaining Home Assistant 2026.8 validation.

## [0.1.1]

### Fixed

- Use Home Assistant 2026.8's `use_stream_for_stills` property so entity-picture
  requests use the shared stream instead of the unimplemented `camera_image()` path.
- Initialize both coordinator and camera bases, restoring Home Assistant's stream,
  access-token, cache, and stream-lock state for JOOAN camera entities.
- Combine recorder/channel connectivity with Home Assistant stream health and retain
  the supported automatic stream retry path after a transient failure.
- Add sanitized DEBUG lifecycle diagnostics for loopback, KP2P, ARQ, authentication,
  live-request, video/keyframe, PyAV, MPEG-TS, disconnect, and stop stages.
- Move synchronous PyAV parsing and muxing work off Home Assistant's event loop.
- Normalize common `http://host/` input and return `invalid_host` for malformed host
  values instead of an unhandled config-flow error.

### Validation

- Added Home Assistant camera-proxy and HLS regression coverage using the real
  2026.8 stream/PyAV path over `tcp://127.0.0.1:<port>`.
- Added still generation, multiple frontend openings, live-card, stream failure and
  recovery, H.265 decode, blank-password, host, lifecycle, and log-redaction tests.
- Real Home Assistant playback remains to be retested after installing this release.

## [0.1.0]

### Added

- Local-only Home Assistant config flow, reauthentication, reconfiguration, and DHCP discovery.
- Parent NVR and child channel devices with camera, connectivity, and recording-state entities.
- Read-only Netsdk polling for recorder identity, channels, stream profiles, and state.
- On-demand H.264/H.265 KP2P stream remuxing through loopback-only MPEG-TS bridges.
- Diagnostics with credential, network-address, MAC-address, and device-ID redaction.
- HACS metadata, original local brand assets, public documentation, and release automation.
- Synthetic bridge coverage for timestamps, disconnects, cancellation, restart, and concurrent consumers.

### Known limitations

- Hardware validation is limited to the JOOAN JA-8108-W.
- Only Cameras 2 and 5 were physically online and stream-tested during development.
- No standard RTSP or ONVIF service, or reliable local motion-event mechanism, was confirmed.
- H.265 playback depends on the client; the integration does not transcode.
- The NVR remains responsible for its wireless cameras, HDD, and recording.

[0.1.2]: https://github.com/meust3/home-assistant-jooan-nvr/releases/tag/v0.1.2
[0.1.1]: https://github.com/meust3/home-assistant-jooan-nvr/releases/tag/v0.1.1
[0.1.0]: https://github.com/meust3/home-assistant-jooan-nvr/releases/tag/v0.1.0
