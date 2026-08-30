# Changelog

All notable changes use [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project follows [Semantic Versioning](https://semver.org/).

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

[0.1.0]: https://github.com/meust3/home-assistant-jooan-nvr/releases/tag/v0.1.0
