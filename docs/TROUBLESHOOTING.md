# Troubleshooting

## JOOAN NVR does not appear in Home Assistant

Confirm HACS installed `custom_components/jooan_nvr/manifest.json`, restart Home
Assistant, refresh the browser, then use **Settings → Devices & services → Add
integration**. DHCP discovery is optional; manual setup remains available.

## Cannot connect

Check the NVR's current LAN address and HTTP port in the router or recorder UI. Confirm
Home Assistant can reach the NVR across any VLAN firewall. Use local recorder
credentials, not EseeCloud credentials. Reconfigure the entry after an address change.

## Authentication fails

Re-enter the exact local username and password. A blank password is supported but is
not recommended. The integration does not try defaults or alternate passwords. A
credential failure should start Home Assistant's reauthentication flow.

## One or more cameras are unavailable

An NVR can be online while a wireless channel is disconnected. Check the channel's
**Connected** diagnostic entity and the recorder's own display. Offline channel
entities remain present and recover on a later coordinator update.

## A stream starts but video is blank

Select **Sub / low bandwidth** first. The tested channels supply H.265, and client
HEVC support varies. Try another Home Assistant client to separate recorder transport
from playback compatibility. A separate local media layer is required when the client
needs transcoding; this integration does not transcode.

Confirm Home Assistant's `stream` integration is loaded and loopback TCP is allowed
inside the Home Assistant runtime. Do not expose the bridge port externally.

## Camera IP addresses are not visible on the home LAN

That is expected for the tested recorder. The NVR manages an isolated wireless camera
network. Home Assistant connects to the NVR; the NVR remains required as the bridge.

## Useful diagnostics

Download diagnostics from the integration entry. They contain model, firmware,
channel state, profile, quality, and known capability limitations with sensitive
fields redacted. Review even redacted diagnostics before sharing them.

For a stream failure that needs more detail, temporarily enable the integration's
sanitized lifecycle log and reproduce one camera opening:

```yaml
logger:
  logs:
    custom_components.jooan_nvr: debug
```

Restart Home Assistant after adding the setting. The DEBUG log identifies the
channel, main/sub stream ID, loopback listener, KP2P/ARQ/authentication, first
video/keyframe, PyAV/MPEG-TS, consumer-disconnect, and timeout stage. It does not log
the configured username/password, Authorization value, UID/HWID, auth payload, or
packet contents. Remove the DEBUG setting after collecting the short reproduction;
normal INFO logging intentionally stays quiet.

Do not post raw debug dumps, packet captures, Authorization headers, UID/HWID values,
MAC addresses, public addresses, credentials, household location, or camera footage.
