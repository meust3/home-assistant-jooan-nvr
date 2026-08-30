# Security policy

## Supported versions

Security fixes are provided for the latest published release. Upgrade through HACS
before reporting a problem that has already been fixed on the default branch.

## Report a vulnerability privately

Use GitHub's **Report a vulnerability** feature in the repository Security tab. Do
not open a public issue for a vulnerability and do not attach credentials, device
identifiers, network captures, or camera footage. Include the affected release,
impact, a minimal reproduction using synthetic data, and any suggested mitigation.

If private vulnerability reporting is unavailable, open a public issue containing no
sensitive detail and ask the maintainer to arrange a private channel.

## Security model

- The integration connects only to the configured local recorder and a loopback TCP
  listener.
- Recorder credentials are stored by Home Assistant and never embedded in stream URLs.
- Diagnostics redact credentials, host addresses, MAC addresses, and stable device IDs.
- The Netsdk client uses read-only endpoints; the integration does not change recorder
  configuration or recordings.
- The KP2P authentication field uses a recorder-family wire-format compatibility
  constant. It is not a device or account secret and cannot authenticate without the
  user's local recorder credentials.
- Blank recorder passwords are supported for compatibility but are not recommended.

Treat Home Assistant backups and `.storage` as sensitive because Home Assistant owns
the saved config entry and credentials. Keep the recorder and Home Assistant on
trusted local networks and restrict unneeded cross-VLAN access.
