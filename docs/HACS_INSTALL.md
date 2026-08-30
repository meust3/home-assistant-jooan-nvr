# Install, update, and roll back with HACS

## Requirements

- Home Assistant 2026.8.0 or newer.
- HACS installed and working.
- Home Assistant network access to the NVR's LAN address and local KP2P service.
- The NVR's local username and password. Do not use EseeCloud account credentials.

## Install

1. Open HACS in Home Assistant.
2. Open the top-right menu.
3. Select **Custom repositories**.
4. Enter `https://github.com/meust3/home-assistant-jooan-nvr`.
5. Select category **Integration**.
6. Add the repository.
7. Open **JOOAN NVR** in HACS.
8. Select **Download**.
9. Select the latest published release.
10. Restart Home Assistant.
11. Open **Settings → Devices & services**.
12. Select **Add integration**.
13. Search for **JOOAN NVR**.
14. Enter the NVR's LAN address, HTTP port, local username, and local password.
15. Keep **Sub / low bandwidth** selected initially.
16. Validate Camera 2 and Camera 5 first; those channels were physically tested.

A blank password is accepted when the recorder is configured that way, but setting a
proper local recorder password is strongly recommended.

## Update

1. Wait for HACS to detect the new GitHub Release, or open HACS and select **Update
   information**.
2. Open **JOOAN NVR** and download the update.
3. Restart Home Assistant.
4. Confirm the integration loads without an error.
5. Confirm at least one online camera stream advances.

HACS tracks published GitHub Releases. A commit on `main` without a versioned Release
is not a supported update.

## Roll back

1. Open **JOOAN NVR** in HACS.
2. Open the repository menu and select **Redownload**.
3. Select a previous available release.
4. Restart Home Assistant.
5. Validate integration startup and a camera stream.

Restore a Home Assistant backup if the required release is unavailable or a source
rollback is insufficient. Config entries and credentials are stored separately from
the source installed by HACS, although a full backup remains the safest fallback.

## Manual fallback

Download the versioned ZIP and `.sha256` file from the GitHub Release. Verify the
archive before extraction:

```bash
sha256sum -c jooan-nvr-vX.Y.Z.zip.sha256
```

Extract the archive into `/config`; it already contains the correct
`custom_components/jooan_nvr` path. Restart Home Assistant.

## Remove

1. Remove the JOOAN NVR config entry in **Settings → Devices & services**.
2. Remove JOOAN NVR from HACS.
3. Restart Home Assistant.

Removal does not modify the recorder, HDD, camera pairing, or recordings.
