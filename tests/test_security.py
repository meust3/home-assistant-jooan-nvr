from jooan_discovery.security import REDACTED, redact, redact_url


def test_redacts_url_credentials_and_legacy_paths() -> None:
    assert redact_url("rtsp://admin:hunter2@192.168.1.2/ch0_0.264") == (
        "rtsp://admin:***@192.168.1.2/ch0_0.264"
    )
    output = redact(
        {
            "password": "hunter2",
            "uri": "rtsp://admin:hunter2@host/live",
            "path": "/user=admin_password=hunter2_channel=1_stream=0.sdp",
            "Authorization": "Digest secret-material",
        }
    )
    assert output["password"] == REDACTED
    assert "hunter2" not in repr(output)
    assert output["Authorization"] == REDACTED


def test_does_not_redact_harmless_values() -> None:
    value = {"model": "JOOAN NVR", "channel": 1}
    assert redact(value) == value


def test_redacts_camera_cloud_identifiers_and_nonces() -> None:
    value = {
        "N1": {"Devid": "IPCAM-secret-id", "Eseeid": "2555755280", "Nonce": "nonce-value"},
        "HWID": "hardware-id",
        "ID": 3,
    }
    output = redact(value)
    assert output["N1"] == {"Devid": "***", "Eseeid": "***", "Nonce": "***"}
    assert output["HWID"] == "***"
    assert output["ID"] == 3
    text = "{'Devid': 'IPCAM-secret-id', 'Eseeid': '2555755280', 'Nonce': 'nonce-value'}"
    assert "IPCAM-secret-id" not in redact(text)
    assert "2555755280" not in redact(text)
    assert "nonce-value" not in redact(text)
