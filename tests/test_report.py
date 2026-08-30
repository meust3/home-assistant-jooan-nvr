from __future__ import annotations

import json

from jooan_discovery.models import HostRecord, RtspEvidence, ScanResult
from jooan_discovery.report import write_reports


def test_reports_are_written_and_credentials_are_redacted(tmp_path) -> None:
    result = ScanResult(
        schema_version=1,
        started_at="2026-08-30T00:00:00+00:00",
        completed_at="2026-08-30T00:01:00+00:00",
        hosts=[
            HostRecord(
                address="192.168.77.2",
                score=80,
                confidence="HIGH CONFIDENCE",
                rtsp=[
                    RtspEvidence(
                        port=554,
                        path="/user=admin_password=hunter2_channel=1_stream=0.sdp",
                        status=200,
                        uri="rtsp://admin:hunter2@192.168.77.2/live",
                        confirmed=True,
                    )
                ],
            )
        ],
    )
    paths = write_reports(result, tmp_path)
    assert all(path.exists() for path in paths)
    combined = "".join(path.read_text(encoding="utf-8") for path in paths)
    assert "hunter2" not in combined
    assert "***" in combined
    assert json.loads((tmp_path / "device-report.json").read_text())["candidates"]
