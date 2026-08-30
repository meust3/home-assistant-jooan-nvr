from jooan_discovery.fingerprint import score_host
from jooan_discovery.models import HostRecord, HttpEvidence, RtspEvidence, ServiceEvidence


def test_ports_alone_do_not_identify_nvr() -> None:
    host = HostRecord(
        address="192.168.77.10",
        services=[ServiceEvidence(port=80), ServiceEvidence(port=554), ServiceEvidence(port=34567)],
    )
    score_host(host)
    assert host.score == 0
    assert host.confidence == "NOT SUPPORTED"


def test_explicit_identity_and_working_pattern_are_confirmed() -> None:
    host = HostRecord(
        address="192.168.77.20",
        http=[HttpEvidence(url="http://192.168.77.20/", status=200, title="JOOAN EseeCloud NVR")],
        rtsp=[
            RtspEvidence(
                port=554,
                path="/ch0_0.264",
                status=200,
                codec="H264",
                confirmed=True,
            )
        ],
    )
    score_host(host)
    assert host.score == 100
    assert host.confidence == "CONFIRMED"
    assert any("EseeCloud-style" in reason for reason in host.score_reasons)


def test_local_esee_recorder_assets_produce_high_confidence() -> None:
    host = HostRecord(
        address="192.168.77.10",
        http=[
            HttpEvidence(
                url="http://192.168.77.10/",
                status=200,
                indicators=["EseeLogin", "NVR163", "KP2P local web module"],
            )
        ],
    )
    score_host(host)
    assert host.score >= 65
    assert host.confidence == "HIGH CONFIDENCE"
