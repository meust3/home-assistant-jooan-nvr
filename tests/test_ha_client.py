from __future__ import annotations

from typing import Any

import pytest

from custom_components.jooan_nvr.client import (
    JooanAuthenticationError,
    JooanClient,
    JooanConnectionError,
)


class _Response:
    def __init__(self, status: int, value: Any) -> None:
        self.status = status
        self.value = value

    async def __aenter__(self):  # type: ignore[no-untyped-def]
        return self

    async def __aexit__(self, *args):  # type: ignore[no-untyped-def]
        return None

    async def json(self, *, content_type=None):  # type: ignore[no-untyped-def]
        del content_type
        return self.value


class _Session:
    def __init__(self, responses: dict[str, _Response | Exception]) -> None:
        self.responses = responses
        self.request_kwargs: list[dict[str, Any]] = []

    def get(self, url, **kwargs):  # type: ignore[no-untyped-def]
        self.request_kwargs.append(kwargs)
        result = self.responses[url.path]
        if isinstance(result, Exception):
            raise result
        return result


def _device() -> dict[str, str]:
    return {
        "UID": "sensitive-cloud-device-id",
        "HWID": "sensitive-hwid",
        "DeviceModel": "JA-8108-W",
        "DeviceName": "Test NVR",
        "FWVersion": "3.0.6.0",
        "MAX_CHN": "2",
        "SupportWeb": "http://d.jooan.cc",
    }


@pytest.mark.asyncio
async def test_client_enumerates_channel_titles_and_streams() -> None:
    session = _Session(
        {
            "/netsdk/Stat/DeviceInfo": _Response(200, _device()),
            "/netsdk/Channel/IPCamInfo": _Response(
                200,
                [
                    {
                        "ID": 0,
                        "Modelname": "IPCAM",
                        "SWVersion": "2.4.13",
                        "MACAddr": "9c:a3:a9:00:00:01",
                        "InterfaceType": "Wireless",
                    },
                    {"ID": 1, "Modelname": "IPCAM"},
                ],
            ),
            "/netsdk/Stream": _Response(
                200,
                {"Title": [{"ID": 0, "Text": "Front"}, {"ID": 1, "Text": "Garage"}]},
            ),
            "/netsdk/Stream/Encode": _Response(
                200,
                [
                    {
                        "ID": 0,
                        "Stream": [
                            {
                                "ID": 0,
                                "Name": "MainStream",
                                "CodingFmt": "H.265+",
                                "Format": "2304x1296",
                                "Framerate": "15fps",
                                "BitrateValue": "2Mbps",
                            },
                            {
                                "ID": 1,
                                "Name": "SubStream",
                                "CodingFmt": "H.265+",
                                "Format": "640x360",
                                "Framerate": "15fps",
                            },
                        ],
                    }
                ],
            ),
        }
    )
    client = JooanClient(session, "192.168.77.10", 80, "admin", "")  # type: ignore[arg-type]

    identity = await client.async_get_identity()
    channels = await client.async_get_channels(identity.channel_count)

    assert identity.model == "JA-8108-W"
    assert identity.device_id not in {"sensitive-cloud-device-id", "sensitive-hwid"}
    assert session.request_kwargs[0]["headers"]["Authorization"] == "Basic YWRtaW46"
    assert "auth" not in session.request_kwargs[0]
    assert [channel.name for channel in channels] == ["Front", "Garage"]
    assert channels[0].profiles[0].resolution == "2304x1296"
    assert channels[0].profiles[1].stream_id == 1


@pytest.mark.asyncio
async def test_client_authentication_failure() -> None:
    client = JooanClient(
        _Session({"/netsdk/Stat/DeviceInfo": _Response(401, {})}),  # type: ignore[arg-type]
        "192.168.77.10",
        80,
        "admin",
        "wrong",
    )

    with pytest.raises(JooanAuthenticationError):
        await client.async_get_identity()


@pytest.mark.asyncio
async def test_client_connection_timeout() -> None:
    client = JooanClient(
        _Session({"/netsdk/Stat/DeviceInfo": TimeoutError()}),  # type: ignore[arg-type]
        "192.168.77.10",
        80,
        "admin",
        "",
    )

    with pytest.raises(JooanConnectionError):
        await client.async_get_identity()
