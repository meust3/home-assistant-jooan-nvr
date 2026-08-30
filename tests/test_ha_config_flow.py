from __future__ import annotations

from unittest.mock import patch

import pytest
from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers.service_info.dhcp import DhcpServiceInfo
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.jooan_nvr.const import (
    CONF_DEVICE_ID,
    CONF_HTTP_PORT,
    CONF_MAC,
    DEFAULT_HTTP_PORT,
    DOMAIN,
    OPT_PREFERRED_STREAM,
    STREAM_MAIN,
    STREAM_SUB,
)
from custom_components.jooan_nvr.models import (
    Channel,
    ChannelStatus,
    NvrIdentity,
    ProbeResult,
)

DEVICE_ID = "0123456789abcdef01234567"
USER_DATA = {
    CONF_HOST: "192.168.77.10",
    CONF_HTTP_PORT: DEFAULT_HTTP_PORT,
    CONF_USERNAME: "admin",
    CONF_PASSWORD: "",
}
PROBE = ProbeResult(
    identity=NvrIdentity(DEVICE_ID, "Test NVR", "JA-8108-W", "3.0.6.0", 2),
    channels=(
        Channel(0, "CAM1", "IPCAM", "2.4.13", None, "Wireless"),
        Channel(1, "CAM2", "IPCAM", "2.4.13", None, "Wireless"),
    ),
    statuses={
        0: ChannelStatus(0, False, False, 0, "Connect Failed"),
        1: ChannelStatus(1, True, True, 39, "Connect success"),
    },
)


@pytest.mark.asyncio
async def test_user_config_flow_shows_detected_channels(hass: HomeAssistant) -> None:
    with (
        patch(
            "custom_components.jooan_nvr.config_flow.JooanConfigFlow._async_probe",
            return_value=PROBE,
        ),
        patch("custom_components.jooan_nvr.async_setup_entry", return_value=True),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": config_entries.SOURCE_USER}
        )
        assert result["type"] is FlowResultType.FORM
        result = await hass.config_entries.flow.async_configure(result["flow_id"], USER_DATA)
        assert result["type"] is FlowResultType.FORM
        assert result["step_id"] == "detected"
        assert result["description_placeholders"]["online_channels"] == "CAM2"
        result = await hass.config_entries.flow.async_configure(result["flow_id"], {})

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_DEVICE_ID] == DEVICE_ID
    assert result["data"][CONF_PASSWORD] == ""


@pytest.mark.asyncio
async def test_duplicate_config_flow_is_rejected(hass: HomeAssistant) -> None:
    MockConfigEntry(domain=DOMAIN, unique_id=DEVICE_ID, data=USER_DATA).add_to_hass(hass)
    with patch(
        "custom_components.jooan_nvr.config_flow.JooanConfigFlow._async_probe",
        return_value=PROBE,
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": config_entries.SOURCE_USER}
        )
        result = await hass.config_entries.flow.async_configure(result["flow_id"], USER_DATA)

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"


@pytest.mark.asyncio
async def test_dhcp_discovery_updates_existing_address(hass: HomeAssistant) -> None:
    test_mac = "9c:a3:aa:00:00:01"
    entry = MockConfigEntry(
        domain=DOMAIN,
        unique_id=DEVICE_ID,
        data={**USER_DATA, CONF_HOST: "192.168.77.99", CONF_MAC: test_mac},
    )
    entry.add_to_hass(hass)
    with patch.object(hass.config_entries, "async_schedule_reload") as schedule_reload:
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={"source": config_entries.SOURCE_DHCP},
            data=DhcpServiceInfo("192.168.77.10", "test-nvr", "9ca3aa000001"),
        )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"
    assert entry.data[CONF_HOST] == "192.168.77.10"
    schedule_reload.assert_called_once_with(entry.entry_id)


@pytest.mark.asyncio
async def test_reauthentication_updates_entry_without_duplicate(hass: HomeAssistant) -> None:
    entry = MockConfigEntry(
        domain=DOMAIN,
        unique_id=DEVICE_ID,
        data={**USER_DATA, CONF_PASSWORD: "old", CONF_DEVICE_ID: DEVICE_ID},
    )
    entry.add_to_hass(hass)
    with (
        patch(
            "custom_components.jooan_nvr.config_flow.JooanConfigFlow._async_probe",
            return_value=PROBE,
        ),
        patch.object(hass.config_entries, "async_reload", return_value=True),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN,
            context={
                "source": config_entries.SOURCE_REAUTH,
                "entry_id": entry.entry_id,
            },
            data=entry.data,
        )
        assert result["step_id"] == "reauth_confirm"
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {CONF_USERNAME: "admin", CONF_PASSWORD: ""},
        )

    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "reauth_successful"
    assert entry.data[CONF_PASSWORD] == ""
    assert len(hass.config_entries.async_entries(DOMAIN)) == 1


@pytest.mark.asyncio
async def test_stream_option_change_reloads_existing_entry(hass: HomeAssistant) -> None:
    entry = MockConfigEntry(
        domain=DOMAIN,
        unique_id=DEVICE_ID,
        data=USER_DATA,
        options={OPT_PREFERRED_STREAM: STREAM_SUB},
    )
    entry.add_to_hass(hass)

    result = await hass.config_entries.options.async_init(entry.entry_id)
    assert result["type"] is FlowResultType.FORM
    with patch.object(hass.config_entries, "async_reload", return_value=True) as reload_entry:
        result = await hass.config_entries.options.async_configure(
            result["flow_id"], {OPT_PREFERRED_STREAM: STREAM_MAIN}
        )
        await hass.async_block_till_done()

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert entry.options[OPT_PREFERRED_STREAM] == STREAM_MAIN
    reload_entry.assert_awaited_once_with(entry.entry_id)
