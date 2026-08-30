from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.jooan_nvr import JooanRuntimeData
from custom_components.jooan_nvr.const import (
    CONF_DEVICE_ID,
    CONF_MAC,
    DOMAIN,
)
from custom_components.jooan_nvr.diagnostics import async_get_config_entry_diagnostics
from custom_components.jooan_nvr.models import Channel, ChannelStatus, NvrIdentity


@pytest.mark.asyncio
async def test_diagnostics_redact_credentials_and_identifiers(hass: HomeAssistant) -> None:
    secret_id = "sensitive-device-id"
    entry = MockConfigEntry(
        domain=DOMAIN,
        unique_id=secret_id,
        data={
            CONF_HOST: "192.168.77.10",
            CONF_USERNAME: "admin",
            CONF_PASSWORD: "secret-password",
            CONF_DEVICE_ID: secret_id,
            CONF_MAC: "9c:a3:aa:00:00:01",
        },
    )
    entry.add_to_hass(hass)
    coordinator = MagicMock()
    coordinator.data = {1: ChannelStatus(1, True, True, 39, "Connect success")}
    coordinator.last_update_success = True
    entry.runtime_data = JooanRuntimeData(
        client=MagicMock(),
        coordinator=coordinator,
        identity=NvrIdentity(secret_id, "Test NVR", "JA-8108-W", "3.0.6.0", 1),
        channels=(
            Channel(
                1,
                "CAM2",
                "IPCAM",
                "2.4.13",
                "9c:a3:a9:00:00:02",
                "Wireless",
            ),
        ),
        bridges=MagicMock(),
    )

    diagnostics = await async_get_config_entry_diagnostics(hass, entry)
    encoded = json.dumps(diagnostics)

    assert "secret-password" not in encoded
    assert "192.168.77.10" not in encoded
    assert "9c:a3:aa:00:00:01" not in encoded
    assert "9c:a3:a9:00:00:02" not in encoded
    assert secret_id not in encoded
