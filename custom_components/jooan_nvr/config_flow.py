"""UI configuration and DHCP discovery for JOOAN NVR."""

from __future__ import annotations

import re
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import (
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlowWithReload,
)
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import callback
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.selector import (
    NumberSelector,
    NumberSelectorConfig,
    NumberSelectorMode,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)
from homeassistant.helpers.service_info.dhcp import DhcpServiceInfo

from .client import (
    JooanAuthenticationError,
    JooanClient,
    JooanConnectionError,
    JooanProtocolError,
)
from .const import (
    CONF_DEVICE_ID,
    CONF_HTTP_PORT,
    CONF_KP2P_PORT,
    CONF_MAC,
    DEFAULT_HTTP_PORT,
    DEFAULT_KP2P_PORT,
    DEFAULT_STREAM,
    DEFAULT_USERNAME,
    DOMAIN,
    OPT_PREFERRED_STREAM,
    STREAM_MAIN,
    STREAM_SUB,
)
from .models import ProbeResult


def _normalise_mac(value: str | None) -> str | None:
    raw = re.sub(r"[^0-9A-Fa-f]", "", value or "")
    if len(raw) != 12:
        return None
    return ":".join(raw[index : index + 2] for index in range(0, 12, 2)).lower()


def _connection_schema(defaults: dict[str, Any]) -> vol.Schema:
    return vol.Schema(
        {
            vol.Required(CONF_HOST, default=defaults.get(CONF_HOST, "")): TextSelector(),
            vol.Required(
                CONF_HTTP_PORT,
                default=defaults.get(CONF_HTTP_PORT, DEFAULT_HTTP_PORT),
            ): NumberSelector(NumberSelectorConfig(min=1, max=65535, mode=NumberSelectorMode.BOX)),
            vol.Required(
                CONF_USERNAME,
                default=defaults.get(CONF_USERNAME, DEFAULT_USERNAME),
            ): TextSelector(),
            vol.Required(
                CONF_PASSWORD,
                default=defaults.get(CONF_PASSWORD, ""),
            ): TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD)),
        }
    )


class JooanConfigFlow(ConfigFlow, domain=DOMAIN):
    """Configure a locally validated JOOAN recorder."""

    VERSION = 1
    MINOR_VERSION = 1

    def __init__(self) -> None:
        self._pending_data: dict[str, Any] | None = None
        self._probe: ProbeResult | None = None
        self._discovered_host: str | None = None
        self._discovered_mac: str | None = None

    async def _async_probe(self, data: dict[str, Any]) -> ProbeResult:
        session = async_get_clientsession(self.hass)
        client = JooanClient(
            session,
            data[CONF_HOST],
            int(data[CONF_HTTP_PORT]),
            data[CONF_USERNAME],
            data.get(CONF_PASSWORD, ""),
        )
        return await client.async_probe()

    async def _async_validate(self, data: dict[str, Any]) -> tuple[ProbeResult | None, str | None]:
        try:
            return await self._async_probe(data), None
        except JooanAuthenticationError:
            return None, "invalid_auth"
        except JooanConnectionError:
            return None, "cannot_connect"
        except JooanProtocolError:
            return None, "not_jooan_nvr"

    async def _async_prepare_entry(
        self, data: dict[str, Any], probe: ProbeResult
    ) -> ConfigFlowResult:
        data = {
            **data,
            CONF_HTTP_PORT: int(data[CONF_HTTP_PORT]),
            CONF_KP2P_PORT: DEFAULT_KP2P_PORT,
            CONF_PASSWORD: data.get(CONF_PASSWORD, ""),
            CONF_DEVICE_ID: probe.identity.device_id,
        }
        if self._discovered_mac:
            data[CONF_MAC] = self._discovered_mac
        await self.async_set_unique_id(probe.identity.device_id)
        self._abort_if_unique_id_configured(
            updates={
                CONF_HOST: data[CONF_HOST],
                **({CONF_MAC: self._discovered_mac} if self._discovered_mac else {}),
            }
        )
        self._pending_data = data
        self._probe = probe
        return await self.async_step_detected()

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Handle manual setup."""
        errors: dict[str, str] = {}
        if user_input is not None:
            probe, error = await self._async_validate(user_input)
            if probe:
                return await self._async_prepare_entry(user_input, probe)
            errors["base"] = error or "unknown"
        return self.async_show_form(
            step_id="user",
            data_schema=_connection_schema(user_input or {}),
            errors=errors,
        )

    async def async_step_dhcp(self, discovery_info: DhcpServiceInfo) -> ConfigFlowResult:
        """Handle the proven recorder OUI and registered-device DHCP discovery."""
        self._discovered_host = discovery_info.ip
        self._discovered_mac = _normalise_mac(discovery_info.macaddress)
        if self._discovered_mac:
            for entry in self.hass.config_entries.async_entries(DOMAIN):
                if entry.data.get(CONF_MAC) != self._discovered_mac:
                    continue
                if entry.data.get(CONF_HOST) != discovery_info.ip:
                    self.hass.config_entries.async_update_entry(
                        entry,
                        data={**entry.data, CONF_HOST: discovery_info.ip},
                    )
                    self.hass.config_entries.async_schedule_reload(entry.entry_id)
                return self.async_abort(reason="already_configured")
        self.context["title_placeholders"] = {"name": discovery_info.hostname or discovery_info.ip}
        return await self.async_step_discovery_credentials()

    async def async_step_discovery_credentials(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Collect local credentials for a DHCP-discovered recorder."""
        errors: dict[str, str] = {}
        defaults = {
            CONF_HOST: self._discovered_host,
            CONF_HTTP_PORT: DEFAULT_HTTP_PORT,
            CONF_USERNAME: DEFAULT_USERNAME,
            CONF_PASSWORD: "",
        }
        if user_input is not None:
            data = {**defaults, **user_input}
            probe, error = await self._async_validate(data)
            if probe:
                return await self._async_prepare_entry(data, probe)
            errors["base"] = error or "unknown"
            defaults.update(user_input)
        return self.async_show_form(
            step_id="discovery_credentials",
            data_schema=_connection_schema(defaults),
            errors=errors,
            description_placeholders={"host": self._discovered_host or ""},
        )

    async def async_step_detected(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Show validated model and channels before saving."""
        if self._pending_data is None or self._probe is None:
            return self.async_abort(reason="cannot_connect")
        if user_input is not None:
            return self.async_create_entry(
                title=self._probe.identity.name,
                data=self._pending_data,
                options={OPT_PREFERRED_STREAM: DEFAULT_STREAM},
            )
        online_names = [
            channel.name
            for channel in self._probe.channels
            if self._probe.statuses.get(channel.channel_id)
            and self._probe.statuses[channel.channel_id].online
        ]
        return self.async_show_form(
            step_id="detected",
            data_schema=vol.Schema({}),
            description_placeholders={
                "model": self._probe.identity.model,
                "channel_count": str(len(self._probe.channels)),
                "online_channels": ", ".join(online_names) or "None",
            },
        )

    async def async_step_reauth(self, entry_data: dict[str, Any]) -> ConfigFlowResult:
        """Begin reauthentication after a credential failure."""
        del entry_data
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Validate and replace local credentials."""
        entry = self._get_reauth_entry()
        errors: dict[str, str] = {}
        defaults = {
            CONF_USERNAME: entry.data.get(CONF_USERNAME, DEFAULT_USERNAME),
            CONF_PASSWORD: "",
        }
        if user_input is not None:
            data = {**entry.data, **user_input}
            probe, error = await self._async_validate(data)
            if probe:
                await self.async_set_unique_id(probe.identity.device_id)
                self._abort_if_unique_id_mismatch()
                return self.async_update_reload_and_abort(
                    entry,
                    data_updates={
                        CONF_USERNAME: data[CONF_USERNAME],
                        CONF_PASSWORD: data.get(CONF_PASSWORD, ""),
                    },
                )
            errors["base"] = error or "unknown"
        schema = vol.Schema(
            {
                vol.Required(CONF_USERNAME, default=defaults[CONF_USERNAME]): TextSelector(),
                vol.Required(CONF_PASSWORD, default=""): TextSelector(
                    TextSelectorConfig(type=TextSelectorType.PASSWORD)
                ),
            }
        )
        return self.async_show_form(step_id="reauth_confirm", data_schema=schema, errors=errors)

    async def async_step_reconfigure(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        """Allow the address and local credentials to be changed."""
        entry = self._get_reconfigure_entry()
        errors: dict[str, str] = {}
        defaults = {**entry.data, CONF_PASSWORD: ""}
        if user_input is not None:
            probe, error = await self._async_validate(user_input)
            if probe:
                await self.async_set_unique_id(probe.identity.device_id)
                self._abort_if_unique_id_mismatch()
                return self.async_update_reload_and_abort(
                    entry,
                    data_updates={
                        CONF_HOST: user_input[CONF_HOST],
                        CONF_HTTP_PORT: int(user_input[CONF_HTTP_PORT]),
                        CONF_USERNAME: user_input[CONF_USERNAME],
                        CONF_PASSWORD: user_input.get(CONF_PASSWORD, ""),
                    },
                )
            errors["base"] = error or "unknown"
            defaults.update(user_input)
        return self.async_show_form(
            step_id="reconfigure",
            data_schema=_connection_schema(defaults),
            errors=errors,
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):  # type: ignore[no-untyped-def]
        """Return the stream-quality options flow."""
        return JooanOptionsFlow()


class JooanOptionsFlow(OptionsFlowWithReload):
    """Configure the default camera quality without duplicate entities."""

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        """Manage integration options."""
        if user_input is not None:
            return self.async_create_entry(data=user_input)
        schema = vol.Schema(
            {
                vol.Required(
                    OPT_PREFERRED_STREAM,
                    default=self.config_entry.options.get(OPT_PREFERRED_STREAM, DEFAULT_STREAM),
                ): SelectSelector(
                    SelectSelectorConfig(
                        options=[STREAM_MAIN, STREAM_SUB],
                        mode=SelectSelectorMode.DROPDOWN,
                        translation_key=OPT_PREFERRED_STREAM,
                    )
                )
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema)
