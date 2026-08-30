from __future__ import annotations

import pytest

pytest_plugins = "pytest_homeassistant_custom_component"


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):  # type: ignore[no-untyped-def]
    """Enable loading this repository's custom integration in Home Assistant tests."""
    yield
