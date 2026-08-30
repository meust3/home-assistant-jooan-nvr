"""Constants for the JOOAN NVR integration."""

from datetime import timedelta

from homeassistant.const import Platform

DOMAIN = "jooan_nvr"

PLATFORMS = [Platform.CAMERA, Platform.BINARY_SENSOR]

CONF_DEVICE_ID = "device_id"
CONF_MAC = "mac"
CONF_HTTP_PORT = "http_port"
CONF_KP2P_PORT = "kp2p_port"

DEFAULT_HTTP_PORT = 80
DEFAULT_KP2P_PORT = 10000
DEFAULT_USERNAME = "admin"

OPT_PREFERRED_STREAM = "preferred_stream"
STREAM_MAIN = "main"
STREAM_SUB = "sub"
DEFAULT_STREAM = STREAM_SUB
STREAM_IDS = {STREAM_MAIN: 0, STREAM_SUB: 1}

UPDATE_INTERVAL = timedelta(seconds=10)
REQUEST_TIMEOUT = 6.0

MANUFACTURER = "JOOAN"
TRANSPORT = "local_kp2p"
