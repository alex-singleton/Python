"""
VPN Client configuration.
"""

# Server address - change this
SERVER_URL = "http://94.20.247.39:9450"

# API endpoints
API_LOGIN = "/api/v1/login"
API_CONNECT = "/api/v1/connect"
API_DISCONNECT = "/api/v1/disconnect"
API_STATUS = "/api/v1/status"
API_PING = "/api/v1/ping"

# Client parameters
APP_NAME = "VPN Client"
APP_VERSION = "1.0.0"
AUTO_RECONNECT = True
RECONNECT_INTERVAL = 5  # seconds
STATUS_CHECK_INTERVAL = 10  # seconds
