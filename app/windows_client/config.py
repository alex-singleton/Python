"""
VPN Client konfiqurasiyası.
"""

# Server ünvanı - dəyişdirin
SERVER_URL = "http://94.20.247.39:9450"

# API endpoint-lər
API_LOGIN = "/api/v1/login"
API_CONNECT = "/api/v1/connect"
API_DISCONNECT = "/api/v1/disconnect"
API_STATUS = "/api/v1/status"
API_PING = "/api/v1/ping"

# Client parametrləri
APP_NAME = "VPN Client"
APP_VERSION = "1.0.0"
AUTO_RECONNECT = True
RECONNECT_INTERVAL = 5  # saniyə
STATUS_CHECK_INTERVAL = 10  # saniyə
