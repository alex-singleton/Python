"""
VPN Client konfiqurasiyasi.
"""

# Server unvani - deyisdirin
SERVER_URL = "http://94.20.247.39:9450"

# API endpoint-ler
API_LOGIN = "/api/v1/login"
API_CONNECT = "/api/v1/connect"
API_DISCONNECT = "/api/v1/disconnect"
API_STATUS = "/api/v1/status"
API_PING = "/api/v1/ping"

# Client parametrleri
APP_NAME = "VPN Client"
APP_VERSION = "1.0.0"
AUTO_RECONNECT = True
RECONNECT_INTERVAL = 5
STATUS_CHECK_INTERVAL = 10
