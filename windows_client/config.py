"""
VPN Client konfiqurasiyasi.
"""

# Server unvani
SERVER_URL = "http://94.20.247.39:9450"

# API endpoint-ler (Rust backend-e uygun)
API_LOGIN = "/api/v1/auth/login"
API_ME = "/api/v1/auth/me"
API_VPN_PEERS = "/api/v1/vpn/peers"
API_VPN_STATUS = "/api/v1/vpn/status"
API_HEALTH = "/api/v1/health"

# Client parametrleri
APP_NAME = "VPN Client"
APP_VERSION = "2.0.0"
AUTO_RECONNECT = True
RECONNECT_INTERVAL = 5
STATUS_CHECK_INTERVAL = 10

