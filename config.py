import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
LOG_DIR = os.path.join(BASE_DIR, "logs")

# Flask config
SECRET_KEY = os.environ.get("FIREWALL_SECRET_KEY", "change-this-secret-key-in-production")
DEBUG = os.environ.get("FIREWALL_DEBUG", "False").lower() == "true"

# Admin credentials (default - change in production)
ADMIN_USERNAME = os.environ.get("FIREWALL_ADMIN_USER", "admin")
ADMIN_PASSWORD_HASH = None  # Set at runtime from data/admin.json

# Data files
BLOCKED_DOMAINS_FILE = os.path.join(DATA_DIR, "blocked_domains.txt")
BLOCKED_IPS_FILE = os.path.join(DATA_DIR, "blocked_ips.txt")
WHITELIST_FILE = os.path.join(DATA_DIR, "whitelist.txt")
ADMIN_FILE = os.path.join(DATA_DIR, "admin.json")

# Firewall settings
FIREWALL_INTERFACE = os.environ.get("FIREWALL_INTERFACE", "tun0")  # VPN interface
DNS_INTERCEPT_PORT = 53
WEB_PORT = int(os.environ.get("FIREWALL_WEB_PORT", 9450))
