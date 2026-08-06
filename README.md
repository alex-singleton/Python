# VPN Firewall Panel

Python-based VPN firewall system. Domain blocking (including HTTPS), IP blocking, whitelist management and web admin panel.

## Features

- **Domain Blocking** - HTTP + HTTPS (TLS SNI string match) + DNS queries
- **IP Blocking** - iptables ingress/egress blocking, CIDR support
- **Whitelist** - Allowed domain/IP list (overrides block rules)
- **Web Panel** - Bootstrap 5 based responsive admin interface
- **Admin Login** - Password change, session management
- **Subdomain Support** - Blocking `example.com` also blocks `sub.example.com`
- **File Upload** - Bulk import from TXT files
- **Systemd Service** - Automatic start and stop

## Requirements

- Linux (Ubuntu/Debian recommended)
- Python 3.8+
- iptables
- Root privileges (for iptables)

## Quick Installation

```bash
# Clone the repo
git clone <repo-url> /opt/firewall
cd /opt/firewall

# Automatic installation
sudo bash install.sh
```

## Manual Installation

```bash
# Required packages
sudo apt install python3 python3-pip python3-venv iptables

# Virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Data directories
mkdir -p data logs

# Run
sudo python3 run.py
```

## Usage

### Starting

```bash
# Standard (port 9450)
sudo python3 run.py

# Custom port
sudo python3 run.py --port 8080

# Debug mode
sudo python3 run.py --debug

# Without engine (panel only)
python3 run.py --no-engine
```

### With Systemd

```bash
sudo systemctl start firewall      # Start
sudo systemctl stop firewall       # Stop
sudo systemctl restart firewall    # Restart
sudo systemctl status firewall     # Status
sudo journalctl -u firewall -f     # Logs
```

### Web Panel

Open `http://server-ip:9450` in your browser.

**Default credentials:**
- Username: `admin`
- Password: `admin123`

> Make sure to change the password after first login!

## Blocking Methods

### Domain Blocking (including HTTPS)

Three levels of blocking:
1. **TLS SNI** - Inspects Server Name Indication in HTTPS traffic (port 443)
2. **HTTP Host** - Inspects Host header in HTTP traffic (port 80)
3. **DNS** - Blocks DNS queries for the domain name (port 53)

### IP Blocking

- Blocks both incoming and outgoing traffic with iptables `DROP` rule
- CIDR notation supported (e.g. `192.168.1.0/24`)

### Whitelist

- Items added to whitelist are automatically removed from block lists
- Whitelist rules are added as `ACCEPT` at the beginning of the chain
- Takes priority over block rules

## Project Structure

```
Firewall/
├── run.py                  # Main startup script
├── config.py               # Configuration
├── requirements.txt        # Python packages
├── install.sh              # Installation script
├── firewall.service        # Systemd service file
├── app/
│   ├── __init__.py         # Flask app factory
│   ├── models.py           # Admin model
│   ├── firewall_core.py    # Blocking logic
│   ├── firewall_engine.py  # iptables integration
│   ├── routes/
│   │   ├── auth.py         # Login/logout
│   │   ├── dashboard.py    # Dashboard page
│   │   ├── domains.py      # Domain blocking
│   │   ├── ips.py          # IP blocking
│   │   └── whitelist.py    # Whitelist
│   ├── templates/          # HTML templates
│   └── static/css/         # CSS
├── data/                   # Block lists
│   ├── blocked_domains.txt
│   ├── blocked_ips.txt
│   ├── whitelist.txt
│   └── admin.json
└── logs/                   # Log files
    └── firewall.log
```

## API Usage Examples

### Block List File Format

```text
# Domains to block (one domain per line)
# This is a comment line - will be skipped
example.com
malware-site.net
tracking.io
ads.network.com
```

### IP List File Format

```text
# IPs to block
192.168.1.100
10.0.0.50
172.16.0.0/16
# Botnet IPs
203.0.113.0/24
```

## Security Notes

- Make sure to change the default password
- Set the `FIREWALL_SECRET_KEY` environment variable
- Allow panel access only from trusted networks
- Run behind HTTPS (nginx reverse proxy) if possible
- Check logs regularly

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FIREWALL_SECRET_KEY` | Flask secret key | `change-this-secret-key-in-production` |
| `FIREWALL_DEBUG` | Debug mode | `False` |
| `FIREWALL_INTERFACE` | VPN interface | `tun0` |
| `FIREWALL_WEB_PORT` | Web panel port | `9450` |
| `FIREWALL_ADMIN_USER` | Admin username | `admin` |

## License

MIT License
