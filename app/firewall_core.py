"""
Firewall Core Module
Domain blocking, IP blocking and whitelist management logic.
"""
import os
import threading
import logging
from datetime import datetime

logger = logging.getLogger("firewall")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")

BLOCKED_DOMAINS_FILE = os.path.join(DATA_DIR, "blocked_domains.txt")
BLOCKED_IPS_FILE = os.path.join(DATA_DIR, "blocked_ips.txt")
WHITELIST_FILE = os.path.join(DATA_DIR, "whitelist.txt")


class FirewallCore:
    """Core firewall class - domain, IP blocking and whitelist management."""

    def __init__(self):
        self._lock = threading.Lock()
        self.blocked_domains = set()
        self.blocked_ips = set()
        self.whitelist = set()
        self.stats = {
            "total_blocked": 0,
            "domains_blocked_count": 0,
            "ips_blocked_count": 0,
            "last_updated": None,
        }
        self._ensure_data_files()
        self.load_all()

    def _ensure_data_files(self):
        """Check data files exist, create if not."""
        os.makedirs(DATA_DIR, exist_ok=True)
        for filepath in [BLOCKED_DOMAINS_FILE, BLOCKED_IPS_FILE, WHITELIST_FILE]:
            if not os.path.exists(filepath):
                open(filepath, "w").close()

    # ─────────────────────────────────────────────
    # LOAD / SAVE
    # ─────────────────────────────────────────────

    def load_all(self):
        """Load all data files."""
        self.blocked_domains = self._load_file(BLOCKED_DOMAINS_FILE)
        self.blocked_ips = self._load_file(BLOCKED_IPS_FILE)
        self.whitelist = self._load_file(WHITELIST_FILE)
        self.stats["last_updated"] = datetime.now().isoformat()
        logger.info(
            f"Loaded: {len(self.blocked_domains)} domains, "
            f"{len(self.blocked_ips)} IPs, {len(self.whitelist)} whitelist"
        )

    def _load_file(self, filepath):
        """Read lines from file, return as set."""
        items = set()
        try:
            with open(filepath, "r") as f:
                for line in f:
                    line = line.strip().lower()
                    if line and not line.startswith("#"):
                        items.add(line)
        except FileNotFoundError:
            pass
        return items

    def _save_file(self, filepath, items):
        """Write set to file."""
        with self._lock:
            with open(filepath, "w") as f:
                for item in sorted(items):
                    f.write(item + "\n")
        self.stats["last_updated"] = datetime.now().isoformat()

    # ─────────────────────────────────────────────
    # DOMAIN BLOCKING
    # ─────────────────────────────────────────────

    def block_domain(self, domain):
        """Block a single domain."""
        domain = domain.strip().lower()
        if not domain:
            return False, "Domain cannot be empty"
        if domain in self.whitelist:
            return False, f"{domain} is in whitelist, remove it first"
        self.blocked_domains.add(domain)
        self._save_file(BLOCKED_DOMAINS_FILE, self.blocked_domains)
        self.stats["domains_blocked_count"] = len(self.blocked_domains)
        logger.info(f"Domain blocked: {domain}")
        return True, f"{domain} blocked"

    def block_domains_list(self, domains):
        """Block a list of domains."""
        added = []
        skipped = []
        for domain in domains:
            domain = domain.strip().lower()
            if not domain or domain.startswith("#"):
                continue
            if domain in self.whitelist:
                skipped.append(domain)
                continue
            self.blocked_domains.add(domain)
            added.append(domain)
        self._save_file(BLOCKED_DOMAINS_FILE, self.blocked_domains)
        self.stats["domains_blocked_count"] = len(self.blocked_domains)
        return added, skipped

    def block_domains_from_file(self, file_content):
        """Block domains from file content."""
        domains = [line.strip() for line in file_content.splitlines() if line.strip()]
        return self.block_domains_list(domains)

    def unblock_domain(self, domain):
        """Unblock a domain."""
        domain = domain.strip().lower()
        if domain in self.blocked_domains:
            self.blocked_domains.discard(domain)
            self._save_file(BLOCKED_DOMAINS_FILE, self.blocked_domains)
            self.stats["domains_blocked_count"] = len(self.blocked_domains)
            logger.info(f"Domain unblocked: {domain}")
            return True, f"{domain} unblocked"
        return False, f"{domain} not found in block list"

    def is_domain_blocked(self, domain):
        """Check if domain is blocked (with subdomain support)."""
        domain = domain.strip().lower()
        if domain in self.whitelist:
            return False
        if domain in self.blocked_domains:
            return True
        # Subdomain check: if example.com is blocked, sub.example.com is also blocked
        parts = domain.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self.blocked_domains:
                return True
        return False

    # ─────────────────────────────────────────────
    # IP BLOCKING
    # ─────────────────────────────────────────────

    def block_ip(self, ip):
        """Block a single IP."""
        ip = ip.strip()
        if not ip:
            return False, "IP cannot be empty"
        if ip in self.whitelist:
            return False, f"{ip} is in whitelist, remove it first"
        self.blocked_ips.add(ip)
        self._save_file(BLOCKED_IPS_FILE, self.blocked_ips)
        self.stats["ips_blocked_count"] = len(self.blocked_ips)
        logger.info(f"IP blocked: {ip}")
        return True, f"{ip} blocked"

    def block_ips_list(self, ips):
        """Block a list of IPs."""
        added = []
        skipped = []
        for ip in ips:
            ip = ip.strip()
            if not ip or ip.startswith("#"):
                continue
            if ip in self.whitelist:
                skipped.append(ip)
                continue
            self.blocked_ips.add(ip)
            added.append(ip)
        self._save_file(BLOCKED_IPS_FILE, self.blocked_ips)
        self.stats["ips_blocked_count"] = len(self.blocked_ips)
        return added, skipped

    def block_ips_from_file(self, file_content):
        """Block IPs from file content."""
        ips = [line.strip() for line in file_content.splitlines() if line.strip()]
        return self.block_ips_list(ips)

    def unblock_ip(self, ip):
        """Unblock an IP."""
        ip = ip.strip()
        if ip in self.blocked_ips:
            self.blocked_ips.discard(ip)
            self._save_file(BLOCKED_IPS_FILE, self.blocked_ips)
            self.stats["ips_blocked_count"] = len(self.blocked_ips)
            logger.info(f"IP unblocked: {ip}")
            return True, f"{ip} unblocked"
        return False, f"{ip} not found in block list"

    def is_ip_blocked(self, ip):
        """Check if IP is blocked."""
        ip = ip.strip()
        if ip in self.whitelist:
            return False
        return ip in self.blocked_ips

    # ─────────────────────────────────────────────
    # WHITELIST
    # ─────────────────────────────────────────────

    def add_to_whitelist(self, item):
        """Add a single item to whitelist."""
        item = item.strip().lower()
        if not item:
            return False, "Item cannot be empty"
        # When added to whitelist, remove from block lists
        self.blocked_domains.discard(item)
        self.blocked_ips.discard(item)
        self.whitelist.add(item)
        self._save_file(WHITELIST_FILE, self.whitelist)
        self._save_file(BLOCKED_DOMAINS_FILE, self.blocked_domains)
        self._save_file(BLOCKED_IPS_FILE, self.blocked_ips)
        logger.info(f"Added to whitelist: {item}")
        return True, f"{item} added to whitelist"

    def add_to_whitelist_list(self, items):
        """Add a list to whitelist."""
        added = []
        for item in items:
            item = item.strip().lower()
            if not item or item.startswith("#"):
                continue
            self.blocked_domains.discard(item)
            self.blocked_ips.discard(item)
            self.whitelist.add(item)
            added.append(item)
        self._save_file(WHITELIST_FILE, self.whitelist)
        self._save_file(BLOCKED_DOMAINS_FILE, self.blocked_domains)
        self._save_file(BLOCKED_IPS_FILE, self.blocked_ips)
        return added

    def add_to_whitelist_from_file(self, file_content):
        """Add to whitelist from file content."""
        items = [line.strip() for line in file_content.splitlines() if line.strip()]
        return self.add_to_whitelist_list(items)

    def remove_from_whitelist(self, item):
        """Remove from whitelist."""
        item = item.strip().lower()
        if item in self.whitelist:
            self.whitelist.discard(item)
            self._save_file(WHITELIST_FILE, self.whitelist)
            logger.info(f"Removed from whitelist: {item}")
            return True, f"{item} removed from whitelist"
        return False, f"{item} not found in whitelist"

    # ─────────────────────────────────────────────
    # STATISTICS
    # ─────────────────────────────────────────────

    def get_stats(self):
        """Return statistics."""
        return {
            "blocked_domains_count": len(self.blocked_domains),
            "blocked_ips_count": len(self.blocked_ips),
            "whitelist_count": len(self.whitelist),
            "total_rules": len(self.blocked_domains) + len(self.blocked_ips),
            "last_updated": self.stats["last_updated"],
        }

    def get_all_blocked_domains(self):
        """Return all blocked domains."""
        return sorted(self.blocked_domains)

    def get_all_blocked_ips(self):
        """Return all blocked IPs."""
        return sorted(self.blocked_ips)

    def get_all_whitelist(self):
        """Return all whitelist items."""
        return sorted(self.whitelist)


# Singleton instance
firewall = FirewallCore()
