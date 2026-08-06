"""
Firewall Engine - iptables integration and DNS/SNI intercept.
Blocks HTTPS traffic via SNI (Server Name Indication).
Blocks HTTP traffic via Host header.
Blocks IPs via iptables.
"""
import subprocess
import logging
import os
import threading
from app.firewall_core import firewall

logger = logging.getLogger("firewall.engine")

IPTABLES = "/sbin/iptables"
IP6TABLES = "/sbin/ip6tables"


class FirewallEngine:
    """iptables and system-level firewall management."""

    def __init__(self, interface="tun0"):
        self.interface = interface
        self.chain_name = "FIREWALL_BLOCK"
        self._lock = threading.Lock()

    # ─────────────────────────────────────────────
    # iptables CHAIN MANAGEMENT
    # ─────────────────────────────────────────────

    def setup_chains(self):
        """Create firewall chains."""
        try:
            # Create custom chain (if not exists)
            self._run_iptables(["-N", self.chain_name], ignore_errors=True)
            # Redirect from FORWARD chain to custom chain
            self._run_iptables(["-C", "FORWARD", "-j", self.chain_name], ignore_errors=True)
            if self._last_returncode != 0:
                self._run_iptables(["-I", "FORWARD", "1", "-j", self.chain_name])
            logger.info("Firewall chains set up")
            return True
        except Exception as e:
            logger.error(f"Chain setup failed: {e}")
            return False

    def cleanup_chains(self):
        """Clean up firewall chains."""
        try:
            self._run_iptables(["-D", "FORWARD", "-j", self.chain_name], ignore_errors=True)
            self._run_iptables(["-F", self.chain_name], ignore_errors=True)
            self._run_iptables(["-X", self.chain_name], ignore_errors=True)
            logger.info("Firewall chains cleaned up")
            return True
        except Exception as e:
            logger.error(f"Chain cleanup failed: {e}")
            return False

    # ─────────────────────────────────────────────
    # IP BLOCKING (iptables)
    # ─────────────────────────────────────────────

    def apply_ip_block(self, ip):
        """Block an IP with iptables."""
        with self._lock:
            # Check if already exists
            check = self._run_iptables(
                ["-C", self.chain_name, "-d", ip, "-j", "DROP"],
                ignore_errors=True
            )
            if self._last_returncode == 0:
                return True  # Already exists

            result = self._run_iptables(
                ["-A", self.chain_name, "-d", ip, "-j", "DROP"]
            )
            # Also block source IP
            self._run_iptables(
                ["-A", self.chain_name, "-s", ip, "-j", "DROP"]
            )
            logger.info(f"iptables: IP blocked - {ip}")
            return result

    def remove_ip_block(self, ip):
        """Remove IP block from iptables."""
        with self._lock:
            self._run_iptables(
                ["-D", self.chain_name, "-d", ip, "-j", "DROP"],
                ignore_errors=True
            )
            self._run_iptables(
                ["-D", self.chain_name, "-s", ip, "-j", "DROP"],
                ignore_errors=True
            )
            logger.info(f"iptables: IP unblocked - {ip}")
            return True

    def apply_all_ip_blocks(self):
        """Apply all blocked IPs to iptables."""
        for ip in firewall.get_all_blocked_ips():
            self.apply_ip_block(ip)
        logger.info(f"All IP blocks applied: {len(firewall.blocked_ips)} total")

    # ─────────────────────────────────────────────
    # DOMAIN BLOCKING (iptables string match + DNS)
    # ─────────────────────────────────────────────

    def apply_domain_block(self, domain):
        """
        Block a domain:
        1. iptables string match for SNI domain name (HTTPS)
        2. Block DNS queries
        """
        with self._lock:
            # HTTPS - Block via TLS SNI
            # Find domain name in SNI extension via string match
            self._run_iptables([
                "-A", self.chain_name,
                "-p", "tcp", "--dport", "443",
                "-m", "string", "--string", domain,
                "--algo", "bm",  # Boyer-Moore algorithm
                "-j", "DROP"
            ], ignore_errors=True)

            # HTTP - Block via Host header
            self._run_iptables([
                "-A", self.chain_name,
                "-p", "tcp", "--dport", "80",
                "-m", "string", "--string", domain,
                "--algo", "bm",
                "-j", "DROP"
            ], ignore_errors=True)

            # DNS - Block queries for domain name
            self._run_iptables([
                "-A", self.chain_name,
                "-p", "udp", "--dport", "53",
                "-m", "string", "--string", domain,
                "--algo", "bm",
                "-j", "DROP"
            ], ignore_errors=True)

            logger.info(f"iptables: Domain blocked - {domain}")
            return True

    def remove_domain_block(self, domain):
        """Remove domain block."""
        with self._lock:
            # HTTPS
            self._run_iptables([
                "-D", self.chain_name,
                "-p", "tcp", "--dport", "443",
                "-m", "string", "--string", domain,
                "--algo", "bm",
                "-j", "DROP"
            ], ignore_errors=True)

            # HTTP
            self._run_iptables([
                "-D", self.chain_name,
                "-p", "tcp", "--dport", "80",
                "-m", "string", "--string", domain,
                "--algo", "bm",
                "-j", "DROP"
            ], ignore_errors=True)

            # DNS
            self._run_iptables([
                "-D", self.chain_name,
                "-p", "udp", "--dport", "53",
                "-m", "string", "--string", domain,
                "--algo", "bm",
                "-j", "DROP"
            ], ignore_errors=True)

            logger.info(f"iptables: Domain unblocked - {domain}")
            return True

    def apply_all_domain_blocks(self):
        """Apply all blocked domains to iptables."""
        for domain in firewall.get_all_blocked_domains():
            self.apply_domain_block(domain)
        logger.info(f"All domain blocks applied: {len(firewall.blocked_domains)} total")

    # ─────────────────────────────────────────────
    # WHITELIST (iptables ACCEPT rules)
    # ─────────────────────────────────────────────

    def apply_whitelist_item(self, item):
        """Add whitelist item to iptables (ACCEPT)."""
        with self._lock:
            # If IP format
            if self._is_ip(item):
                self._run_iptables([
                    "-I", self.chain_name, "1",
                    "-d", item, "-j", "ACCEPT"
                ], ignore_errors=True)
                self._run_iptables([
                    "-I", self.chain_name, "1",
                    "-s", item, "-j", "ACCEPT"
                ], ignore_errors=True)
            else:
                # Domain - ACCEPT on all ports
                self._run_iptables([
                    "-I", self.chain_name, "1",
                    "-m", "string", "--string", item,
                    "--algo", "bm",
                    "-j", "ACCEPT"
                ], ignore_errors=True)
            return True

    def apply_all_whitelist(self):
        """Apply all whitelist items."""
        for item in firewall.get_all_whitelist():
            self.apply_whitelist_item(item)
        logger.info(f"Whitelist applied: {len(firewall.whitelist)} total")

    # ─────────────────────────────────────────────
    # FULL SYNCHRONIZATION
    # ─────────────────────────────────────────────

    def sync_all_rules(self):
        """Synchronize all rules with iptables."""
        # First flush the chain
        self._run_iptables(["-F", self.chain_name], ignore_errors=True)
        # Apply whitelist first (priority)
        self.apply_all_whitelist()
        # Then apply blocks
        self.apply_all_ip_blocks()
        self.apply_all_domain_blocks()
        logger.info("All rules synchronized")
        return True

    def get_current_rules(self):
        """Show current iptables rules."""
        try:
            result = subprocess.run(
                [IPTABLES, "-L", self.chain_name, "-n", "--line-numbers"],
                capture_output=True, text=True, timeout=10
            )
            return result.stdout if result.returncode == 0 else "Chain does not exist"
        except Exception as e:
            return f"Error: {e}"

    def get_status(self):
        """Return firewall engine status."""
        rules = self.get_current_rules()
        rule_count = len([l for l in rules.splitlines() if l.strip() and not l.startswith("Chain") and not l.startswith("num")])
        return {
            "active": self.chain_name in rules,
            "interface": self.interface,
            "rule_count": rule_count,
            "rules_preview": rules[:2000]
        }

    # ─────────────────────────────────────────────
    # HELPER METHODS
    # ─────────────────────────────────────────────

    def _run_iptables(self, args, ignore_errors=False):
        """Execute an iptables command."""
        cmd = [IPTABLES] + args
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10
            )
            self._last_returncode = result.returncode
            if result.returncode != 0 and not ignore_errors:
                logger.warning(f"iptables error: {' '.join(cmd)} -> {result.stderr}")
                return False
            return True
        except subprocess.TimeoutExpired:
            logger.error(f"iptables timeout: {' '.join(cmd)}")
            self._last_returncode = -1
            return False
        except FileNotFoundError:
            logger.error("iptables not found. Root privileges required.")
            self._last_returncode = -1
            return False

    @staticmethod
    def _is_ip(item):
        """Check if item is in IP format."""
        parts = item.split(".")
        if len(parts) == 4:
            try:
                return all(0 <= int(p) <= 255 for p in parts)
            except ValueError:
                pass
        # CIDR notation
        if "/" in item:
            ip_part = item.split("/")[0]
            return FirewallEngine._is_ip(ip_part)
        return False


# Singleton engine instance
engine = FirewallEngine()
