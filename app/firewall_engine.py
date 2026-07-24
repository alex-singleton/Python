"""
Firewall Engine - iptables inteqrasiyası və DNS/SNI intercept.
HTTPS trafikini SNI (Server Name Indication) vasitəsilə bloklayır.
HTTP trafikini Host header vasitəsilə bloklayır.
IP-ləri iptables vasitəsilə bloklayır.
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
    """iptables və sistem səviyyəsində firewall idarəetməsi."""

    def __init__(self, interface="tun0"):
        self.interface = interface
        self.chain_name = "FIREWALL_BLOCK"
        self._lock = threading.Lock()

    # ─────────────────────────────────────────────
    # iptables ZƏNCİR İDARƏETMƏSİ
    # ─────────────────────────────────────────────

    def setup_chains(self):
        """Firewall chain-lərini yarat."""
        try:
            # Custom chain yarat (əgər yoxdursa)
            self._run_iptables(["-N", self.chain_name], ignore_errors=True)
            # FORWARD chain-dən custom chain-ə yönləndir
            self._run_iptables(["-C", "FORWARD", "-j", self.chain_name], ignore_errors=True)
            if self._last_returncode != 0:
                self._run_iptables(["-I", "FORWARD", "1", "-j", self.chain_name])
            logger.info("Firewall chain-ləri quruldu")
            return True
        except Exception as e:
            logger.error(f"Chain qurulması uğursuz: {e}")
            return False

    def cleanup_chains(self):
        """Firewall chain-lərini təmizlə."""
        try:
            self._run_iptables(["-D", "FORWARD", "-j", self.chain_name], ignore_errors=True)
            self._run_iptables(["-F", self.chain_name], ignore_errors=True)
            self._run_iptables(["-X", self.chain_name], ignore_errors=True)
            logger.info("Firewall chain-ləri təmizləndi")
            return True
        except Exception as e:
            logger.error(f"Chain təmizlənməsi uğursuz: {e}")
            return False

    # ─────────────────────────────────────────────
    # IP BLOKLAMA (iptables)
    # ─────────────────────────────────────────────

    def apply_ip_block(self, ip):
        """IP-ni iptables ilə blokla."""
        with self._lock:
            # Əvvəlcə mövcud olub-olmadığını yoxla
            check = self._run_iptables(
                ["-C", self.chain_name, "-d", ip, "-j", "DROP"],
                ignore_errors=True
            )
            if self._last_returncode == 0:
                return True  # Artıq mövcuddur

            result = self._run_iptables(
                ["-A", self.chain_name, "-d", ip, "-j", "DROP"]
            )
            # Source IP-ni də blokla
            self._run_iptables(
                ["-A", self.chain_name, "-s", ip, "-j", "DROP"]
            )
            logger.info(f"iptables: IP bloklandı - {ip}")
            return result

    def remove_ip_block(self, ip):
        """IP blokunu iptables-dan götür."""
        with self._lock:
            self._run_iptables(
                ["-D", self.chain_name, "-d", ip, "-j", "DROP"],
                ignore_errors=True
            )
            self._run_iptables(
                ["-D", self.chain_name, "-s", ip, "-j", "DROP"],
                ignore_errors=True
            )
            logger.info(f"iptables: IP bloku götürüldü - {ip}")
            return True

    def apply_all_ip_blocks(self):
        """Bütün bloklanmış IP-ləri iptables-a tətbiq et."""
        for ip in firewall.get_all_blocked_ips():
            self.apply_ip_block(ip)
        logger.info(f"Bütün IP blokları tətbiq edildi: {len(firewall.blocked_ips)} ədəd")

    # ─────────────────────────────────────────────
    # DOMAIN BLOKLAMA (iptables string match + DNS)
    # ─────────────────────────────────────────────

    def apply_domain_block(self, domain):
        """
        Domain-i blokla:
        1. iptables string match ilə SNI-da domain adını axtar (HTTPS)
        2. DNS sorğularını blokla
        """
        with self._lock:
            # HTTPS - TLS SNI vasitəsilə bloklama
            # SNI extension-da domain adını string match ilə tap
            self._run_iptables([
                "-A", self.chain_name,
                "-p", "tcp", "--dport", "443",
                "-m", "string", "--string", domain,
                "--algo", "bm",  # Boyer-Moore alqoritmi
                "-j", "DROP"
            ], ignore_errors=True)

            # HTTP - Host header vasitəsilə bloklama
            self._run_iptables([
                "-A", self.chain_name,
                "-p", "tcp", "--dport", "80",
                "-m", "string", "--string", domain,
                "--algo", "bm",
                "-j", "DROP"
            ], ignore_errors=True)

            # DNS sorğularını blokla (domain adına görə)
            self._run_iptables([
                "-A", self.chain_name,
                "-p", "udp", "--dport", "53",
                "-m", "string", "--string", domain,
                "--algo", "bm",
                "-j", "DROP"
            ], ignore_errors=True)

            logger.info(f"iptables: Domain bloklandı - {domain}")
            return True

    def remove_domain_block(self, domain):
        """Domain blokunu götür."""
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

            logger.info(f"iptables: Domain bloku götürüldü - {domain}")
            return True

    def apply_all_domain_blocks(self):
        """Bütün bloklanmış domainləri iptables-a tətbiq et."""
        for domain in firewall.get_all_blocked_domains():
            self.apply_domain_block(domain)
        logger.info(f"Bütün domain blokları tətbiq edildi: {len(firewall.blocked_domains)} ədəd")

    # ─────────────────────────────────────────────
    # WHITELIST (iptables ACCEPT qaydaları)
    # ─────────────────────────────────────────────

    def apply_whitelist_item(self, item):
        """Whitelist elementini iptables-a əlavə et (ACCEPT)."""
        with self._lock:
            # IP formatındadırsa
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
                # Domain - bütün portlarda ACCEPT
                self._run_iptables([
                    "-I", self.chain_name, "1",
                    "-m", "string", "--string", item,
                    "--algo", "bm",
                    "-j", "ACCEPT"
                ], ignore_errors=True)
            return True

    def apply_all_whitelist(self):
        """Bütün whitelist elementlərini tətbiq et."""
        for item in firewall.get_all_whitelist():
            self.apply_whitelist_item(item)
        logger.info(f"Whitelist tətbiq edildi: {len(firewall.whitelist)} ədəd")

    # ─────────────────────────────────────────────
    # TAM SİNXRONİZASİYA
    # ─────────────────────────────────────────────

    def sync_all_rules(self):
        """Bütün qaydaları iptables ilə sinxronlaşdır."""
        # Əvvəlcə chain-i təmizlə
        self._run_iptables(["-F", self.chain_name], ignore_errors=True)
        # Whitelist-i əvvəl tətbiq et (prioritet)
        self.apply_all_whitelist()
        # Sonra bloklamaları
        self.apply_all_ip_blocks()
        self.apply_all_domain_blocks()
        logger.info("Bütün qaydalar sinxronlaşdırıldı")
        return True

    def get_current_rules(self):
        """Hazırki iptables qaydalarını göstər."""
        try:
            result = subprocess.run(
                [IPTABLES, "-L", self.chain_name, "-n", "--line-numbers"],
                capture_output=True, text=True, timeout=10
            )
            return result.stdout if result.returncode == 0 else "Chain mövcud deyil"
        except Exception as e:
            return f"Xəta: {e}"

    def get_status(self):
        """Firewall engine statusunu qaytar."""
        rules = self.get_current_rules()
        rule_count = len([l for l in rules.splitlines() if l.strip() and not l.startswith("Chain") and not l.startswith("num")])
        return {
            "active": self.chain_name in rules,
            "interface": self.interface,
            "rule_count": rule_count,
            "rules_preview": rules[:2000]
        }

    # ─────────────────────────────────────────────
    # YARDIMÇI METODLAR
    # ─────────────────────────────────────────────

    def _run_iptables(self, args, ignore_errors=False):
        """iptables əmrini icra et."""
        cmd = [IPTABLES] + args
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10
            )
            self._last_returncode = result.returncode
            if result.returncode != 0 and not ignore_errors:
                logger.warning(f"iptables xətası: {' '.join(cmd)} -> {result.stderr}")
                return False
            return True
        except subprocess.TimeoutExpired:
            logger.error(f"iptables timeout: {' '.join(cmd)}")
            self._last_returncode = -1
            return False
        except FileNotFoundError:
            logger.error("iptables tapılmadı. Root hüquqları lazımdır.")
            self._last_returncode = -1
            return False

    @staticmethod
    def _is_ip(item):
        """Elementin IP formatında olub-olmadığını yoxla."""
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
