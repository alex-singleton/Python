"""
Firewall Core Module
Domain bloklama, IP bloklama və whitelist idarəetmə məntiqi.
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
    """Firewall əsas sinfi - domain, IP bloklama və whitelist idarəetməsi."""

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
        """Data fayllarının mövcudluğunu yoxla, yoxdursa yarat."""
        os.makedirs(DATA_DIR, exist_ok=True)
        for filepath in [BLOCKED_DOMAINS_FILE, BLOCKED_IPS_FILE, WHITELIST_FILE]:
            if not os.path.exists(filepath):
                open(filepath, "w").close()

    # ─────────────────────────────────────────────
    # YÜKLƏMƏ / SAXLAMA
    # ─────────────────────────────────────────────

    def load_all(self):
        """Bütün data fayllarını yüklə."""
        self.blocked_domains = self._load_file(BLOCKED_DOMAINS_FILE)
        self.blocked_ips = self._load_file(BLOCKED_IPS_FILE)
        self.whitelist = self._load_file(WHITELIST_FILE)
        self.stats["last_updated"] = datetime.now().isoformat()
        logger.info(
            f"Yükləndi: {len(self.blocked_domains)} domain, "
            f"{len(self.blocked_ips)} IP, {len(self.whitelist)} whitelist"
        )

    def _load_file(self, filepath):
        """Fayldan sətirləri oxu, set olaraq qaytar."""
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
        """Set-i fayla yaz."""
        with self._lock:
            with open(filepath, "w") as f:
                for item in sorted(items):
                    f.write(item + "\n")
        self.stats["last_updated"] = datetime.now().isoformat()

    # ─────────────────────────────────────────────
    # DOMAIN BLOKLAMA
    # ─────────────────────────────────────────────

    def block_domain(self, domain):
        """Tək domain blokla."""
        domain = domain.strip().lower()
        if not domain:
            return False, "Domain boş ola bilməz"
        if domain in self.whitelist:
            return False, f"{domain} whitelist-dədir, əvvəlcə oradan silin"
        self.blocked_domains.add(domain)
        self._save_file(BLOCKED_DOMAINS_FILE, self.blocked_domains)
        self.stats["domains_blocked_count"] = len(self.blocked_domains)
        logger.info(f"Domain bloklandı: {domain}")
        return True, f"{domain} bloklandı"

    def block_domains_list(self, domains):
        """Domain siyahısını blokla."""
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
        """Fayl məzmunundan domainləri blokla."""
        domains = [line.strip() for line in file_content.splitlines() if line.strip()]
        return self.block_domains_list(domains)

    def unblock_domain(self, domain):
        """Domain blokunu götür."""
        domain = domain.strip().lower()
        if domain in self.blocked_domains:
            self.blocked_domains.discard(domain)
            self._save_file(BLOCKED_DOMAINS_FILE, self.blocked_domains)
            self.stats["domains_blocked_count"] = len(self.blocked_domains)
            logger.info(f"Domain bloku götürüldü: {domain}")
            return True, f"{domain} blokdan çıxarıldı"
        return False, f"{domain} blok siyahısında tapılmadı"

    def is_domain_blocked(self, domain):
        """Domain bloklanıbmı yoxla (subdomain dəstəyi ilə)."""
        domain = domain.strip().lower()
        if domain in self.whitelist:
            return False
        if domain in self.blocked_domains:
            return True
        # Subdomain yoxlaması: example.com bloklanıbsa, sub.example.com da bloklanır
        parts = domain.split(".")
        for i in range(1, len(parts)):
            parent = ".".join(parts[i:])
            if parent in self.blocked_domains:
                return True
        return False

    # ─────────────────────────────────────────────
    # IP BLOKLAMA
    # ─────────────────────────────────────────────

    def block_ip(self, ip):
        """Tək IP blokla."""
        ip = ip.strip()
        if not ip:
            return False, "IP boş ola bilməz"
        if ip in self.whitelist:
            return False, f"{ip} whitelist-dədir, əvvəlcə oradan silin"
        self.blocked_ips.add(ip)
        self._save_file(BLOCKED_IPS_FILE, self.blocked_ips)
        self.stats["ips_blocked_count"] = len(self.blocked_ips)
        logger.info(f"IP bloklandı: {ip}")
        return True, f"{ip} bloklandı"

    def block_ips_list(self, ips):
        """IP siyahısını blokla."""
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
        """Fayl məzmunundan IP-ləri blokla."""
        ips = [line.strip() for line in file_content.splitlines() if line.strip()]
        return self.block_ips_list(ips)

    def unblock_ip(self, ip):
        """IP blokunu götür."""
        ip = ip.strip()
        if ip in self.blocked_ips:
            self.blocked_ips.discard(ip)
            self._save_file(BLOCKED_IPS_FILE, self.blocked_ips)
            self.stats["ips_blocked_count"] = len(self.blocked_ips)
            logger.info(f"IP bloku götürüldü: {ip}")
            return True, f"{ip} blokdan çıxarıldı"
        return False, f"{ip} blok siyahısında tapılmadı"

    def is_ip_blocked(self, ip):
        """IP bloklanıbmı yoxla."""
        ip = ip.strip()
        if ip in self.whitelist:
            return False
        return ip in self.blocked_ips

    # ─────────────────────────────────────────────
    # WHITELIST
    # ─────────────────────────────────────────────

    def add_to_whitelist(self, item):
        """Tək element whitelist-ə əlavə et."""
        item = item.strip().lower()
        if not item:
            return False, "Element boş ola bilməz"
        # Whitelist-ə əlavə ediləndə blok siyahılarından sil
        self.blocked_domains.discard(item)
        self.blocked_ips.discard(item)
        self.whitelist.add(item)
        self._save_file(WHITELIST_FILE, self.whitelist)
        self._save_file(BLOCKED_DOMAINS_FILE, self.blocked_domains)
        self._save_file(BLOCKED_IPS_FILE, self.blocked_ips)
        logger.info(f"Whitelist-ə əlavə edildi: {item}")
        return True, f"{item} whitelist-ə əlavə edildi"

    def add_to_whitelist_list(self, items):
        """Siyahını whitelist-ə əlavə et."""
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
        """Fayl məzmunundan whitelist-ə əlavə et."""
        items = [line.strip() for line in file_content.splitlines() if line.strip()]
        return self.add_to_whitelist_list(items)

    def remove_from_whitelist(self, item):
        """Whitelist-dən sil."""
        item = item.strip().lower()
        if item in self.whitelist:
            self.whitelist.discard(item)
            self._save_file(WHITELIST_FILE, self.whitelist)
            logger.info(f"Whitelist-dən silindi: {item}")
            return True, f"{item} whitelist-dən silindi"
        return False, f"{item} whitelist-də tapılmadı"

    # ─────────────────────────────────────────────
    # STATİSTİKA
    # ─────────────────────────────────────────────

    def get_stats(self):
        """Statistika məlumatlarını qaytar."""
        return {
            "blocked_domains_count": len(self.blocked_domains),
            "blocked_ips_count": len(self.blocked_ips),
            "whitelist_count": len(self.whitelist),
            "total_rules": len(self.blocked_domains) + len(self.blocked_ips),
            "last_updated": self.stats["last_updated"],
        }

    def get_all_blocked_domains(self):
        """Bütün bloklanmış domainləri qaytar."""
        return sorted(self.blocked_domains)

    def get_all_blocked_ips(self):
        """Bütün bloklanmış IP-ləri qaytar."""
        return sorted(self.blocked_ips)

    def get_all_whitelist(self):
        """Bütün whitelist elementlərini qaytar."""
        return sorted(self.whitelist)


# Singleton instance
firewall = FirewallCore()
