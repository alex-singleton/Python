"""
VPN İstifadəçi İdarəetmə Modulu
İstifadəçi əlavə etmə, silmə, aktiv/deaktiv, trafik limiti.
"""
import os
import json
import uuid
import threading
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
USERS_FILE = os.path.join(DATA_DIR, "vpn_users.json")


class VPNUserManager:
    """VPN istifadəçilərini idarə edir."""

    def __init__(self):
        self._lock = threading.Lock()
        self.users = {}
        self._ensure_file()
        self.load()

    def _ensure_file(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        if not os.path.exists(USERS_FILE):
            with open(USERS_FILE, "w") as f:
                json.dump({}, f)

    def load(self):
        """İstifadəçiləri fayldan yüklə."""
        try:
            with open(USERS_FILE, "r") as f:
                self.users = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.users = {}

    def save(self):
        """İstifadəçiləri fayla yaz."""
        with self._lock:
            with open(USERS_FILE, "w") as f:
                json.dump(self.users, f, indent=2, ensure_ascii=False)

    # ─────────────────────────────────────────────
    # İSTİFADƏÇİ ƏMƏLİYYATLARI
    # ─────────────────────────────────────────────

    def add_user(self, username, password, max_devices=1, traffic_limit_gb=0, expire_date=None):
        """Yeni istifadəçi əlavə et."""
        username = username.strip().lower()
        if not username or not password:
            return False, "İstifadəçi adı və parol boş ola bilməz"
        if username in self.users:
            return False, f"{username} artıq mövcuddur"
        if len(password) < 4:
            return False, "Parol minimum 4 simvol olmalıdır"

        self.users[username] = {
            "id": str(uuid.uuid4()),
            "password_hash": generate_password_hash(password),
            "active": True,
            "max_devices": max_devices,
            "traffic_limit_gb": traffic_limit_gb,  # 0 = limitsiz
            "traffic_used_mb": 0,
            "expire_date": expire_date,  # None = limitsiz
            "created_at": datetime.now().isoformat(),
            "last_login": None,
            "last_ip": None,
            "connected": False,
            "connected_devices": 0,
            "total_connections": 0,
        }
        self.save()
        return True, f"{username} əlavə edildi"

    def remove_user(self, username):
        """İstifadəçini sil."""
        username = username.strip().lower()
        if username not in self.users:
            return False, f"{username} tapılmadı"
        del self.users[username]
        self.save()
        return True, f"{username} silindi"

    def toggle_user(self, username):
        """İstifadəçini aktiv/deaktiv et."""
        username = username.strip().lower()
        if username not in self.users:
            return False, f"{username} tapılmadı"
        self.users[username]["active"] = not self.users[username]["active"]
        status = "aktivləşdirildi" if self.users[username]["active"] else "deaktiv edildi"
        self.save()
        return True, f"{username} {status}"

    def update_user(self, username, max_devices=None, traffic_limit_gb=None, expire_date=None):
        """İstifadəçi parametrlərini yenilə."""
        username = username.strip().lower()
        if username not in self.users:
            return False, f"{username} tapılmadı"
        if max_devices is not None:
            self.users[username]["max_devices"] = max_devices
        if traffic_limit_gb is not None:
            self.users[username]["traffic_limit_gb"] = traffic_limit_gb
        if expire_date is not None:
            self.users[username]["expire_date"] = expire_date
        self.save()
        return True, f"{username} yeniləndi"

    def change_password(self, username, new_password):
        """İstifadəçi parolunu dəyiş."""
        username = username.strip().lower()
        if username not in self.users:
            return False, f"{username} tapılmadı"
        if len(new_password) < 4:
            return False, "Parol minimum 4 simvol olmalıdır"
        self.users[username]["password_hash"] = generate_password_hash(new_password)
        self.save()
        return True, f"{username} parolu dəyişdirildi"

    def reset_traffic(self, username):
        """İstifadəçinin trafik sayğacını sıfırla."""
        username = username.strip().lower()
        if username not in self.users:
            return False, f"{username} tapılmadı"
        self.users[username]["traffic_used_mb"] = 0
        self.save()
        return True, f"{username} trafiki sıfırlandı"

    # ─────────────────────────────────────────────
    # AUTENTİFİKASİYA
    # ─────────────────────────────────────────────

    def authenticate(self, username, password):
        """İstifadəçi login yoxlaması."""
        username = username.strip().lower()
        if username not in self.users:
            return False, "Yanlış istifadəçi adı və ya parol", None

        user = self.users[username]

        if not user["active"]:
            return False, "Hesab deaktiv edilib", None

        if not check_password_hash(user["password_hash"], password):
            return False, "Yanlış istifadəçi adı və ya parol", None

        # Müddət yoxlaması
        if user["expire_date"]:
            try:
                expire = datetime.fromisoformat(user["expire_date"])
                if datetime.now() > expire:
                    return False, "Hesab müddəti bitib", None
            except ValueError:
                pass

        # Trafik limiti yoxlaması
        if user["traffic_limit_gb"] > 0:
            used_gb = user["traffic_used_mb"] / 1024
            if used_gb >= user["traffic_limit_gb"]:
                return False, "Trafik limiti bitib", None

        # Login uğurlu
        user["last_login"] = datetime.now().isoformat()
        user["total_connections"] += 1
        self.save()

        token = str(uuid.uuid4())
        return True, "Giriş uğurlu", {
            "token": token,
            "username": username,
            "traffic_limit_gb": user["traffic_limit_gb"],
            "traffic_used_mb": user["traffic_used_mb"],
            "expire_date": user["expire_date"],
            "max_devices": user["max_devices"],
        }

    def update_connection_status(self, username, connected, ip=None):
        """Bağlantı statusunu yenilə."""
        username = username.strip().lower()
        if username not in self.users:
            return
        self.users[username]["connected"] = connected
        if connected:
            self.users[username]["connected_devices"] += 1
            if ip:
                self.users[username]["last_ip"] = ip
        else:
            self.users[username]["connected_devices"] = max(
                0, self.users[username]["connected_devices"] - 1
            )
        self.save()

    def add_traffic(self, username, bytes_used):
        """Trafik məlumatını əlavə et."""
        username = username.strip().lower()
        if username not in self.users:
            return
        self.users[username]["traffic_used_mb"] += bytes_used / (1024 * 1024)
        self.save()

    # ─────────────────────────────────────────────
    # SORĞULAR
    # ─────────────────────────────────────────────

    def get_all_users(self):
        """Bütün istifadəçiləri qaytar."""
        result = []
        for username, data in self.users.items():
            result.append({
                "username": username,
                "active": data["active"],
                "max_devices": data["max_devices"],
                "traffic_limit_gb": data["traffic_limit_gb"],
                "traffic_used_mb": round(data["traffic_used_mb"], 2),
                "expire_date": data["expire_date"],
                "created_at": data["created_at"],
                "last_login": data["last_login"],
                "last_ip": data["last_ip"],
                "connected": data["connected"],
                "connected_devices": data["connected_devices"],
                "total_connections": data["total_connections"],
            })
        return sorted(result, key=lambda x: x["created_at"], reverse=True)

    def get_user(self, username):
        """Tək istifadəçi məlumatı."""
        username = username.strip().lower()
        if username not in self.users:
            return None
        data = self.users[username]
        return {
            "username": username,
            **data
        }

    def get_stats(self):
        """İstifadəçi statistikası."""
        total = len(self.users)
        active = sum(1 for u in self.users.values() if u["active"])
        connected = sum(1 for u in self.users.values() if u["connected"])
        return {
            "total_users": total,
            "active_users": active,
            "inactive_users": total - active,
            "connected_now": connected,
        }


# Singleton
vpn_users = VPNUserManager()
