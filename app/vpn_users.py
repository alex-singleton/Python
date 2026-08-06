"""
VPN User Management Module
User add, remove, activate/deactivate, traffic limits.
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
    """Manages VPN users."""

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
        """Load users from file."""
        try:
            with open(USERS_FILE, "r") as f:
                self.users = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self.users = {}

    def save(self):
        """Save users to file."""
        with self._lock:
            with open(USERS_FILE, "w") as f:
                json.dump(self.users, f, indent=2, ensure_ascii=False)

    # ─────────────────────────────────────────────
    # USER OPERATIONS
    # ─────────────────────────────────────────────

    def add_user(self, username, password, max_devices=1, traffic_limit_gb=0, expire_date=None):
        """Add a new user."""
        username = username.strip().lower()
        if not username or not password:
            return False, "Username and password cannot be empty"
        if username in self.users:
            return False, f"{username} already exists"
        if len(password) < 4:
            return False, "Password must be at least 4 characters"

        self.users[username] = {
            "id": str(uuid.uuid4()),
            "password_hash": generate_password_hash(password),
            "active": True,
            "max_devices": max_devices,
            "traffic_limit_gb": traffic_limit_gb,  # 0 = unlimited
            "traffic_used_mb": 0,
            "expire_date": expire_date,  # None = unlimited
            "created_at": datetime.now().isoformat(),
            "last_login": None,
            "last_ip": None,
            "connected": False,
            "connected_devices": 0,
            "total_connections": 0,
        }
        self.save()
        return True, f"{username} added"

    def remove_user(self, username):
        """Remove a user."""
        username = username.strip().lower()
        if username not in self.users:
            return False, f"{username} not found"
        del self.users[username]
        self.save()
        return True, f"{username} removed"

    def toggle_user(self, username):
        """Activate/deactivate a user."""
        username = username.strip().lower()
        if username not in self.users:
            return False, f"{username} not found"
        self.users[username]["active"] = not self.users[username]["active"]
        status = "activated" if self.users[username]["active"] else "deactivated"
        self.save()
        return True, f"{username} {status}"

    def update_user(self, username, max_devices=None, traffic_limit_gb=None, expire_date=None):
        """Update user parameters."""
        username = username.strip().lower()
        if username not in self.users:
            return False, f"{username} not found"
        if max_devices is not None:
            self.users[username]["max_devices"] = max_devices
        if traffic_limit_gb is not None:
            self.users[username]["traffic_limit_gb"] = traffic_limit_gb
        if expire_date is not None:
            self.users[username]["expire_date"] = expire_date
        self.save()
        return True, f"{username} updated"

    def change_password(self, username, new_password):
        """Change user password."""
        username = username.strip().lower()
        if username not in self.users:
            return False, f"{username} not found"
        if len(new_password) < 4:
            return False, "Password must be at least 4 characters"
        self.users[username]["password_hash"] = generate_password_hash(new_password)
        self.save()
        return True, f"{username} password changed"

    def reset_traffic(self, username):
        """Reset user traffic counter."""
        username = username.strip().lower()
        if username not in self.users:
            return False, f"{username} not found"
        self.users[username]["traffic_used_mb"] = 0
        self.save()
        return True, f"{username} traffic reset"

    # ─────────────────────────────────────────────
    # AUTHENTICATION
    # ─────────────────────────────────────────────

    def authenticate(self, username, password):
        """User login verification."""
        username = username.strip().lower()
        if username not in self.users:
            return False, "Incorrect username or password", None

        user = self.users[username]

        if not user["active"]:
            return False, "Account is deactivated", None

        if not check_password_hash(user["password_hash"], password):
            return False, "Incorrect username or password", None

        # Expiry check
        if user["expire_date"]:
            try:
                expire = datetime.fromisoformat(user["expire_date"])
                if datetime.now() > expire:
                    return False, "Account has expired", None
            except ValueError:
                pass

        # Traffic limit check
        if user["traffic_limit_gb"] > 0:
            used_gb = user["traffic_used_mb"] / 1024
            if used_gb >= user["traffic_limit_gb"]:
                return False, "Traffic limit exceeded", None

        # Login successful
        user["last_login"] = datetime.now().isoformat()
        user["total_connections"] += 1
        self.save()

        token = str(uuid.uuid4())
        return True, "Login successful", {
            "token": token,
            "username": username,
            "traffic_limit_gb": user["traffic_limit_gb"],
            "traffic_used_mb": user["traffic_used_mb"],
            "expire_date": user["expire_date"],
            "max_devices": user["max_devices"],
        }

    def update_connection_status(self, username, connected, ip=None):
        """Update connection status."""
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
        """Add traffic data."""
        username = username.strip().lower()
        if username not in self.users:
            return
        self.users[username]["traffic_used_mb"] += bytes_used / (1024 * 1024)
        self.save()

    # ─────────────────────────────────────────────
    # QUERIES
    # ─────────────────────────────────────────────

    def get_all_users(self):
        """Return all users."""
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
        """Get single user data."""
        username = username.strip().lower()
        if username not in self.users:
            return None
        data = self.users[username]
        return {
            "username": username,
            **data
        }

    def get_stats(self):
        """User statistics."""
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
