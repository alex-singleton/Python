"""
İstifadəçi modeli - Flask-Login üçün.
"""
import os
import json
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
ADMIN_FILE = os.path.join(DATA_DIR, "admin.json")


class Admin(UserMixin):
    """Admin istifadəçi sinfi."""

    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @staticmethod
    def get_admin():
        """Admin məlumatlarını yüklə, yoxdursa default yarat."""
        os.makedirs(DATA_DIR, exist_ok=True)
        if not os.path.exists(ADMIN_FILE):
            # Default admin yarat
            default_admin = {
                "id": "1",
                "username": "admin",
                "password_hash": generate_password_hash("admin123")
            }
            with open(ADMIN_FILE, "w") as f:
                json.dump(default_admin, f, indent=2)
            return Admin(**default_admin)

        with open(ADMIN_FILE, "r") as f:
            data = json.load(f)
        return Admin(**data)

    @staticmethod
    def update_password(new_password):
        """Admin parolunu yenilə."""
        admin = Admin.get_admin()
        admin.password_hash = generate_password_hash(new_password)
        data = {
            "id": admin.id,
            "username": admin.username,
            "password_hash": admin.password_hash
        }
        with open(ADMIN_FILE, "w") as f:
            json.dump(data, f, indent=2)
        return True

    @staticmethod
    def update_username(new_username):
        """Admin istifadəçi adını yenilə."""
        admin = Admin.get_admin()
        data = {
            "id": admin.id,
            "username": new_username,
            "password_hash": admin.password_hash
        }
        with open(ADMIN_FILE, "w") as f:
            json.dump(data, f, indent=2)
        return True
