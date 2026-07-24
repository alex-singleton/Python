"""
VPN API routes - Windows client üçün.
Client login, connect, disconnect, status əmrləri.
"""
import uuid
import time
from flask import Blueprint, request, jsonify
from app.vpn_users import vpn_users

api_bp = Blueprint("api", __name__, url_prefix="/api/v1")

# Aktiv session-lar: {token: {username, connected_at, ip}}
active_sessions = {}


@api_bp.route("/login", methods=["POST"])
def login():
    """Client login - token qaytarır."""
    data = request.get_json()
    if not data:
        return jsonify({"success": False, "message": "JSON data tələb olunur"}), 400

    username = data.get("username", "")
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"success": False, "message": "İstifadəçi adı və parol lazımdır"}), 400

    success, message, user_data = vpn_users.authenticate(username, password)

    if not success:
        return jsonify({"success": False, "message": message}), 401

    # Session yarat
    token = user_data["token"]
    active_sessions[token] = {
        "username": username,
        "connected_at": time.time(),
        "ip": request.remote_addr,
    }

    return jsonify({
        "success": True,
        "message": message,
        "token": token,
        "user": {
            "username": username,
            "traffic_limit_gb": user_data["traffic_limit_gb"],
            "traffic_used_mb": user_data["traffic_used_mb"],
            "expire_date": user_data["expire_date"],
            "max_devices": user_data["max_devices"],
        }
    })


@api_bp.route("/connect", methods=["POST"])
def connect():
    """VPN bağlantısını başlat."""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token or token not in active_sessions:
        return jsonify({"success": False, "message": "Yanlış və ya müddəti bitmiş token"}), 401

    session = active_sessions[token]
    username = session["username"]

    # Bağlantı statusunu yenilə
    vpn_users.update_connection_status(username, True, request.remote_addr)

    # Proxy konfiqurasiyasını qaytar
    return jsonify({
        "success": True,
        "message": "Bağlantı quruldu",
        "proxy": {
            "type": "socks5",
            "host": request.host.split(":")[0],
            "port": 1080,
            "username": username,
            "password": token,
        }
    })


@api_bp.route("/disconnect", methods=["POST"])
def disconnect():
    """VPN bağlantısını kəs."""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token or token not in active_sessions:
        return jsonify({"success": False, "message": "Yanlış token"}), 401

    session = active_sessions[token]
    username = session["username"]

    vpn_users.update_connection_status(username, False)
    del active_sessions[token]

    return jsonify({"success": True, "message": "Bağlantı kəsildi"})


@api_bp.route("/status", methods=["GET"])
def status():
    """Bağlantı statusu."""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token or token not in active_sessions:
        return jsonify({"success": False, "connected": False, "message": "Bağlantı yoxdur"}), 401

    session = active_sessions[token]
    username = session["username"]
    user = vpn_users.get_user(username)

    if not user:
        return jsonify({"success": False, "connected": False}), 401

    return jsonify({
        "success": True,
        "connected": True,
        "username": username,
        "traffic_used_mb": round(user["traffic_used_mb"], 2),
        "traffic_limit_gb": user["traffic_limit_gb"],
        "connected_since": session["connected_at"],
    })


@api_bp.route("/ping", methods=["GET"])
def ping():
    """Server mövcudluq yoxlaması."""
    return jsonify({"success": True, "message": "pong", "time": time.time()})
