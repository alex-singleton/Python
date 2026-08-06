"""
VPN User Management routes - Admin panel.
"""
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required
from app.vpn_users import vpn_users

users_bp = Blueprint("users", __name__, url_prefix="/users")


@users_bp.route("/")
@login_required
def users_page():
    all_users = vpn_users.get_all_users()
    stats = vpn_users.get_stats()
    return render_template("users.html", users=all_users, stats=stats)


@users_bp.route("/add", methods=["POST"])
@login_required
def add_user():
    """Add a new user."""
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    max_devices = int(request.form.get("max_devices", 1))
    traffic_limit_gb = float(request.form.get("traffic_limit_gb", 0))
    expire_date = request.form.get("expire_date", "").strip() or None

    if not username or not password:
        flash("Please enter username and password!", "danger")
        return redirect(url_for("users.users_page"))

    success, msg = vpn_users.add_user(
        username, password, max_devices, traffic_limit_gb, expire_date
    )
    flash(msg, "success" if success else "danger")
    return redirect(url_for("users.users_page"))


@users_bp.route("/toggle/<username>", methods=["POST"])
@login_required
def toggle_user(username):
    """Activate/deactivate a user."""
    success, msg = vpn_users.toggle_user(username)
    flash(msg, "success" if success else "danger")
    return redirect(url_for("users.users_page"))


@users_bp.route("/delete/<username>", methods=["POST"])
@login_required
def delete_user(username):
    """Delete a user."""
    success, msg = vpn_users.remove_user(username)
    flash(msg, "success" if success else "danger")
    return redirect(url_for("users.users_page"))


@users_bp.route("/change-password/<username>", methods=["POST"])
@login_required
def change_password(username):
    """Change user password."""
    new_password = request.form.get("new_password", "").strip()
    if not new_password:
        flash("Please enter a new password!", "danger")
        return redirect(url_for("users.users_page"))
    success, msg = vpn_users.change_password(username, new_password)
    flash(msg, "success" if success else "danger")
    return redirect(url_for("users.users_page"))


@users_bp.route("/reset-traffic/<username>", methods=["POST"])
@login_required
def reset_traffic(username):
    """Reset traffic counter."""
    success, msg = vpn_users.reset_traffic(username)
    flash(msg, "success" if success else "danger")
    return redirect(url_for("users.users_page"))


@users_bp.route("/update/<username>", methods=["POST"])
@login_required
def update_user(username):
    """Update user parameters."""
    max_devices = int(request.form.get("max_devices", 1))
    traffic_limit_gb = float(request.form.get("traffic_limit_gb", 0))
    expire_date = request.form.get("expire_date", "").strip() or None

    success, msg = vpn_users.update_user(username, max_devices, traffic_limit_gb, expire_date)
    flash(msg, "success" if success else "danger")
    return redirect(url_for("users.users_page"))
