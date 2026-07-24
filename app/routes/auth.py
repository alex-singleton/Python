"""
Auth routes - Admin giriş/çıxış.
"""
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from app.models import Admin
from app import login_manager

auth_bp = Blueprint("auth", __name__)


@login_manager.user_loader
def load_user(user_id):
    admin = Admin.get_admin()
    if admin.id == user_id:
        return admin
    return None


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        admin = Admin.get_admin()
        if admin.username == username and admin.check_password(password):
            login_user(admin)
            next_page = request.args.get("next")
            return redirect(next_page or url_for("dashboard.index"))
        else:
            flash("Yanlış istifadəçi adı və ya parol!", "danger")

    return render_template("login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Uğurla çıxış etdiniz.", "success")
    return redirect(url_for("auth.login"))


@auth_bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        admin = Admin.get_admin()
        if not admin.check_password(current_password):
            flash("Cari parol yanlışdır!", "danger")
        elif new_password != confirm_password:
            flash("Yeni parollar uyğun gəlmir!", "danger")
        elif len(new_password) < 6:
            flash("Parol minimum 6 simvol olmalıdır!", "danger")
        else:
            Admin.update_password(new_password)
            flash("Parol uğurla dəyişdirildi!", "success")
            return redirect(url_for("dashboard.index"))

    return render_template("change_password.html")
