"""
Dashboard route - Main panel page.
"""
from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required
from app.firewall_core import firewall
from app.firewall_engine import engine

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
@login_required
def index():
    stats = firewall.get_stats()
    engine_status = engine.get_status()
    return render_template("dashboard.html", stats=stats, engine_status=engine_status)


@dashboard_bp.route("/sync-rules", methods=["POST"])
@login_required
def sync_rules():
    engine.sync_all_rules()
    flash("Rules synchronized successfully!", "success")
    return redirect(url_for("dashboard.index"))
