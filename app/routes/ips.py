"""
IP blocking routes - single, list, file.
"""
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required
from app.firewall_core import firewall, BLOCKED_IPS_FILE
from app.firewall_engine import engine

ips_bp = Blueprint("ips", __name__, url_prefix="/ips")


@ips_bp.route("/")
@login_required
def ips_page():
    blocked = firewall.get_all_blocked_ips()
    return render_template("ips.html", blocked_ips=blocked)


@ips_bp.route("/block-single", methods=["POST"])
@login_required
def block_single():
    """Block a single IP."""
    ip = request.form.get("ip", "").strip()
    if not ip:
        flash("Please enter an IP address!", "danger")
        return redirect(url_for("ips.ips_page"))

    success, msg = firewall.block_ip(ip)
    if success:
        engine.apply_ip_block(ip)
        flash(msg, "success")
    else:
        flash(msg, "warning")
    return redirect(url_for("ips.ips_page"))


@ips_bp.route("/block-list", methods=["POST"])
@login_required
def block_list():
    """Block a list of IPs (from textarea)."""
    ips_text = request.form.get("ips_list", "").strip()
    if not ips_text:
        flash("List is empty!", "danger")
        return redirect(url_for("ips.ips_page"))

    ips = [ip.strip() for ip in ips_text.splitlines() if ip.strip()]
    added, skipped = firewall.block_ips_list(ips)

    for ip in added:
        engine.apply_ip_block(ip)

    msg = f"{len(added)} IPs blocked."
    if skipped:
        msg += f" {len(skipped)} skipped (in whitelist)."
    flash(msg, "success" if added else "warning")
    return redirect(url_for("ips.ips_page"))


@ips_bp.route("/block-file", methods=["POST"])
@login_required
def block_file():
    """Block IPs from file."""
    file = request.files.get("ips_file")
    if not file or file.filename == "":
        flash("No file selected!", "danger")
        return redirect(url_for("ips.ips_page"))

    try:
        content = file.read().decode("utf-8")
    except UnicodeDecodeError:
        flash("File must be in UTF-8 format!", "danger")
        return redirect(url_for("ips.ips_page"))

    added, skipped = firewall.block_ips_from_file(content)

    for ip in added:
        engine.apply_ip_block(ip)

    msg = f"{len(added)} IPs blocked from file."
    if skipped:
        msg += f" {len(skipped)} skipped (in whitelist)."
    flash(msg, "success" if added else "warning")
    return redirect(url_for("ips.ips_page"))


@ips_bp.route("/unblock/<path:ip>", methods=["POST"])
@login_required
def unblock(ip):
    """Unblock an IP."""
    success, msg = firewall.unblock_ip(ip)
    if success:
        engine.remove_ip_block(ip)
        flash(msg, "success")
    else:
        flash(msg, "warning")
    return redirect(url_for("ips.ips_page"))


@ips_bp.route("/unblock-all", methods=["POST"])
@login_required
def unblock_all():
    """Unblock all IPs."""
    ips = firewall.get_all_blocked_ips()
    count = len(ips)
    for ip in ips:
        engine.remove_ip_block(ip)
        firewall.blocked_ips.discard(ip)
    firewall._save_file(BLOCKED_IPS_FILE, firewall.blocked_ips)
    flash(f"{count} IPs unblocked!", "success")
    return redirect(url_for("ips.ips_page"))
