"""
IP bloklama routes - tək, siyahı, fayl ilə.
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
    """Tək IP blokla."""
    ip = request.form.get("ip", "").strip()
    if not ip:
        flash("IP ünvanı daxil edin!", "danger")
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
    """IP siyahısını blokla (textarea-dan)."""
    ips_text = request.form.get("ips_list", "").strip()
    if not ips_text:
        flash("Siyahı boşdur!", "danger")
        return redirect(url_for("ips.ips_page"))

    ips = [ip.strip() for ip in ips_text.splitlines() if ip.strip()]
    added, skipped = firewall.block_ips_list(ips)

    for ip in added:
        engine.apply_ip_block(ip)

    msg = f"{len(added)} IP bloklandı."
    if skipped:
        msg += f" {len(skipped)} ədəd whitelist-də olduğu üçün keçildi."
    flash(msg, "success" if added else "warning")
    return redirect(url_for("ips.ips_page"))


@ips_bp.route("/block-file", methods=["POST"])
@login_required
def block_file():
    """Fayldan IP-ləri blokla."""
    file = request.files.get("ips_file")
    if not file or file.filename == "":
        flash("Fayl seçilməyib!", "danger")
        return redirect(url_for("ips.ips_page"))

    try:
        content = file.read().decode("utf-8")
    except UnicodeDecodeError:
        flash("Fayl UTF-8 formatında olmalıdır!", "danger")
        return redirect(url_for("ips.ips_page"))

    added, skipped = firewall.block_ips_from_file(content)

    for ip in added:
        engine.apply_ip_block(ip)

    msg = f"{len(added)} IP fayldan bloklandı."
    if skipped:
        msg += f" {len(skipped)} ədəd whitelist-də olduğu üçün keçildi."
    flash(msg, "success" if added else "warning")
    return redirect(url_for("ips.ips_page"))


@ips_bp.route("/unblock/<path:ip>", methods=["POST"])
@login_required
def unblock(ip):
    """IP blokunu götür."""
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
    """Bütün IP bloklarını götür."""
    ips = firewall.get_all_blocked_ips()
    count = len(ips)
    for ip in ips:
        engine.remove_ip_block(ip)
        firewall.blocked_ips.discard(ip)
    firewall._save_file(BLOCKED_IPS_FILE, firewall.blocked_ips)
    flash(f"{count} IP blokdan çıxarıldı!", "success")
    return redirect(url_for("ips.ips_page"))
