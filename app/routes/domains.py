"""
Domain bloklama routes - tək, siyahı, fayl ilə.
"""
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required
from app.firewall_core import firewall
from app.firewall_engine import engine

domains_bp = Blueprint("domains", __name__, url_prefix="/domains")


@domains_bp.route("/")
@login_required
def domains_page():
    blocked = firewall.get_all_blocked_domains()
    return render_template("domains.html", blocked_domains=blocked)


@domains_bp.route("/block-single", methods=["POST"])
@login_required
def block_single():
    """Tək domain blokla."""
    domain = request.form.get("domain", "").strip()
    if not domain:
        flash("Domain daxil edin!", "danger")
        return redirect(url_for("domains.domains_page"))

    success, msg = firewall.block_domain(domain)
    if success:
        engine.apply_domain_block(domain)
        flash(msg, "success")
    else:
        flash(msg, "warning")
    return redirect(url_for("domains.domains_page"))


@domains_bp.route("/block-list", methods=["POST"])
@login_required
def block_list():
    """Domain siyahısını blokla (textarea-dan)."""
    domains_text = request.form.get("domains_list", "").strip()
    if not domains_text:
        flash("Siyahı boşdur!", "danger")
        return redirect(url_for("domains.domains_page"))

    domains = [d.strip() for d in domains_text.splitlines() if d.strip()]
    added, skipped = firewall.block_domains_list(domains)

    for domain in added:
        engine.apply_domain_block(domain)

    msg = f"{len(added)} domain bloklandı."
    if skipped:
        msg += f" {len(skipped)} ədəd whitelist-də olduğu üçün keçildi."
    flash(msg, "success" if added else "warning")
    return redirect(url_for("domains.domains_page"))


@domains_bp.route("/block-file", methods=["POST"])
@login_required
def block_file():
    """Fayldan domainləri blokla."""
    file = request.files.get("domains_file")
    if not file or file.filename == "":
        flash("Fayl seçilməyib!", "danger")
        return redirect(url_for("domains.domains_page"))

    try:
        content = file.read().decode("utf-8")
    except UnicodeDecodeError:
        flash("Fayl UTF-8 formatında olmalıdır!", "danger")
        return redirect(url_for("domains.domains_page"))

    added, skipped = firewall.block_domains_from_file(content)

    for domain in added:
        engine.apply_domain_block(domain)

    msg = f"{len(added)} domain fayldan bloklandı."
    if skipped:
        msg += f" {len(skipped)} ədəd whitelist-də olduğu üçün keçildi."
    flash(msg, "success" if added else "warning")
    return redirect(url_for("domains.domains_page"))


@domains_bp.route("/unblock/<domain>", methods=["POST"])
@login_required
def unblock(domain):
    """Domain blokunu götür."""
    success, msg = firewall.unblock_domain(domain)
    if success:
        engine.remove_domain_block(domain)
        flash(msg, "success")
    else:
        flash(msg, "warning")
    return redirect(url_for("domains.domains_page"))


@domains_bp.route("/unblock-all", methods=["POST"])
@login_required
def unblock_all():
    """Bütün domain bloklarını götür."""
    domains = firewall.get_all_blocked_domains()
    count = len(domains)
    for domain in domains:
        engine.remove_domain_block(domain)
        firewall.blocked_domains.discard(domain)
    from app.firewall_core import BLOCKED_DOMAINS_FILE
    firewall._save_file(BLOCKED_DOMAINS_FILE, firewall.blocked_domains)
    flash(f"{count} domain blokdan çıxarıldı!", "success")
    return redirect(url_for("domains.domains_page"))
