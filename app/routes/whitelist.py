"""
Whitelist routes - tək, siyahı, fayl ilə.
"""
from flask import Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required
from app.firewall_core import firewall, WHITELIST_FILE
from app.firewall_engine import engine

whitelist_bp = Blueprint("whitelist", __name__, url_prefix="/whitelist")


@whitelist_bp.route("/")
@login_required
def whitelist_page():
    items = firewall.get_all_whitelist()
    return render_template("whitelist.html", whitelist_items=items)


@whitelist_bp.route("/add-single", methods=["POST"])
@login_required
def add_single():
    """Tək element whitelist-ə əlavə et."""
    item = request.form.get("item", "").strip()
    if not item:
        flash("Domain və ya IP daxil edin!", "danger")
        return redirect(url_for("whitelist.whitelist_page"))

    success, msg = firewall.add_to_whitelist(item)
    if success:
        engine.apply_whitelist_item(item)
        flash(msg, "success")
    else:
        flash(msg, "warning")
    return redirect(url_for("whitelist.whitelist_page"))


@whitelist_bp.route("/add-list", methods=["POST"])
@login_required
def add_list():
    """Siyahını whitelist-ə əlavə et (textarea-dan)."""
    items_text = request.form.get("items_list", "").strip()
    if not items_text:
        flash("Siyahı boşdur!", "danger")
        return redirect(url_for("whitelist.whitelist_page"))

    items = [item.strip() for item in items_text.splitlines() if item.strip()]
    added = firewall.add_to_whitelist_list(items)

    for item in added:
        engine.apply_whitelist_item(item)

    flash(f"{len(added)} element whitelist-ə əlavə edildi.", "success" if added else "warning")
    return redirect(url_for("whitelist.whitelist_page"))


@whitelist_bp.route("/add-file", methods=["POST"])
@login_required
def add_file():
    """Fayldan whitelist-ə əlavə et."""
    file = request.files.get("whitelist_file")
    if not file or file.filename == "":
        flash("Fayl seçilməyib!", "danger")
        return redirect(url_for("whitelist.whitelist_page"))

    try:
        content = file.read().decode("utf-8")
    except UnicodeDecodeError:
        flash("Fayl UTF-8 formatında olmalıdır!", "danger")
        return redirect(url_for("whitelist.whitelist_page"))

    added = firewall.add_to_whitelist_from_file(content)

    for item in added:
        engine.apply_whitelist_item(item)

    flash(f"{len(added)} element fayldan whitelist-ə əlavə edildi.", "success" if added else "warning")
    return redirect(url_for("whitelist.whitelist_page"))


@whitelist_bp.route("/remove/<path:item>", methods=["POST"])
@login_required
def remove(item):
    """Whitelist-dən sil."""
    success, msg = firewall.remove_from_whitelist(item)
    if success:
        flash(msg, "success")
    else:
        flash(msg, "warning")
    return redirect(url_for("whitelist.whitelist_page"))


@whitelist_bp.route("/remove-all", methods=["POST"])
@login_required
def remove_all():
    """Bütün whitelist elementlərini sil."""
    items = firewall.get_all_whitelist()
    count = len(items)
    firewall.whitelist.clear()
    firewall._save_file(WHITELIST_FILE, firewall.whitelist)
    flash(f"{count} element whitelist-dən silindi!", "success")
    return redirect(url_for("whitelist.whitelist_page"))
