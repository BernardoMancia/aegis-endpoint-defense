from flask import Blueprint, request, jsonify, render_template, session, redirect, url_for, abort, flash
from functools import wraps
from datetime import datetime
from extensions import db
from models.user import SocUser
from services.audit_service import audit

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("soc_user"):
            return redirect(url_for("auth.login_page"))
        if session.get("soc_role") != "admin":
            abort(403)
        return f(*args, **kwargs)
    return decorated


@admin_bp.route("/users")
@require_admin
def users():
    pending = SocUser.query.filter_by(status="pending").order_by(SocUser.created_at.asc()).all()
    approved = SocUser.query.filter_by(status="active").order_by(SocUser.created_at.desc()).all()
    rejected = SocUser.query.filter_by(status="rejected").order_by(SocUser.created_at.desc()).all()
    return render_template("admin_users.html",
                           pending=pending, approved=approved, rejected=rejected,
                           current_user=session.get("soc_user"),
                           current_role=session.get("soc_role"))


@admin_bp.route("/users/<int:user_id>/approve", methods=["POST"])
@require_admin
def approve_user(user_id):
    user = SocUser.query.get_or_404(user_id)
    user.status = "active"
    user.approved_at = datetime.utcnow()
    user.approved_by = session.get("soc_user")
    db.session.commit()
    audit("USER_APPROVED", actor=session.get("soc_user"), target_type="user",
          target_id=user_id, details=f"Usuário {user.username} aprovado")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/reject", methods=["POST"])
@require_admin
def reject_user(user_id):
    user = SocUser.query.get_or_404(user_id)
    user.status = "rejected"
    user.approved_by = session.get("soc_user")
    db.session.commit()
    audit("USER_REJECTED", actor=session.get("soc_user"), target_type="user",
          target_id=user_id, details=f"Usuário {user.username} recusado")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/api")
@require_admin
def api_list_users():
    users = SocUser.query.order_by(SocUser.created_at.desc()).all()
    return jsonify([u.to_dict() for u in users])


@admin_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@require_admin
def delete_user(user_id):
    user = SocUser.query.get_or_404(user_id)
    if user.username == "admin":
        flash("Não é possível deletar o admin principal.", "error")
        return redirect(url_for("admin.users"))
    db.session.delete(user)
    db.session.commit()
    audit("USER_DELETED", actor=session.get("soc_user"), target_type="user",
          target_id=user_id, details=f"Usuário {user.username} deletado")
    flash(f"Usuário {user.username} removido com sucesso.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/password", methods=["POST"])
@require_admin
def change_password(user_id):
    user = SocUser.query.get_or_404(user_id)
    new_password = request.form.get("new_password")
    if not new_password:
        return abort(400, "Nova senha não informada")
    user.password_hash = SocUser.hash_password(new_password)
    db.session.commit()
    audit("USER_PASSWORD_RESET", actor=session.get("soc_user"), target_type="user",
          target_id=user_id, details=f"Senha do {user.username} alterada pelo admin")
    flash(f"Senha de {user.username} atualizada.", "success")
    return redirect(url_for("admin.users"))
