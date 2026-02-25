from datetime import datetime
from flask import Blueprint, request, jsonify, render_template, session, redirect, url_for, abort, flash
from extensions import db
from models.user import SocUser, ROLES
from services.audit_service import audit
from utils.permissions import require_admin, require_superadmin

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def _actor():
    return session.get("soc_user")


def _actor_obj():
    return SocUser.query.filter_by(username=_actor()).first()


@admin_bp.route("/users")
@require_admin
def users():
    pending = SocUser.query.filter_by(status="pending").order_by(SocUser.created_at.asc()).all()
    approved = SocUser.query.filter_by(status="active").order_by(SocUser.created_at.desc()).all()
    rejected = SocUser.query.filter_by(status="rejected").order_by(SocUser.created_at.desc()).all()
    return render_template(
        "admin_users.html",
        pending=pending, approved=approved, rejected=rejected,
        current_user=_actor(),
        current_role=session.get("soc_role"),
        all_roles=ROLES,
    )


@admin_bp.route("/users/<int:user_id>/approve", methods=["POST"])
@require_admin
def approve_user(user_id):
    user = SocUser.query.get_or_404(user_id)
    user.status = "active"
    user.approved_at = datetime.utcnow()
    user.approved_by = _actor()
    db.session.commit()
    audit("USER_APPROVED", actor=_actor(), target_type="user", target_id=user_id, details=f"{user.username} aprovado")
    flash(f"Usuário {user.username} aprovado.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/reject", methods=["POST"])
@require_admin
def reject_user(user_id):
    user = SocUser.query.get_or_404(user_id)
    user.status = "rejected"
    user.approved_by = _actor()
    db.session.commit()
    audit("USER_REJECTED", actor=_actor(), target_type="user", target_id=user_id, details=f"{user.username} recusado")
    flash(f"Usuário {user.username} recusado.", "warning")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/role", methods=["POST"])
@require_superadmin
def change_role(user_id):
    actor = _actor_obj()
    target = SocUser.query.get_or_404(user_id)
    new_role = request.form.get("role")

    if new_role not in ROLES:
        flash("Role inválida.", "danger")
        return redirect(url_for("admin.users"))
    if target.role == "superadmin" and target.id != actor.id:
        flash("Não é possível alterar a role de outro Super Administrador.", "danger")
        return redirect(url_for("admin.users"))
    if new_role == "superadmin" and actor.role != "superadmin":
        flash("Apenas um Super Administrador pode promover outros ao nível Super Admin.", "danger")
        return redirect(url_for("admin.users"))

    old_role = target.role
    target.role = new_role
    db.session.commit()
    audit("USER_ROLE_CHANGED", actor=_actor(), target_type="user", target_id=user_id,
          details=f"{target.username}: {old_role} → {new_role}")
    flash(f"Role de {target.username} alterada para {ROLES[new_role]['label']}.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/unlock", methods=["POST"])
@require_admin
def unlock_user(user_id):
    user = SocUser.query.get_or_404(user_id)
    user.locked_until = None
    user.failed_logins = 0
    db.session.commit()
    audit("USER_UNLOCKED", actor=_actor(), target_type="user", target_id=user_id, details=f"{user.username} desbloqueado")
    flash(f"Conta de {user.username} desbloqueada.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@require_superadmin
def delete_user(user_id):
    actor = _actor_obj()
    user = SocUser.query.get_or_404(user_id)
    if user.id == actor.id:
        flash("Não é possível deletar sua própria conta.", "danger")
        return redirect(url_for("admin.users"))
    if user.role == "superadmin":
        flash("Não é possível deletar outro Super Administrador.", "danger")
        return redirect(url_for("admin.users"))
    username = user.username
    db.session.delete(user)
    db.session.commit()
    audit("USER_DELETED", actor=_actor(), target_type="user", target_id=user_id, details=f"{username} deletado")
    flash(f"Usuário {username} removido.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/password", methods=["POST"])
@require_admin
def change_password(user_id):
    target = SocUser.query.get_or_404(user_id)
    actor = _actor_obj()
    if not actor.can_manage(target):
        flash("Você não tem permissão para redefinir a senha deste usuário.", "danger")
        return redirect(url_for("admin.users"))
    new_password = request.form.get("new_password")
    if not new_password or len(new_password) < 8:
        flash("A nova senha deve ter ao menos 8 caracteres.", "danger")
        return redirect(url_for("admin.users"))
    target.password_hash = SocUser.hash_password(new_password)
    target.password_changed_at = datetime.utcnow()
    db.session.commit()
    audit("USER_PASSWORD_RESET", actor=_actor(), target_type="user", target_id=user_id,
          details=f"Senha de {target.username} redefinida")
    flash(f"Senha de {target.username} atualizada.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/api")
@require_admin
def api_list_users():
    users = SocUser.query.order_by(SocUser.created_at.desc()).all()
    return jsonify([u.to_dict() for u in users])


@admin_bp.route("/users/<int:user_id>/profile", methods=["GET"])
@require_superadmin
def view_user_profile(user_id):
    actor = _actor_obj()
    target = SocUser.query.get_or_404(user_id)
    if not actor.can_manage(target) and actor.id != target.id:
        flash("Você não tem permissão para ver o perfil deste usuário.", "danger")
        return redirect(url_for("admin.users"))
    from models.user import LoginHistory, ROLES
    history = LoginHistory.query.filter_by(user_id=target.id).order_by(LoginHistory.timestamp.desc()).limit(10).all()
    return render_template("admin_user_profile.html",
                           target=target, history=history,
                           all_roles=ROLES,
                           current_user=_actor(),
                           current_role=session.get("soc_role"))


@admin_bp.route("/users/<int:user_id>/profile/update", methods=["POST"])
@require_superadmin
def update_user_profile(user_id):
    actor = _actor_obj()
    target = SocUser.query.get_or_404(user_id)
    if not actor.can_manage(target):
        flash("Você não tem permissão para editar este perfil.", "danger")
        return redirect(url_for("admin.users"))

    display_name = request.form.get("display_name", "").strip()
    email = request.form.get("email", "").strip()

    if display_name:
        target.display_name = display_name
    if email and "@" in email:
        target.email = email

    db.session.commit()
    audit("ADMIN_USER_PROFILE_UPDATE", actor=_actor(), target_type="user", target_id=user_id,
          details=f"Perfil de {target.username} atualizado pelo superadmin")
    flash(f"Perfil de {target.username} atualizado.", "success")
    return redirect(url_for("admin.view_user_profile", user_id=user_id))


@admin_bp.route("/users/<int:user_id>/profile/reset-mfa", methods=["POST"])
@require_superadmin
def reset_user_mfa(user_id):
    actor = _actor_obj()
    target = SocUser.query.get_or_404(user_id)
    if not actor.can_manage(target):
        flash("Acesso negado.", "danger")
        return redirect(url_for("admin.users"))
    target.mfa_enabled = False
    target.mfa_secret = None
    target.mfa_recovery_codes = None
    db.session.commit()
    audit("ADMIN_MFA_RESET", actor=_actor(), target_type="user", target_id=user_id,
          details=f"MFA de {target.username} resetado pelo superadmin")
    flash(f"MFA de {target.username} foi desativado.", "warning")
    return redirect(url_for("admin.view_user_profile", user_id=user_id))

