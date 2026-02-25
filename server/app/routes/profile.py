import secrets
from datetime import datetime, timedelta
from flask import Blueprint, request, render_template, session, redirect, url_for, flash
from extensions import db, log
from models.user import SocUser, LoginHistory
from services.audit_service import audit
from utils.permissions import require_login

profile_bp = Blueprint("profile", __name__)


def _current_user():
    return SocUser.query.filter_by(username=session.get("soc_user")).first()


@profile_bp.route("/profile")
@require_login
def profile_page():
    user = _current_user()
    history = LoginHistory.query.filter_by(user_id=user.id).order_by(LoginHistory.timestamp.desc()).limit(10).all()
    return render_template("profile.html", user=user, history=history)


@profile_bp.route("/profile/update", methods=["POST"])
@require_login
def update_profile():
    user = _current_user()
    display_name = request.form.get("display_name", "").strip()
    if display_name:
        user.display_name = display_name
        session["soc_display"] = display_name
    
    try:
        db.session.commit()
    except Exception as e:
        log.error(f"[PROFILE] Erro transacional ao atualizar display_name de {user.username}: {e}")
        db.session.rollback()
        flash("Falha interna ao salvar. Tente novamente mais tarde.", "danger")
        return redirect(url_for("profile.profile_page"))

    audit("PROFILE_UPDATE", actor=user.username, target_type="user", details="Display name atualizado")
    flash("Perfil atualizado com sucesso.", "success")
    return redirect(url_for("profile.profile_page"))


@profile_bp.route("/profile/change-password", methods=["POST"])
@require_login
def change_own_password():
    user = _current_user()
    current_pw = request.form.get("current_password", "")
    new_pw = request.form.get("new_password", "")
    confirm_pw = request.form.get("confirm_password", "")

    if not user.check_password(current_pw):
        flash("Senha atual incorreta.", "danger")
        return redirect(url_for("profile.profile_page"))
    if len(new_pw) < 8:
        flash("A nova senha deve ter ao menos 8 caracteres.", "danger")
        return redirect(url_for("profile.profile_page"))
    if new_pw != confirm_pw:
        flash("As senhas não conferem.", "danger")
        return redirect(url_for("profile.profile_page"))

    user.password_hash = SocUser.hash_password(new_pw)
    user.password_changed_at = datetime.utcnow()
    try:
        db.session.commit()
    except Exception as e:
        log.error(f"[PROFILE] Erro transacional ao atualizar senha de {user.username}: {e}")
        db.session.rollback()
        flash("Falha interna ao alterar senha. Tente novamente.", "danger")
        return redirect(url_for("profile.profile_page"))

    audit("PASSWORD_CHANGE_SELF", actor=user.username, target_type="user")
    flash("Senha alterada com sucesso.", "success")
    return redirect(url_for("profile.profile_page"))


@profile_bp.route("/profile/request-email", methods=["POST"])
@require_login
def request_email_change():
    user = _current_user()
    new_email = request.form.get("new_email", "").strip()
    if not new_email or "@" not in new_email:
        flash("Email inválido.", "danger")
        return redirect(url_for("profile.profile_page"))

    token = secrets.token_urlsafe(32)
    user.pending_email = new_email
    user.email_token = token
    user.email_token_expires = datetime.utcnow() + timedelta(hours=24)
    try:
        db.session.commit()
    except Exception as e:
        log.error(f"[PROFILE] Erro ao gerar token de email para {user.username}: {e}")
        db.session.rollback()
        flash("Falha interna ao solicitar troca de e-mail.", "danger")
        return redirect(url_for("profile.profile_page"))

    confirm_url = url_for("profile.confirm_email", token=token, _external=True)
    log.info(f"[EMAIL] Confirmação de troca de email para {user.username}: {confirm_url}")
    flash(f"Link de confirmação gerado. Em produção, seria enviado para {user.email}. Link: {confirm_url}", "info")
    audit("EMAIL_CHANGE_REQUEST", actor=user.username, target_type="user", details=f"→ {new_email}")
    return redirect(url_for("profile.profile_page"))


@profile_bp.route("/profile/confirm-email/<token>")
def confirm_email(token):
    user = SocUser.query.filter_by(email_token=token).first()
    if not user:
        flash("Token inválido ou expirado.", "danger")
        return redirect(url_for("auth.login_page"))
    if user.email_token_expires < datetime.utcnow():
        flash("Token expirado. Solicite novo link.", "danger")
        return redirect(url_for("profile.profile_page"))
    old_email = user.email
    user.email = user.pending_email
    user.pending_email = None
    user.email_token = None
    user.email_token_expires = None
    try:
        db.session.commit()
    except Exception as e:
        log.error(f"[PROFILE] Erro ao confirmar troca de email de {user.username}: {e}")
        db.session.rollback()
        flash("Falha interna durante a validação. Tente mais tarde.", "danger")
        return redirect(url_for("profile.profile_page"))

    audit("EMAIL_CHANGED", actor=user.username, target_type="user", details=f"{old_email} → {user.email}")
    flash("Email atualizado com sucesso!", "success")
    if session.get("soc_user"):
        return redirect(url_for("profile.profile_page"))
    return redirect(url_for("auth.login_page"))


@profile_bp.route("/profile/notifications", methods=["POST"])
@require_login
def update_notifications():
    import json
    user = _current_user()
    prefs = {
        "new_incident": "new_incident" in request.form,
        "agent_offline": "agent_offline" in request.form,
        "high_severity": "high_severity" in request.form,
        "login_new_ip": "login_new_ip" in request.form,
    }
    user.notification_prefs = json.dumps(prefs)
    db.session.commit()
    flash("Preferências de notificação salvas.", "success")
    return redirect(url_for("profile.profile_page"))
