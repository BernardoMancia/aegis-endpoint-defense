import io
import json
import base64
import secrets
from datetime import datetime, timedelta
from flask import (Blueprint, request, render_template, session,
                   redirect, url_for, flash, jsonify, abort)
from extensions import db, log
from models.user import SocUser, LoginHistory, ROLES
from services.audit_service import audit

auth_bp = Blueprint("auth", __name__)

MFA_ISSUER = "Aegis SOC"
MAX_FAILED = 5
LOCKOUT_MINUTES = 15


def _get_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()


def _record_login(user, success, reason=None):
    record = LoginHistory(
        user_id=user.id,
        ip_address=_get_ip(),
        user_agent=request.headers.get("User-Agent", "")[:256],
        success=success,
        reason=reason,
    )
    db.session.add(record)
    if success:
        user.last_login_at = datetime.utcnow()
        user.last_login_ip = _get_ip()
        user.failed_logins = 0
        user.locked_until = None
    else:
        user.failed_logins = (user.failed_logins or 0) + 1
        if user.failed_logins >= MAX_FAILED:
            user.locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
    db.session.commit()


def _set_session(user):
    session.permanent = True
    session["soc_user"] = user.username
    session["soc_display"] = user.display_name or user.username
    session["soc_role"] = user.role
    session["soc_uid"] = user.id


@auth_bp.route("/login", methods=["GET"])
def login_page():
    if session.get("soc_user"):
        return redirect(url_for("dashboard.index"))
    return render_template("login.html", error=None, success=None)


@auth_bp.route("/login", methods=["POST"])
def do_login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    ip = _get_ip()

    user = SocUser.query.filter_by(username=username).first()

    if not user:
        return render_template("login.html", error="Credenciais inválidas.", success=None)

    if user.is_locked:
        mins = user.lock_remaining_minutes
        return render_template("login.html",
            error=f"Conta bloqueada por tentativas excessivas. Tente novamente em {mins} minuto(s).",
            success=None)

    if not user.check_password(password):
        _record_login(user, False, "Senha incorreta")
        remaining = MAX_FAILED - (user.failed_logins or 0)
        if remaining > 0:
            return render_template("login.html",
                error=f"Credenciais inválidas. {remaining} tentativa(s) restante(s) antes do bloqueio.",
                success=None)
        return render_template("login.html",
            error=f"Conta bloqueada por {LOCKOUT_MINUTES} minutos por tentativas excessivas.",
            success=None)

    if user.status == "pending":
        return render_template("login.html", error="Cadastro aguardando aprovação do administrador.", success=None)
    if user.status == "rejected":
        return render_template("login.html", error="Seu cadastro foi rejeitado. Entre em contato com o administrador.", success=None)

    if user.mfa_enabled:
        session["mfa_pending_user"] = user.id
        return redirect(url_for("auth.mfa_verify_page"))

    _record_login(user, True)
    _set_session(user)
    audit("USER_LOGIN", actor=user.username, target_type="auth", details=f"Login de {ip}")
    return redirect(url_for("dashboard.index"))


@auth_bp.route("/logout")
def do_logout():
    actor = session.get("soc_user", "unknown")
    session.clear()
    audit("USER_LOGOUT", actor=actor, target_type="auth")
    return redirect(url_for("auth.login_page"))


@auth_bp.route("/register", methods=["POST"])
def do_register():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    display_name = request.form.get("display_name", "").strip()
    email = request.form.get("email", "").strip()
    reason = request.form.get("reason", "").strip()

    if not username or not password:
        return render_template("login.html", error="Username e senha são obrigatórios.", success=None, show_register=True)
    if len(password) < 8:
        return render_template("login.html", error="A senha deve ter ao menos 8 caracteres.", success=None, show_register=True)
    if SocUser.query.filter_by(username=username).first():
        return render_template("login.html", error="Este username já está em uso.", success=None, show_register=True)

    new_user = SocUser(
        username=username,
        display_name=display_name or username,
        password_hash=SocUser.hash_password(password),
        email=email,
        reason=reason,
        status="pending",
        role="viewer",
    )
    db.session.add(new_user)
    try:
        db.session.commit()
    except Exception as e:
        log.error(f"[AUTH] Erro ao registrar {username}: {e}")
        db.session.rollback()
        return render_template("login.html", error="Falha interna no servidor ao tentar registrar. Tente novamente.", success=None, show_register=True)

    audit("USER_REGISTER_REQUEST", actor=username, target_type="auth", details=f"Solicitação: {reason[:80]}")
    return render_template("login.html", error=None, success="Solicitação enviada! Aguarde aprovação.")


@auth_bp.route("/mfa/verify", methods=["GET"])
def mfa_verify_page():
    if not session.get("mfa_pending_user"):
        return redirect(url_for("auth.login_page"))
    return render_template("mfa_verify.html")


@auth_bp.route("/mfa/verify", methods=["POST"])
def mfa_do_verify():
    import pyotp
    uid = session.get("mfa_pending_user")
    if not uid:
        return redirect(url_for("auth.login_page"))
    user = SocUser.query.get(uid)
    if not user:
        session.pop("mfa_pending_user", None)
        return redirect(url_for("auth.login_page"))

    code = request.form.get("code", "").strip().replace(" ", "")

    recovery_code = request.form.get("recovery_code", "").strip()
    if recovery_code:
        if user.use_recovery_code(recovery_code):
            try:
                db.session.commit()
            except Exception as e:
                log.error(f"[AUTH] Erro ao salvar login de recuperação de {user.username}: {e}")
                db.session.rollback()
                return render_template("mfa_verify.html", error="Erro interno ao processar recuperação.")

            session.pop("mfa_pending_user", None)
            _record_login(user, True)
            _set_session(user)
            audit("USER_LOGIN_RECOVERY", actor=user.username, target_type="auth", details="Login via código de recuperação")
            return redirect(url_for("dashboard.index"))
        return render_template("mfa_verify.html", error="Código de recuperação inválido ou já utilizado.")

    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(code, valid_window=1):
        return render_template("mfa_verify.html", error="Código MFA inválido. Tente novamente.")

    session.pop("mfa_pending_user", None)
    _record_login(user, True)
    _set_session(user)
    audit("USER_LOGIN_MFA", actor=user.username, target_type="auth", details=f"Login com MFA de {_get_ip()}")
    return redirect(url_for("dashboard.index"))


@auth_bp.route("/mfa/setup", methods=["GET"])
def mfa_setup_page():
    if "soc_user" not in session:
        return redirect(url_for("auth.login_page"))
    import pyotp
    import qrcode
    user = SocUser.query.filter_by(username=session["soc_user"]).first_or_404()
    if not user.mfa_secret:
        user.mfa_secret = pyotp.random_base32()
        db.session.commit()
    totp = pyotp.TOTP(user.mfa_secret)
    uri = totp.provisioning_uri(name=user.username, issuer_name=MFA_ISSUER)
    qr = qrcode.make(uri)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()
    return render_template("mfa_setup.html", qr_b64=qr_b64, secret=user.mfa_secret, mfa_enabled=user.mfa_enabled)


@auth_bp.route("/mfa/confirm", methods=["POST"])
def mfa_confirm():
    if "soc_user" not in session:
        return redirect(url_for("auth.login_page"))
    import pyotp
    user = SocUser.query.filter_by(username=session["soc_user"]).first_or_404()
    code = request.form.get("code", "").strip()
    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(code, valid_window=1):
        flash("Código inválido. Escaneie o QR novamente e tente.", "danger")
        return redirect(url_for("auth.mfa_setup_page"))
    user.mfa_enabled = True
    codes = user.generate_recovery_codes()
    try:
        db.session.commit()
    except Exception as e:
        log.error(f"[AUTH] Erro ao ativar MFA de {user.username}: {e}")
        db.session.rollback()
        flash("Falha interna ao ativar o MFA. Tente novamente.", "danger")
        return redirect(url_for("auth.mfa_setup_page"))

    audit("MFA_ENABLED", actor=user.username, target_type="auth")
    flash("MFA ativado com sucesso!", "success")
    return render_template("mfa_recovery.html", codes=codes)


@auth_bp.route("/mfa/disable", methods=["POST"])
def mfa_disable():
    if "soc_user" not in session:
        return redirect(url_for("auth.login_page"))
    import pyotp
    user = SocUser.query.filter_by(username=session["soc_user"]).first_or_404()
    password = request.form.get("password", "")
    code = request.form.get("code", "").strip()
    if not user.check_password(password):
        flash("Senha incorreta.", "danger")
        return redirect(url_for("profile.profile_page"))
    if user.mfa_enabled:
        totp = pyotp.TOTP(user.mfa_secret)
        if not totp.verify(code, valid_window=1):
            flash("Código MFA inválido.", "danger")
            return redirect(url_for("profile.profile_page"))
    user.mfa_enabled = False
    user.mfa_secret = None
    user.mfa_recovery_codes = None
    try:
        db.session.commit()
    except Exception as e:
        log.error(f"[AUTH] Erro ao desativar MFA de {user.username}: {e}")
        db.session.rollback()
        flash("Falha interna ao desativar o MFA.", "danger")
        return redirect(url_for("profile.profile_page"))

    audit("MFA_DISABLED", actor=user.username, target_type="auth")
    flash("MFA desativado.", "warning")
    return redirect(url_for("profile.profile_page"))
