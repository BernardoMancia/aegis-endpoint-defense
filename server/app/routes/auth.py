from flask import Blueprint, request, jsonify, render_template, session, redirect, url_for
from datetime import datetime
from extensions import db
from models.user import SocUser
from services.audit_service import audit

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET"])
def login_page():
    if session.get("soc_user"):
        return redirect(url_for("dashboard.index"))
    return render_template("login.html", error=None, success=None)


@auth_bp.route("/login", methods=["POST"])
def do_login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    user = SocUser.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return render_template("login.html", error="Credenciais inválidas.", success=None)
    if user.status == "pending":
        return render_template("login.html", error="Cadastro aguardando aprovação do administrador.", success=None)
    if user.status == "rejected":
        return render_template("login.html", error="Seu cadastro foi recusado. Entre em contato com o administrador.", success=None)
    session.permanent = True
    session["soc_user"] = user.username
    session["soc_display"] = user.display_name or user.username
    session["soc_role"] = user.role
    audit("USER_LOGIN", actor=user.username, target_type="auth", details="Login bem-sucedido")
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
    if len(password) < 6:
        return render_template("login.html", error="A senha deve ter ao menos 6 caracteres.", success=None, show_register=True)
    if SocUser.query.filter_by(username=username).first():
        return render_template("login.html", error="Este username já está em uso.", success=None, show_register=True)

    new_user = SocUser(
        username=username,
        display_name=display_name or username,
        password_hash=SocUser.hash_password(password),
        email=email,
        reason=reason,
        status="pending",
        role="analyst",
    )
    db.session.add(new_user)
    db.session.commit()
    audit("USER_REGISTER_REQUEST", actor=username, target_type="auth", details=f"Solicitação de cadastro: {reason[:80]}")
    return render_template("login.html", error=None, success="Solicitação enviada! Aguarde aprovação do administrador.")
