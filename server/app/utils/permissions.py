from functools import wraps
from flask import session, abort, redirect, url_for, flash
from models.user import ROLES


ROLE_LEVELS = {role: info["level"] for role, info in ROLES.items()}

PERMISSIONS = {
    "manage_roles":       ["superadmin"],
    "delete_users":       ["superadmin"],
    "approve_users":      ["superadmin", "admin"],
    "reset_passwords":    ["superadmin", "admin"],
    "view_audit":         ["superadmin", "admin"],
    "manage_incidents":   ["superadmin", "admin", "analyst"],
    "execute_soar":       ["superadmin", "admin", "analyst", "operator"],
    "view_dashboard":     ["superadmin", "admin", "analyst", "operator", "viewer"],
}


def current_role():
    return session.get("soc_role", "viewer")


def current_user_level():
    return ROLE_LEVELS.get(current_role(), 1)


def has_permission(action: str) -> bool:
    allowed = PERMISSIONS.get(action, [])
    return current_role() in allowed


def require_role(*roles):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if "soc_user" not in session:
                return redirect(url_for("auth.login"))
            if current_role() not in roles:
                flash("Acesso negado. Você não tem permissão para esta área.", "danger")
                return abort(403)
            return f(*args, **kwargs)
        return wrapper
    return decorator


def require_login(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "soc_user" not in session:
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return wrapper


def require_min_role(min_role: str):
    min_level = ROLE_LEVELS.get(min_role, 1)
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if "soc_user" not in session:
                return redirect(url_for("auth.login"))
            if current_user_level() < min_level:
                flash("Acesso negado. Seu nível de acesso é insuficiente.", "danger")
                return abort(403)
            return f(*args, **kwargs)
        return wrapper
    return decorator


require_admin = require_role("admin", "superadmin")
require_superadmin = require_role("superadmin")
require_analyst = require_min_role("analyst")
require_operator = require_min_role("operator")
