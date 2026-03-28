import hashlib
import json
import os
import secrets
import bcrypt
from datetime import datetime
from extensions import db


ROLES = {
    "superadmin": {"level": 5, "label": "Super Administrador", "color": "danger"},
    "admin":      {"level": 4, "label": "Administrador",       "color": "warning"},
    "analyst":    {"level": 3, "label": "Analista SOC",        "color": "info"},
    "operator":   {"level": 2, "label": "Operador",            "color": "primary"},
    "viewer":     {"level": 1, "label": "Observador",          "color": "secondary"},
}


class LoginHistory(db.Model):
    __tablename__ = "login_history"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("soc_users.id"), nullable=False)
    ip_address = db.Column(db.String(64))
    user_agent = db.Column(db.String(256))
    success = db.Column(db.Boolean, default=True)
    reason = db.Column(db.String(128))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)


class SocUser(db.Model):
    __tablename__ = "soc_users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    display_name = db.Column(db.String(128))
    password_hash = db.Column(db.String(128), nullable=False)
    password_changed_at = db.Column(db.DateTime, default=datetime.utcnow)

    role = db.Column(db.String(16), default="viewer")
    status = db.Column(db.String(16), default="pending")
    email = db.Column(db.String(256))
    reason = db.Column(db.Text)
    avatar_url = db.Column(db.String(512))

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved_at = db.Column(db.DateTime)
    approved_by = db.Column(db.String(64))

    last_login_at = db.Column(db.DateTime)
    last_login_ip = db.Column(db.String(64))
    failed_logins = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)

    mfa_secret = db.Column(db.String(64))
    mfa_enabled = db.Column(db.Boolean, default=False)
    mfa_recovery_codes = db.Column(db.Text)

    pending_email = db.Column(db.String(256))
    email_token = db.Column(db.String(128))
    email_token_expires = db.Column(db.DateTime)

    notification_prefs = db.Column(db.Text, default='{"new_incident": true, "agent_offline": true, "high_severity": true, "login_new_ip": true}')

    login_history = db.relationship("LoginHistory", backref="user", lazy="dynamic", cascade="all, delete-orphan")

    @property
    def role_info(self):
        return ROLES.get(self.role, ROLES["viewer"])

    @property
    def role_level(self):
        return self.role_info["level"]

    @property
    def is_locked(self):
        if self.locked_until and self.locked_until > datetime.utcnow():
            return True
        return False

    @property
    def lock_remaining_minutes(self):
        if self.locked_until and self.locked_until > datetime.utcnow():
            diff = (self.locked_until - datetime.utcnow()).total_seconds()
            return max(1, int(diff // 60))
        return 0

    @property
    def notification_settings(self):
        try:
            return json.loads(self.notification_prefs or "{}")
        except Exception:
            return {}

    @staticmethod
    def hash_password(password: str) -> str:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    @staticmethod
    def _legacy_hash(password: str) -> str:
        salt = os.getenv("AEGIS_SECRET_KEY", "aegis-salt")
        return hashlib.sha256(f"{salt}{password}".encode()).hexdigest()

    def check_password(self, password: str) -> bool:
        if self.password_hash.startswith("$2b$"):
            return bcrypt.checkpw(password.encode(), self.password_hash.encode())
        if self.password_hash == SocUser._legacy_hash(password):
            self.password_hash = SocUser.hash_password(password)
            return True
        return False

    def generate_recovery_codes(self):
        codes = [secrets.token_hex(5).upper() for _ in range(8)]
        self.mfa_recovery_codes = json.dumps(codes)
        return codes

    def use_recovery_code(self, code: str) -> bool:
        codes = json.loads(self.mfa_recovery_codes or "[]")
        code = code.upper().strip()
        if code in codes:
            codes.remove(code)
            self.mfa_recovery_codes = json.dumps(codes)
            return True
        return False

    def can_manage(self, target_user) -> bool:
        if self.role == "superadmin":
            return True
        if target_user.role == "superadmin":
            return False
        return self.role_level > target_user.role_level

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "display_name": self.display_name or self.username,
            "role": self.role,
            "role_label": self.role_info["label"],
            "role_color": self.role_info["color"],
            "status": self.status,
            "email": self.email,
            "avatar_url": self.avatar_url,
            "mfa_enabled": self.mfa_enabled,
            "is_locked": self.is_locked,
            "reason": self.reason,
            "created_at": self.created_at.isoformat(),
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "approved_by": self.approved_by,
        }
