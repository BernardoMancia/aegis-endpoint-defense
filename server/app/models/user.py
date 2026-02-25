import hashlib
import os
from datetime import datetime
from extensions import db


class SocUser(db.Model):
    __tablename__ = "soc_users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    display_name = db.Column(db.String(128))
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(16), default="analyst")
    status = db.Column(db.String(16), default="pending")
    email = db.Column(db.String(256))
    reason = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved_at = db.Column(db.DateTime)
    approved_by = db.Column(db.String(64))

    @staticmethod
    def hash_password(password: str) -> str:
        salt = os.getenv("AEGIS_SECRET_KEY", "aegis-salt")
        return hashlib.sha256(f"{salt}{password}".encode()).hexdigest()

    def check_password(self, password: str) -> bool:
        return self.password_hash == SocUser.hash_password(password)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "display_name": self.display_name or self.username,
            "role": self.role,
            "status": self.status,
            "email": self.email,
            "reason": self.reason,
            "created_at": self.created_at.isoformat(),
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "approved_by": self.approved_by,
        }
