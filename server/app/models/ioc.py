from datetime import datetime
from extensions import db


class IOC(db.Model):
    __tablename__ = "iocs"
    id = db.Column(db.Integer, primary_key=True)
    ioc_type = db.Column(db.String(32), index=True)
    value = db.Column(db.String(512), unique=True, nullable=False, index=True)
    threat_name = db.Column(db.String(256))
    severity = db.Column(db.String(16), default="HIGH")
    threat_feed = db.Column(db.String(128), default="manual")
    description = db.Column(db.Text)
    active = db.Column(db.Boolean, default=True)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen_at = db.Column(db.DateTime)
    hit_count = db.Column(db.Integer, default=0)

    def to_dict(self):
        return {
            "id": self.id,
            "ioc_type": self.ioc_type,
            "value": self.value,
            "threat_name": self.threat_name,
            "severity": self.severity,
            "threat_feed": self.threat_feed,
            "description": self.description,
            "active": self.active,
            "added_at": self.added_at.isoformat() if self.added_at else None,
            "last_seen_at": self.last_seen_at.isoformat() if self.last_seen_at else None,
            "hit_count": self.hit_count,
        }


class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(128), index=True)
    actor = db.Column(db.String(128), default="system")
    target_type = db.Column(db.String(64))
    target_id = db.Column(db.String(128))
    details = db.Column(db.Text)
    ip_source = db.Column(db.String(64))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "action": self.action,
            "actor": self.actor,
            "target_type": self.target_type,
            "target_id": self.target_id,
            "details": self.details,
            "ip_source": self.ip_source,
            "timestamp": self.timestamp.isoformat(),
        }
