import json
from datetime import datetime, timedelta
from extensions import db


class Agent(db.Model):
    __tablename__ = "agents"
    id = db.Column(db.Integer, primary_key=True)
    original_hostname = db.Column(db.String(255), unique=True, nullable=False, index=True)
    hostname = db.Column(db.String(255))
    ip_address = db.Column(db.String(64))
    mac_address = db.Column(db.String(64))
    os_info = db.Column(db.String(512))
    agent_version = db.Column(db.String(32))
    platform = db.Column(db.String(32), default="windows")
    status = db.Column(db.String(16), default="online")
    isolation_active = db.Column(db.Boolean, default=False)
    tags = db.Column(db.Text, default="[]")
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    registered_at = db.Column(db.DateTime, default=datetime.utcnow)
    pending_command = db.Column(db.Text)
    pending_command_time = db.Column(db.DateTime)
    last_screenshot = db.Column(db.Text)
    extra_data = db.Column(db.Text, default="{}")
    command_result = db.Column(db.Text)
    command_result_time = db.Column(db.DateTime)
    chat_requested = db.Column(db.Boolean, default=False)
    is_uninstalled = db.Column(db.Boolean, default=False)

    events = db.relationship("SecurityEvent", backref="agent", lazy="dynamic", cascade="all,delete-orphan")
    incidents = db.relationship("Incident", backref="agent", lazy="dynamic", cascade="all,delete-orphan")

    def to_dict(self):
        from models.chat import AgentChat
        now = datetime.utcnow()
        last_seen_dt = self.last_seen or now
        
        # 45 seconds tolerance for heartbeat (which is every 15s)
        offline_threshold = now - timedelta(seconds=45)
        
        if getattr(self, "is_uninstalled", False):
            computed_status = "uninstalled"
        elif self.isolation_active:
            computed_status = "isolated"
        elif last_seen_dt > offline_threshold:
            # If last_seen is very recent (or even slightly in the future due to drift), it's online
            computed_status = "online"
        else:
            computed_status = "offline"
        return {
            "id": self.id,
            "original_hostname": self.original_hostname,
            "hostname": self.hostname or self.original_hostname,
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "os_info": self.os_info,
            "agent_version": self.agent_version,
            "platform": self.platform,
            "status": computed_status,
            "is_uninstalled": getattr(self, "is_uninstalled", False),
            "isolation_active": self.isolation_active,
            "tags": json.loads(self.tags or "[]"),
            "last_seen": last_seen_dt.isoformat(),
            "registered_at": self.registered_at.isoformat() if self.registered_at else None,
            "pending_command": json.loads(self.pending_command) if self.pending_command else None,
            "extra_data": json.loads(self.extra_data or "{}"),
            "command_result": json.loads(self.command_result) if self.command_result else None,
            "command_result_time": self.command_result_time.isoformat() if self.command_result_time else None,
            "last_screenshot": bool(self.last_screenshot),
            "chat_requested": self.chat_requested,
            "has_unread_chat": AgentChat.query.filter_by(agent_id=self.id, sender="agent", is_read=False).count() > 0,
        }
