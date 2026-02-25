from datetime import datetime
from extensions import db


class ChatMessage(db.Model):
    __tablename__ = "chat_messages"
    id = db.Column(db.Integer, primary_key=True)
    session = db.Column(db.String(64), default="default", index=True)
    role = db.Column(db.String(16))
    content = db.Column(db.Text)
    model_used = db.Column(db.String(64))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "session": self.session,
            "role": self.role,
            "content": self.content,
            "model_used": self.model_used,
            "timestamp": self.timestamp.isoformat(),
        }


class AgentChat(db.Model):
    __tablename__ = "agent_chats"
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.Integer, db.ForeignKey("agents.id"), index=True, nullable=False)
    sender = db.Column(db.String(16))
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "sender": self.sender,
            "message": self.message,
            "timestamp": self.timestamp.isoformat(),
            "is_read": self.is_read,
        }


class AgentVulnerability(db.Model):
    __tablename__ = "agent_vulnerabilities"
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.Integer, db.ForeignKey("agents.id"), index=True, nullable=False)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(16), default="MEDIUM")
    remediation_cmd = db.Column(db.Text)
    status = db.Column(db.String(16), default="OPEN")
    detected_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "remediation_cmd": self.remediation_cmd,
            "status": self.status,
            "detected_at": self.detected_at.isoformat(),
        }
