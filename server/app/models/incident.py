import json
from datetime import datetime
from extensions import db


class Incident(db.Model):
    __tablename__ = "incidents"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(512), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(16), default="MEDIUM")
    status = db.Column(db.String(32), default="OPEN")
    agent_id = db.Column(db.Integer, db.ForeignKey("agents.id"), index=True)
    mitre_technique = db.Column(db.String(64))
    mitre_tactic = db.Column(db.String(64))
    events_linked = db.Column(db.Text, default="[]")
    playbook_steps = db.Column(db.Text, default="[]")
    assigned_to = db.Column(db.String(128))
    soar_actions = db.Column(db.Text, default="[]")
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)

    def to_dict(self):
        from models.agent import Agent
        agent = Agent.query.get(self.agent_id) if self.agent_id else None
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "agent_id": self.agent_id,
            "agent_hostname": agent.hostname if agent else "N/A",
            "mitre_technique": self.mitre_technique,
            "mitre_tactic": self.mitre_tactic,
            "events_linked": json.loads(self.events_linked or "[]"),
            "playbook_steps": json.loads(self.playbook_steps or "[]"),
            "assigned_to": self.assigned_to,
            "soar_actions": json.loads(self.soar_actions or "[]"),
            "notes": self.notes,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }
