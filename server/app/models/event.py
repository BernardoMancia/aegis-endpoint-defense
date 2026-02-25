import json
from datetime import datetime
from extensions import db


class SecurityEvent(db.Model):
    __tablename__ = "security_events"
    id = db.Column(db.Integer, primary_key=True)
    agent_id = db.Column(db.Integer, db.ForeignKey("agents.id"), nullable=False, index=True)
    event_type = db.Column(db.String(128), index=True)
    severity = db.Column(db.String(16), default="LOW")
    source = db.Column(db.String(64), default="windows")
    category = db.Column(db.String(64))
    mitre_technique = db.Column(db.String(64))
    mitre_tactic = db.Column(db.String(64))
    raw_data = db.Column(db.Text)
    parsed_data = db.Column(db.Text, default="{}")
    ioc_matched = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "agent_id": self.agent_id,
            "event_type": self.event_type,
            "severity": self.severity,
            "source": self.source,
            "category": self.category,
            "mitre_technique": self.mitre_technique,
            "mitre_tactic": self.mitre_tactic,
            "raw_data": self.raw_data,
            "parsed_data": json.loads(self.parsed_data or "{}"),
            "ioc_matched": self.ioc_matched,
            "timestamp": self.timestamp.isoformat(),
        }
