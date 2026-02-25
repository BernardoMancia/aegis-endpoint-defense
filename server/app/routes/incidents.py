from datetime import datetime
from flask import Blueprint, request, jsonify
from extensions import db
from models.incident import Incident
from services.audit_service import audit

incidents_bp = Blueprint("incidents", __name__)


@incidents_bp.route("/api/incidents")
def list_incidents():
    status_filter = request.args.get("status")
    agent_id = request.args.get("agent_id", type=int)
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 50, type=int), 200)
    q = Incident.query
    if status_filter:
        q = q.filter_by(status=status_filter)
    if agent_id:
        q = q.filter_by(agent_id=agent_id)
    paginated = q.order_by(Incident.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    return jsonify({"incidents": [i.to_dict() for i in paginated.items], "total": paginated.total})


@incidents_bp.route("/api/incidents", methods=["POST"])
def create_incident():
    data = request.get_json(silent=True) or {}
    import json
    incident = Incident(
        title=data.get("title", "Incidente Manual"),
        description=data.get("description"),
        severity=data.get("severity", "MEDIUM"),
        agent_id=data.get("agent_id"),
        mitre_technique=data.get("mitre_technique"),
        mitre_tactic=data.get("mitre_tactic"),
        playbook_steps=json.dumps(data.get("playbook_steps", [])),
        assigned_to=data.get("assigned_to"),
    )
    db.session.add(incident)
    db.session.commit()
    audit("INCIDENT_CREATED", target_type="incident", target_id=incident.id, details=incident.title)
    return jsonify(incident.to_dict()), 201


@incidents_bp.route("/api/incidents/<int:incident_id>", methods=["PATCH"])
def update_incident(incident_id):
    incident = Incident.query.get_or_404(incident_id)
    data = request.get_json(silent=True) or {}
    allowed = {"status", "severity", "assigned_to", "notes", "title", "description"}
    for field in allowed:
        if field in data:
            setattr(incident, field, data[field])
    if data.get("status") in ("RESOLVED", "FALSE_POSITIVE") and not incident.resolved_at:
        incident.resolved_at = datetime.utcnow()
    incident.updated_at = datetime.utcnow()
    db.session.commit()
    audit("INCIDENT_UPDATED", target_type="incident", target_id=incident_id, details=str(data))
    return jsonify(incident.to_dict())


@incidents_bp.route("/api/audit")
def get_audit():
    from models.ioc import AuditLog
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 50, type=int), 200)
    action_filter = request.args.get("action")
    q = AuditLog.query
    if action_filter:
        q = q.filter(AuditLog.action.like(f"%{action_filter}%"))
    paginated = q.order_by(AuditLog.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)
    return jsonify({"logs": [l.to_dict() for l in paginated.items], "total": paginated.total})
