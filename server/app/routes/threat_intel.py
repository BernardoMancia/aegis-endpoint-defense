from datetime import datetime
from functools import wraps
from flask import Blueprint, request, jsonify, abort, current_app
from extensions import db, log
from models.ioc import IOC
from services.audit_service import audit

threat_intel_bp = Blueprint("threat_intel", __name__)


def require_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        token = auth.replace("Bearer ", "").strip()
        if token != current_app.config["API_TOKEN"]:
            audit("UNAUTHORIZED_ACCESS", actor="unknown", target_type="api",
                  details=f"Tentativa de check IoC sem token: {token[:8]}...")
            abort(401)
        return f(*args, **kwargs)
    return decorated

threat_intel_bp = Blueprint("threat_intel", __name__)


@threat_intel_bp.route("/api/threat_intel/ioc")
def list_iocs():
    ioc_type = request.args.get("type")
    q = IOC.query.filter_by(active=True)
    if ioc_type:
        q = q.filter_by(ioc_type=ioc_type)
    iocs = q.order_by(IOC.added_at.desc()).all()
    return jsonify([i.to_dict() for i in iocs])


@threat_intel_bp.route("/api/threat_intel/ioc", methods=["POST"])
def add_ioc():
    data = request.get_json(silent=True) or {}
    value = data.get("value", "").strip().lower()
    if not value:
        return jsonify({"error": "value obrigatório"}), 400
    existing = IOC.query.filter_by(value=value).first()
    if existing:
        existing.active = True
        existing.threat_name = data.get("threat_name", existing.threat_name)
        db.session.commit()
        return jsonify(existing.to_dict())
    ioc = IOC(
        ioc_type=data.get("ioc_type", "hash"),
        value=value,
        threat_name=data.get("threat_name"),
        severity=data.get("severity", "HIGH"),
        threat_feed=data.get("threat_feed", "manual"),
        description=data.get("description"),
    )
    db.session.add(ioc)
    db.session.commit()
    audit("IOC_ADDED", target_type="ioc", target_id=ioc.id, details=f"{ioc.ioc_type}:{value}")
    return jsonify(ioc.to_dict()), 201


@threat_intel_bp.route("/api/threat_intel/ioc/<int:ioc_id>", methods=["DELETE"])
def delete_ioc(ioc_id):
    ioc = IOC.query.get_or_404(ioc_id)
    ioc.active = False
    db.session.commit()
    audit("IOC_DELETED", target_type="ioc", target_id=ioc_id)
    return jsonify({"status": "ok"})


@threat_intel_bp.route("/api/ioc/check", methods=["POST"])
@require_token
def check_ioc_endpoint():
    data = request.get_json(silent=True) or {}
    value = data.get("value", "").strip().lower()
    if not value:
        return jsonify({"error": "value obrigatório"}), 400
    ioc = IOC.query.filter_by(value=value, active=True).first()
    if ioc:
        ioc.hit_count = (ioc.hit_count or 0) + 1
        ioc.last_seen_at = datetime.utcnow()
        db.session.commit()
        return jsonify({"matched": True, "ioc": ioc.to_dict()})
    return jsonify({"matched": False, "value": value})


@threat_intel_bp.route("/api/agent/<int:agent_id>/vulnerabilities")
def list_vulnerabilities(agent_id):
    from models.chat import AgentVulnerability
    vulns = AgentVulnerability.query.filter_by(agent_id=agent_id, status="OPEN").all()
    return jsonify([v.to_dict() for v in vulns])


@threat_intel_bp.route("/api/vulnerabilities", methods=["POST"])
def report_vulnerabilities():
    from models.agent import Agent
    from models.chat import AgentVulnerability
    from functools import wraps
    from flask import current_app, abort
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "").strip()
    if token != current_app.config["API_TOKEN"]:
        abort(401)
    data = request.get_json(silent=True) or {}
    original_hostname = data.get("original_hostname")
    vulns = data.get("vulnerabilities", [])
    if not original_hostname or not isinstance(vulns, list):
        return jsonify({"error": "Dados inválidos"}), 400
    agent = Agent.query.filter_by(original_hostname=original_hostname).first()
    if not agent:
        return jsonify({"error": "Agente não encontrado"}), 404
    current_open = AgentVulnerability.query.filter_by(agent_id=agent.id, status="OPEN").all()
    new_titles = [v.get("title") for v in vulns]
    for co in current_open:
        if co.title not in new_titles:
            co.status = "RESOLVED"
    for v_data in vulns:
        title = v_data.get("title")
        existing = AgentVulnerability.query.filter_by(agent_id=agent.id, title=title, status="OPEN").first()
        if not existing:
            new_v = AgentVulnerability(
                agent_id=agent.id,
                title=title,
                description=v_data.get("description", ""),
                severity=v_data.get("severity", "MEDIUM"),
                remediation_cmd=v_data.get("remediation_cmd", ""),
            )
            db.session.add(new_v)
    db.session.commit()
    return jsonify({"status": "ok", "message": f"{len(vulns)} vulnerabilidades reportadas"})
