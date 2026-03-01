import json
from datetime import datetime, timedelta
from functools import wraps
from flask import Blueprint, request, jsonify, abort, current_app
from extensions import db, log
from models.agent import Agent
from models.event import SecurityEvent
from models.incident import Incident
from services.audit_service import audit
from services.siem_engine import SIEMEngine

agents_bp = Blueprint("agents", __name__)


def require_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        token = auth.replace("Bearer ", "").strip()
        if token != current_app.config["API_TOKEN"]:
            audit("UNAUTHORIZED_ACCESS", actor="unknown", target_type="api",
                  details=f"Token inválido: {token[:8]}...")
            abort(401)
        return f(*args, **kwargs)
    return decorated


@agents_bp.route("/api/health")
def health():
    return jsonify({"status": "ok", "server": "Aegis C2", "timestamp": datetime.utcnow().isoformat()})


@agents_bp.route("/api/agents")
def list_agents():
    agents = Agent.query.filter_by(is_uninstalled=False).order_by(Agent.last_seen.desc()).all()
    return jsonify([a.to_dict() for a in agents])


@agents_bp.route("/api/agents/<int:agent_id>", methods=["GET"])
def get_agent(agent_id):
    agent = Agent.query.get_or_404(agent_id)
    return jsonify(agent.to_dict())


@agents_bp.route("/api/agents/<int:agent_id>", methods=["DELETE"])
def delete_agent(agent_id):
    agent = Agent.query.get_or_404(agent_id)
    db.session.delete(agent)
    db.session.commit()
    audit("AGENT_DELETED", target_type="agent", target_id=agent_id)
    return jsonify({"status": "ok"})


@agents_bp.route("/api/heartbeat", methods=["POST"])
@require_token
def heartbeat():
    data = request.get_json(silent=True) or {}
    original_hostname = data.get("original_hostname") or data.get("hostname")
    if not original_hostname:
        return jsonify({"error": "original_hostname obrigatório"}), 400

    agent = Agent.query.filter_by(original_hostname=original_hostname).order_by(Agent.id.desc()).first()
    if not agent:
        agent = Agent(original_hostname=original_hostname, hostname=data.get("hostname", original_hostname))
        db.session.add(agent)
        audit("AGENT_REGISTERED", actor="agent", target_type="agent", target_id=original_hostname)
        log.info(f"[C2] Novo agente registrado: {original_hostname}")
    elif agent.is_uninstalled and not agent.pending_command:
        agent.is_uninstalled = False
        audit("AGENT_REVIVED", actor="agent", target_type="agent", target_id=original_hostname)
        log.info(f"[C2] Agente reativado apos desinstalacao ou reinstalacao identificada: {original_hostname}")

    agent.ip_address = data.get("ip_address", agent.ip_address)
    agent.mac_address = data.get("mac_address", agent.mac_address)
    agent.os_info = data.get("os_info", agent.os_info)
    agent.agent_version = data.get("agent_version", agent.agent_version)
    agent.platform = data.get("platform", agent.platform or "windows")
    agent.last_seen = datetime.utcnow()
    extra = data.get("extra_data", {})
    if extra:
        agent.extra_data = json.dumps(extra)

    pending = None
    if agent.pending_command:
        pending = json.loads(agent.pending_command)
        agent.pending_command = None
        agent.pending_command_time = None

    db.session.commit()
    return jsonify({"status": "ok", "agent_id": agent.id, "pending_command": pending})


@agents_bp.route("/api/ingest_logs", methods=["POST"])
@require_token
def ingest_logs():
    data = request.get_json(silent=True) or {}
    original_hostname = data.get("original_hostname")
    events_list = data.get("events", [])
    if not original_hostname:
        return jsonify({"error": "original_hostname obrigatório"}), 400
    agent = Agent.query.filter_by(original_hostname=original_hostname).order_by(Agent.id.desc()).first()
    if not agent:
        return jsonify({"error": "Agente não encontrado"}), 404
    events_list = events_list[:500]
    new_incidents = SIEMEngine.process_events(agent, events_list)
    return jsonify({
        "status": "ok",
        "events_processed": len(events_list),
        "incidents_created": len(new_incidents),
        "incident_ids": [inc.id for inc in new_incidents if inc],
    })


@agents_bp.route("/api/ingest_android", methods=["POST"])
@require_token
def ingest_android():
    data = request.get_json(silent=True) or {}
    original_hostname = data.get("original_hostname")
    if not original_hostname:
        return jsonify({"error": "original_hostname obrigatório"}), 400
    agent = Agent.query.filter_by(original_hostname=original_hostname).first()
    if not agent:
        agent = Agent(original_hostname=original_hostname, hostname=original_hostname, platform="android")
        db.session.add(agent)
    agent.platform = "android"
    agent.last_seen = datetime.utcnow()
    agent.extra_data = json.dumps({
        "gps": data.get("gps"), "battery": data.get("battery"),
        "apps_count": len(data.get("installed_apps", [])),
        "installed_apps": data.get("installed_apps", [])[:20],
    })
    pending = None
    if agent.pending_command:
        pending = json.loads(agent.pending_command)
        agent.pending_command = None
    db.session.commit()
    return jsonify({"status": "ok", "pending_command": pending})


@agents_bp.route("/api/agent/request_chat", methods=["POST"])
@require_token
def agent_request_chat():
    data = request.get_json(silent=True) or {}
    original_hostname = data.get("original_hostname")
    if not original_hostname:
        return jsonify({"error": "original_hostname ausente"}), 400
    agent = Agent.query.filter_by(original_hostname=original_hostname).first()
    if not agent:
        return jsonify({"error": "Agente não encontrado"}), 404
    agent.chat_requested = True
    db.session.commit()
    return jsonify({"status": "ok"})


@agents_bp.route("/api/agent/resolve_chat", methods=["POST"])
@require_token
def resolve_chat():
    data = request.get_json(silent=True) or {}
    agent_id = data.get("agent_id")
    if not agent_id:
        return jsonify({"error": "agent_id ausente"}), 400
    agent = Agent.query.get(agent_id)
    if not agent:
        return jsonify({"error": "Agente não encontrado"}), 404
    agent.chat_requested = False
    db.session.commit()
    return jsonify({"status": "ok"})


@agents_bp.route("/api/agent/<int:agent_id>/detail")
def agent_detail(agent_id):
    agent = Agent.query.get_or_404(agent_id)
    recent_events = SecurityEvent.query.filter_by(agent_id=agent_id).order_by(SecurityEvent.timestamp.desc()).limit(20).all()
    open_incidents = Incident.query.filter_by(agent_id=agent_id, status="OPEN").order_by(Incident.created_at.desc()).limit(10).all()
    extra = json.loads(agent.extra_data or "{}")
    cmd_result = json.loads(agent.command_result) if agent.command_result else None
    return jsonify({
        "agent": agent.to_dict(),
        "recent_events": [e.to_dict() for e in recent_events],
        "open_incidents": [i.to_dict() for i in open_incidents],
        "extra_data": extra,
        "last_command_result": cmd_result,
        "event_count": agent.events.count(),
        "incident_count": agent.incidents.count(),
    })


@agents_bp.route("/api/command_output", methods=["POST"])
@require_token
def command_output():
    data = request.get_json(silent=True) or {}
    original_hostname = data.get("original_hostname")
    if not original_hostname:
        return jsonify({"error": "original_hostname obrigatório"}), 400
    agent = Agent.query.filter_by(original_hostname=original_hostname).first()
    if not agent:
        return jsonify({"error": "Agente não encontrado"}), 404
    result = {
        "command": data.get("command", ""),
        "output": data.get("output", ""),
        "exit_code": data.get("exit_code", 0),
        "timestamp": datetime.utcnow().isoformat(),
    }
    agent.command_result = json.dumps(result)
    agent.command_result_time = datetime.utcnow()
    db.session.commit()
    log.info(f"[C2] Output recebido de {agent.hostname}: {result['command'][:60]}")
    return jsonify({"status": "ok"})


@agents_bp.route("/api/stats")
def stats():
    agent_id = request.args.get("agent_id", type=int)
    from sqlalchemy import func
    from models.event import SecurityEvent
    from models.incident import Incident
    from models.ioc import IOC

    # Base active agents subquery or filter
    active_agents_ids = db.session.query(Agent.id).filter(Agent.is_uninstalled == False)

    total_agents = Agent.query.filter_by(is_uninstalled=False).count()
    online_thresh = datetime.utcnow() - timedelta(minutes=3)
    online_agents = Agent.query.filter(Agent.last_seen > online_thresh, Agent.isolation_active == False, Agent.is_uninstalled == False).count()
    isolated_agents = Agent.query.filter_by(isolation_active=True, is_uninstalled=False).count()

    # Event queries filtered by active agents
    evt_q = SecurityEvent.query.join(Agent).filter(Agent.is_uninstalled == False)
    if agent_id:
        evt_q = evt_q.filter(SecurityEvent.agent_id == agent_id)

    total_events = evt_q.count()
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    events_today = evt_q.filter(SecurityEvent.timestamp >= today_start).count()

    by_severity = dict(db.session.query(SecurityEvent.severity, func.count())
                       .join(Agent).filter(Agent.is_uninstalled == False)
                       .group_by(SecurityEvent.severity).all())
    
    by_category = dict(db.session.query(SecurityEvent.category, func.count())
                       .join(Agent).filter(Agent.is_uninstalled == False)
                       .group_by(SecurityEvent.category).all())

    hours_data = []
    for h in range(23, -1, -1):
        start = datetime.utcnow() - timedelta(hours=h + 1)
        end = datetime.utcnow() - timedelta(hours=h)
        q = SecurityEvent.query.join(Agent).filter(Agent.is_uninstalled == False, SecurityEvent.timestamp.between(start, end))
        if agent_id:
            q = q.filter(SecurityEvent.agent_id == agent_id)
        hours_data.append({"hour": end.strftime("%H:%M"), "count": q.count()})

    mitre_rows = db.session.query(SecurityEvent.mitre_technique, func.count())\
        .join(Agent).filter(Agent.is_uninstalled == False, SecurityEvent.mitre_technique.isnot(None))\
        .group_by(SecurityEvent.mitre_technique)\
        .order_by(func.count().desc()).limit(10).all()

    # Incident queries filtered by active agents
    open_incidents = Incident.query.join(Agent).filter(Agent.is_uninstalled == False, Incident.status == "OPEN").count()
    critical_incidents = Incident.query.join(Agent).filter(Agent.is_uninstalled == False, Incident.severity == "CRITICAL", Incident.status == "OPEN").count()

    ioc_count = IOC.query.filter_by(active=True).count()
    ioc_hits = db.session.query(func.sum(IOC.hit_count)).scalar() or 0

    return jsonify({
        "agents": {"total": total_agents, "online": online_agents, "isolated": isolated_agents},
        "events": {"total": total_events, "today": events_today, "by_severity": by_severity, "by_category": by_category},
        "incidents": {"open": open_incidents, "critical": critical_incidents},
        "threat_intel": {"ioc_count": ioc_count, "total_hits": ioc_hits},
        "chart_hours": hours_data,
        "top_mitre": [{"technique": t, "count": c} for t, c in mitre_rows],
    })
