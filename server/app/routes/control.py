import json
from datetime import datetime
from functools import wraps
from flask import Blueprint, request, jsonify, abort, current_app
from extensions import db, log
from models.agent import Agent
from services.audit_service import audit

control_bp = Blueprint("control", __name__)


def require_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        token = auth.replace("Bearer ", "").strip()
        if token != current_app.config["API_TOKEN"]:
            abort(401)
        return f(*args, **kwargs)
    return decorated


QUICK_COMMANDS = {
    "PROCESSLIST": "tasklist /V /FO TABLE",
    "NETSTAT": "netstat -ano",
    "SYSINFO": "systeminfo",
    "SERVICES": "sc queryex type= all state= all",
    "USERS": "net user",
    "LOCALGROUPS": "net localgroup administrators",
    "STARTUP": "wmic startup get caption,command",
    "SCHEDTASKS": "schtasks /query /fo TABLE /v",
    "SHARES": "net share",
    "FIREWALL": "netsh advfirewall show allprofiles",
    "ENVVARS": "set",
    "HOTFIXES": "wmic qfe list brief",
}


@control_bp.route("/control/command", methods=["POST"])
@require_token
def send_command():
    data = request.get_json(silent=True) or {}
    agent_id = data.get("agent_id")
    command_str = data.get("command", "").strip()
    if not agent_id or not command_str:
        return jsonify({"error": "agent_id e command são obrigatórios"}), 400
    agent = Agent.query.get_or_404(agent_id)
    agent.pending_command = json.dumps({"command": "SHELL", "args": command_str})
    agent.pending_command_time = datetime.utcnow()
    db.session.commit()
    audit("COMMAND_SENT", target_type="agent", target_id=agent_id, details=command_str[:100])
    return jsonify({"status": "ok", "message": f"Comando enviado para {agent.hostname}"})


@control_bp.route("/control/quick_command", methods=["POST"])
@require_token
def quick_command():
    data = request.get_json(silent=True) or {}
    agent_id = data.get("agent_id")
    cmd_type = data.get("type", "").upper()
    if not agent_id or cmd_type not in QUICK_COMMANDS:
        return jsonify({"error": f"agent_id e type válido obrigatórios. Tipos: {list(QUICK_COMMANDS.keys())}"}), 400
    agent = Agent.query.get_or_404(agent_id)
    cmd_str = QUICK_COMMANDS[cmd_type]
    agent.pending_command = json.dumps({"command": "SHELL", "args": cmd_str})
    agent.pending_command_time = datetime.utcnow()
    db.session.commit()
    audit("QUICK_COMMAND", target_type="agent", target_id=agent_id, details=f"{cmd_type}: {cmd_str}")
    return jsonify({"status": "ok", "command": cmd_str, "type": cmd_type})


@control_bp.route("/control/isolate", methods=["POST"])
@require_token
def isolate_host():
    data = request.get_json(silent=True) or {}
    agent_id = data.get("agent_id")
    if not agent_id:
        return jsonify({"error": "agent_id obrigatório"}), 400
    agent = Agent.query.get_or_404(agent_id)
    agent.isolation_active = True
    agent.status = "isolated"
    agent.pending_command = json.dumps({"command": "ISOLATE"})
    agent.pending_command_time = datetime.utcnow()
    db.session.commit()
    audit("MANUAL_ISOLATE", target_type="agent", target_id=agent_id)
    return jsonify({"status": "ok", "message": f"Host {agent.hostname} será isolado"})


@control_bp.route("/control/unisolate", methods=["POST"])
@require_token
def unisolate_host():
    data = request.get_json(silent=True) or {}
    agent_id = data.get("agent_id")
    if not agent_id:
        return jsonify({"error": "agent_id obrigatório"}), 400
    agent = Agent.query.get_or_404(agent_id)
    agent.isolation_active = False
    agent.status = "online"
    agent.pending_command = json.dumps({"command": "UNISOLATE"})
    agent.pending_command_time = datetime.utcnow()
    db.session.commit()
    audit("MANUAL_UNISOLATE", target_type="agent", target_id=agent_id)
    return jsonify({"status": "ok", "message": f"Host {agent.hostname} removido do isolamento"})


@control_bp.route("/control/wipe", methods=["POST"])
@require_token
def wipe_host():
    data = request.get_json(silent=True) or {}
    agent_id = data.get("agent_id")
    confirm = data.get("confirm", False)
    if not agent_id or not confirm:
        return jsonify({"error": "agent_id e confirm:true são obrigatórios"}), 400
    agent = Agent.query.get_or_404(agent_id)
    agent.pending_command = json.dumps({"command": "WIPE", "confirm": True})
    agent.pending_command_time = datetime.utcnow()
    db.session.commit()
    audit("WIPE_TRIGGERED", target_type="agent", target_id=agent_id,
          details="AÇÃO DESTRUTIVA — WIPE solicitado pelo analista")
    return jsonify({"status": "ok", "message": f"Wipe enfileirado para {agent.hostname}"})


@control_bp.route("/control/screenshot", methods=["POST"])
@require_token
def request_screenshot():
    data = request.get_json(silent=True) or {}
    agent_id = data.get("agent_id")
    if not agent_id:
        return jsonify({"error": "agent_id obrigatório"}), 400
    agent = Agent.query.get_or_404(agent_id)
    agent.pending_command = json.dumps({"command": "SCREENSHOT"})
    agent.pending_command_time = datetime.utcnow()
    db.session.commit()
    audit("SCREENSHOT_REQUESTED", target_type="agent", target_id=agent_id)
    return jsonify({"status": "ok", "message": f"Screenshot solicitado de {agent.hostname}"})


@control_bp.route("/api/screenshot/<int:agent_id>", methods=["POST"])
@require_token
def upload_screenshot(agent_id):
    agent = Agent.query.get_or_404(agent_id)
    data = request.get_json(silent=True) or {}
    agent.last_screenshot = data.get("screenshot_b64")
    db.session.commit()
    return jsonify({"status": "ok"})


@control_bp.route("/api/screenshot/<int:agent_id>", methods=["GET"])
def get_screenshot(agent_id):
    agent = Agent.query.get_or_404(agent_id)
    return jsonify({"screenshot_b64": agent.last_screenshot})


@control_bp.route("/api/soar/<int:agent_id>", methods=["POST"])
@require_token
def soar_action(agent_id):
    data = request.get_json(silent=True) or {}
    action = data.get("action")
    if not action:
        return jsonify({"error": "action obrigatória"}), 400
    agent = Agent.query.get_or_404(agent_id)
    soar_map = {
        "force_scan_vulns": {"type": "force_scan_vulns"},
        "force_scan_fim": {"type": "force_scan_fim"},
        "force_logs": {"type": "force_logs"},
        "force_scan_network": {"command": "SHELL", "args": "netstat -ano | findstr LISTENING"},
    }
    if action not in soar_map:
        return jsonify({"error": "action desconhecida"}), 400
    agent.pending_command = json.dumps(soar_map[action])
    agent.pending_command_time = datetime.utcnow()
    db.session.commit()
    audit("SOAR_ACTION", target_type="agent", target_id=agent_id, details=action)
    return jsonify({"status": "ok"})


@control_bp.route("/control/uninstall", methods=["POST"])
@require_token
def uninstall_agent():
    data = request.get_json(silent=True) or {}
    agent_id = data.get("agent_id")
    if not agent_id:
        return jsonify({"error": "agent_id obrigatório"}), 400
        
    agent = Agent.query.get_or_404(agent_id)
    # Envia o comando de auto-destruição
    agent.pending_command = json.dumps({"command": "UNINSTALL"})
    agent.pending_command_time = datetime.utcnow()
    # Ativa o soft delete do painel
    agent.is_uninstalled = True
    db.session.commit()
    
    audit("AGENT_UNINSTALL_REQUESTED", target_type="agent", target_id=agent_id,
          details=f"Desinstalação forçada enviada para {agent.hostname}")
          
    return jsonify({"status": "ok", "message": f"Ordem de desinstalação enviada para {agent.hostname}. O agente removerá a si mesmo do Windows."})

