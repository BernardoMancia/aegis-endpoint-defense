from datetime import datetime
from flask import Blueprint, request, jsonify
from extensions import db, log
from models.chat import ChatMessage, AgentChat
from models.agent import Agent
from services.ai_service import get_ai_response
from services.audit_service import audit

chat_bp = Blueprint("chat", __name__)


@chat_bp.route("/api/chat", methods=["POST"])
def ai_chat():
    data = request.get_json(silent=True) or {}
    message = data.get("message", "").strip()
    sess = data.get("session", "default")
    if not message:
        return jsonify({"error": "message obrigatório"}), 400
    user_msg = ChatMessage(session=sess, role="user", content=message)
    db.session.add(user_msg)
    db.session.flush()
    history = ChatMessage.query.filter_by(session=sess).order_by(ChatMessage.timestamp.asc()).limit(10).all()
    response_text, model_used = get_ai_response(message, history)
    assist_msg = ChatMessage(session=sess, role="assistant", content=response_text, model_used=model_used)
    db.session.add(assist_msg)
    db.session.commit()
    return jsonify({
        "response": response_text,
        "model": model_used,
        "session": sess,
        "timestamp": assist_msg.timestamp.isoformat(),
    })


@chat_bp.route("/api/chat/history")
def chat_history():
    sess = request.args.get("session", "default")
    limit = min(request.args.get("limit", 50, type=int), 200)
    msgs = ChatMessage.query.filter_by(session=sess).order_by(ChatMessage.timestamp.asc()).limit(limit).all()
    return jsonify([m.to_dict() for m in msgs])


@chat_bp.route("/api/chat/clear", methods=["DELETE"])
def clear_chat():
    sess = request.args.get("session", "default")
    ChatMessage.query.filter_by(session=sess).delete()
    db.session.commit()
    return jsonify({"status": "ok"})


@chat_bp.route("/api/chat/agent/<int:agent_id>/send", methods=["POST"])
def admin_send_chat(agent_id):
    from flask import session
    if not session.get("soc_user") or session.get("soc_role") not in ["admin", "superadmin"]:
        return jsonify({"error": "Não autorizado"}), 403

    data = request.get_json(silent=True) or {}
    message = data.get("message", "").strip()
    if not message:
        return jsonify({"error": "Mensagem vazia"}), 400
    agent = Agent.query.get_or_404(agent_id)
    chat_msg = AgentChat(agent_id=agent.id, sender="admin", message=message, is_read=False)
    db.session.add(chat_msg)
    try:
        db.session.commit()
    except Exception as e:
        log.error(f"[CHAT] Erro ao salvar msg do admin para agente {agent_id}: {e}")
        db.session.rollback()
        return jsonify({"error": "Falha no banco de dados"}), 500
    return jsonify({"status": "ok", "msg": chat_msg.to_dict()})


@chat_bp.route("/api/chat/agent/poll", methods=["POST"])
def agent_poll_chat():
    from flask import current_app, abort
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "").strip()
    if token != current_app.config["API_TOKEN"]:
        abort(401)
    data = request.get_json(silent=True) or {}
    original_hostname = data.get("original_hostname")
    message = data.get("message", "").strip()
    agent = Agent.query.filter_by(original_hostname=original_hostname).first()
    if not agent:
        return jsonify({"error": "Agente não encontrado"}), 404
    if message:
        new_msg = AgentChat(agent_id=agent.id, sender="agent", message=message, is_read=False)
        db.session.add(new_msg)
        audit("AGENT_CHAT", target_type="agent", target_id=agent.id, details="Agente enviou msg no chat")
    unread = AgentChat.query.filter_by(agent_id=agent.id, sender="admin", is_read=False).order_by(AgentChat.timestamp.asc()).all()
    response_msgs = [m.to_dict() for m in unread]
    for m in unread:
        m.is_read = True
    try:
        db.session.commit()
    except Exception as e:
        log.error(f"[CHAT] Erro ao sincronizar pool do agente {agent.id}: {e}")
        db.session.rollback()
    return jsonify({"messages": response_msgs})


@chat_bp.route("/api/chat/agent/<int:agent_id>/history")
def get_agent_chat_history(agent_id):
    agent = Agent.query.get_or_404(agent_id)
    history = AgentChat.query.filter_by(agent_id=agent.id).order_by(AgentChat.timestamp.asc()).limit(50).all()
    for h in history:
        if h.sender == "agent" and not h.is_read:
            h.is_read = True
    db.session.commit()
    return jsonify([m.to_dict() for m in history])
