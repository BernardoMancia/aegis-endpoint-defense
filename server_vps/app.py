"""
Aegis SIEM & EDR Platform - C2 Server
======================================
Backend Flask principal com:
- Modelos SQLAlchemy (Agent, SecurityEvent, Incident, ChatMessage, IOC, AuditLog)
- SIEM Engine com correlação de eventos e mapeamento MITRE ATT&CK
- API REST completa (heartbeat, ingest, SOAR, dashboard, threat intel, AI chat)
- Dashboard SOC via templates HTML
"""

import os
import json
import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from functools import wraps

import requests
from dotenv import load_dotenv
from flask import Flask, request, jsonify, render_template, abort, g, session, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from sqlalchemy import text, func

load_dotenv()



app = Flask(__name__)
CORS(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_db_env = os.getenv("DATABASE_PATH", "")

if _db_env:

    if not os.path.isabs(_db_env):
        _db_env = os.path.join(BASE_DIR, _db_env)
    DB_PATH = _db_env if _db_env.endswith(".db") else os.path.join(_db_env, "aegis.db")
else:
    DB_PATH = os.path.join(BASE_DIR, "data", "aegis.db")

os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)


app.config.update(
    SECRET_KEY=os.getenv("AEGIS_SECRET_KEY", secrets.token_hex(32)),
    SQLALCHEMY_DATABASE_URI=f"sqlite:///{DB_PATH}",
    SQLALCHEMY_ENGINE_OPTIONS={
        "connect_args": {"check_same_thread": False},
        "pool_size": 10,
        "pool_timeout": 30,
    },
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
)

db = SQLAlchemy(app)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("aegis")

API_TOKEN = os.getenv("AEGIS_API_TOKEN", "aegis-default-token-mude-agora")
if API_TOKEN == "":
    API_TOKEN = "aegis-default-token-mude-agora"
log.debug(f"[AEGIS] Token carregado: {API_TOKEN[:4]}...{API_TOKEN[-4:]}")


def enable_wal(connection, _):
    cursor = connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA cache_size=-64000")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

from sqlalchemy import event as sa_event




class Agent(db.Model):
    """Endpoint registrado no C2 — original_hostname é o ID imutável."""
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

    events = db.relationship("SecurityEvent", backref="agent", lazy="dynamic", cascade="all,delete-orphan")
    incidents = db.relationship("Incident", backref="agent", lazy="dynamic", cascade="all,delete-orphan")

    def to_dict(self):
        last_seen_dt = self.last_seen or datetime.utcnow()
        offline_threshold = datetime.utcnow() - timedelta(minutes=3)
        computed_status = "isolated" if self.isolation_active else (
            "online" if last_seen_dt > offline_threshold else "offline"
        )
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


class SecurityEvent(db.Model):
    """Evento de segurança ingerido de um endpoint."""
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


class Incident(db.Model):
    """Incidente de segurança criado pela SIEM Engine ou manualmente."""
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


class ChatMessage(db.Model):
    """Histórico do chat com o AI Assistant."""
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
    """Mensagens de chat direto entre SOC Admin e Agente."""
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
    """Vulnerabilidades detectadas localmente pelo Agente."""
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


class IOC(db.Model):
    """Indicador de Comprometimento (IoC) para threat intel."""
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
    """Log de auditoria de todas as ações no SOC."""
    __tablename__ = "audit_logs"
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(128), index=True)
    actor = db.Column(db.String(128), default="soc_analyst")
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





class SocUser(db.Model):
    __tablename__ = "soc_users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    display_name = db.Column(db.String(128))
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(16), default="analyst")
    status = db.Column(db.String(16), default="pending")
    email = db.Column(db.String(256))
    reason = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved_at = db.Column(db.DateTime)
    approved_by = db.Column(db.String(64))

    @staticmethod
    def hash_password(password: str) -> str:
        salt = os.getenv("AEGIS_SECRET_KEY", "aegis-salt")
        return hashlib.sha256(f"{salt}{password}".encode()).hexdigest()

    def check_password(self, password: str) -> bool:
        return self.password_hash == SocUser.hash_password(password)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "display_name": self.display_name or self.username,
            "role": self.role,
            "status": self.status,
            "email": self.email,
            "reason": self.reason,
            "created_at": self.created_at.isoformat(),
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "approved_by": self.approved_by,
        }


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("soc_user"):
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("soc_user"):
            return redirect(url_for("login_page"))
        if session.get("soc_role") != "admin":
            abort(403)
        return f(*args, **kwargs)
    return decorated


def require_token(f):
    """Valida o Bearer Token da API para endpoints de agentes."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        token = auth.replace("Bearer ", "").strip()
        print(f"[AUTH DEBUG] Recebido: '{token}' | Esperado: '{API_TOKEN}' | Iguais: {token == API_TOKEN}")
        if token != API_TOKEN:
            audit("UNAUTHORIZED_ACCESS", actor="unknown", target_type="api",
                  details=f"Tentativa com token inválido: {token[:8]}...")
            abort(401)
        return f(*args, **kwargs)
    return decorated




def audit(action, actor="system", target_type=None, target_id=None, details=None):
    """Registra uma ação no AuditLog."""
    try:
        entry = AuditLog(
            action=action,
            actor=actor,
            target_type=target_type,
            target_id=str(target_id) if target_id else None,
            details=details,
            ip_source=request.remote_addr if request else None,
        )
        db.session.add(entry)
        db.session.commit()
    except Exception as e:
        log.error(f"Falha ao gravar audit log: {e}")


def check_ioc(value: str) -> IOC | None:
    """Verifica se um valor bate com algum IoC ativo."""
    ioc = IOC.query.filter_by(value=value.lower(), active=True).first()
    if ioc:
        ioc.hit_count = (ioc.hit_count or 0) + 1
        ioc.last_seen_at = datetime.utcnow()
        db.session.commit()
    return ioc


def send_slack_alert(title: str, message: str, severity: str = "CRITICAL"):
    """Envia alerta para Slack (se configurado)."""
    webhook = os.getenv("SLACK_WEBHOOK_URL")
    if not webhook:
        return
    color = {"CRITICAL": "#ff0000", "HIGH": "#ff8c00", "MEDIUM": "#ffd700", "LOW": "#00ff00"}.get(severity, "#888")
    payload = {
        "attachments": [{
            "color": color,
            "title": f"🛡️ AEGIS ALERT — {severity}",
            "text": f"*{title}*\n{message}",
            "footer": "Aegis SIEM",
            "ts": int(datetime.utcnow().timestamp()),
        }]
    }
    try:
        requests.post(webhook, json=payload, timeout=5)
    except Exception as e:
        log.warning(f"Slack webhook falhou: {e}")




class SIEMEngine:
    """
    Motor de correlação de eventos de segurança com mapeamento MITRE ATT&CK.
    Mantém estado temporal em memória para detecção de padrões temporais.
    """

    _auth_failures: dict = defaultdict(list)
    _smb_targets:   dict = defaultdict(list)
    _upload_bytes:  dict = defaultdict(int)

    SUSPICIOUS_PROCESSES = {
        "mimikatz", "mimikatz64", "procdump", "pwdump", "lsass_dump",
        "wce", "gsecdump", "fgdump", "meterpreter", "cobalt_strike",
        "empire", "metasploit", "powersploit", "invoke-obfuscation",
        "rubeus", "bloodhound", "sharphound", "lazagne",
    }

    CRITICAL_EVENT_IDS = {
        "4625": ("Failed Logon", "MEDIUM", "auth", "T1110", "Credential Access"),
        "4648": ("Explicit Credential Logon", "MEDIUM", "auth", "T1078", "Defense Evasion"),
        "4657": ("Registry Value Modified", "MEDIUM", "registry", "T1112", "Defense Evasion"),
        "4672": ("Special Privileges Logon", "HIGH", "auth", "T1068", "Privilege Escalation"),
        "4688": ("Process Created", "LOW", "process", "T1059", "Execution"),
        "4697": ("Service Installed in System", "HIGH", "process", "T1543", "Persistence"),
        "4698": ("Scheduled Task Created", "MEDIUM", "process", "T1053", "Persistence"),
        "4720": ("User Account Created", "MEDIUM", "auth", "T1136", "Persistence"),
        "4732": ("Member Added to Security Group", "HIGH", "auth", "T1098", "Privilege Escalation"),
        "7045": ("New Service Installed", "MEDIUM", "process", "T1543.003", "Persistence"),
        "1102": ("Audit Log Cleared", "CRITICAL", "auth", "T1070.001", "Defense Evasion"),
        "4103": ("Script Block Logging", "MEDIUM", "process", "T1059.001", "Execution"),
        "4104": ("PowerShell Script Block", "HIGH", "process", "T1059.001", "Execution"),
    }

    @classmethod
    def process_events(cls, agent: Agent, events: list) -> list:
        """Processa uma lista de eventos e cria incidentes quando necessário."""
        created_incidents = []

        for evt_data in events:
            event = cls._store_event(agent, evt_data)
            if event:
                incidents = cls._correlate(agent, event, evt_data)
                created_incidents.extend(incidents)

        return created_incidents

    @classmethod
    def _store_event(cls, agent: Agent, evt_data: dict) -> SecurityEvent | None:
        """Persiste um evento no banco e verifica IoCs."""
        try:
            event_id = str(evt_data.get("event_id", ""))
            base = cls.CRITICAL_EVENT_IDS.get(event_id, ("Generic Event", "LOW", "generic", None, None))
            event_type = evt_data.get("event_type", base[0])
            severity = evt_data.get("severity", base[1])

            ioc_hit = False
            for field in ["hash", "ip", "domain", "parent_hash", "target_ip"]:
                val = evt_data.get(field, "")
                if val and check_ioc(val.lower()):
                    ioc_hit = True
                    severity = "CRITICAL"
                    break

            event = SecurityEvent(
                agent_id=agent.id,
                event_type=event_type,
                severity=severity,
                source=evt_data.get("source", "windows"),
                category=evt_data.get("category", base[2]),
                mitre_technique=evt_data.get("mitre_technique", base[3]),
                mitre_tactic=evt_data.get("mitre_tactic", base[4]),
                raw_data=json.dumps(evt_data),
                parsed_data=json.dumps(evt_data.get("parsed", {})),
                ioc_matched=ioc_hit,
                timestamp=datetime.utcnow(),
            )
            db.session.add(event)
            db.session.flush()
            return event
        except Exception as e:
            log.error(f"Erro ao salvar evento: {e}")
            db.session.rollback()
            return None

    @classmethod
    def _correlate(cls, agent: Agent, event: SecurityEvent, evt_data: dict) -> list:
        """Aplica as regras de correlação ao evento recém criado."""
        incidents = []
        now = datetime.utcnow()
        aid = agent.id
        eid_str = str(evt_data.get("event_id", ""))

        if eid_str == "4625":
            cls._auth_failures[aid].append(now)
            cls._auth_failures[aid] = [t for t in cls._auth_failures[aid] if now - t < timedelta(seconds=60)]
            if len(cls._auth_failures[aid]) >= 5:
                inc = cls._create_incident(
                    agent=agent,
                    title=f"🔑 Brute Force Detectado em {agent.hostname}",
                    description=f"Detectadas {len(cls._auth_failures[aid])} falhas de autenticação em 60 segundos.",
                    severity="HIGH",
                    mitre_technique="T1110",
                    mitre_tactic="Credential Access",
                    event=event,
                    playbook=["Bloquear conta do usuário alvo", "Verificar logs de origem", "Checar IPs relacionados no threat intel"],
                    soar_auto=False,
                )
                if inc:
                    incidents.append(inc)
                    cls._auth_failures[aid] = []

        elif eid_str == "4672":
            inc = cls._create_incident(
                agent=agent,
                title=f"⚠️ Escalada de Privilégio em {agent.hostname}",
                description="Logon com privilégios especiais detectado (Event ID 4672).",
                severity="CRITICAL",
                mitre_technique="T1068",
                mitre_tactic="Privilege Escalation",
                event=event,
                playbook=["Verificar identidade do usuário", "Analisar processo pai", "Isolar host se não autorizado", "Criar ticket de IR"],
                soar_auto=True,
            )
            if inc:
                incidents.append(inc)

        elif eid_str in ("7045", "4697"):
            inc = cls._create_incident(
                agent=agent,
                title=f"🔧 Novo Serviço Instalado em {agent.hostname}",
                description=f"Instalação de serviço detectada — Event ID {eid_str}.",
                severity="HIGH",
                mitre_technique="T1543.003",
                mitre_tactic="Persistence",
                event=event,
                playbook=["Identificar binário do serviço", "Verificar assinatura digital", "Comparar com baseline", "Remover se malicioso"],
                soar_auto=False,
            )
            if inc:
                incidents.append(inc)

        elif eid_str == "1102":
            inc = cls._create_incident(
                agent=agent,
                title=f"🗑️ Logs de Auditoria Apagados em {agent.hostname}",
                description="O log de auditoria do Windows foi limpo — possível tentativa de evasão.",
                severity="CRITICAL",
                mitre_technique="T1070.001",
                mitre_tactic="Defense Evasion",
                event=event,
                playbook=["Isolar host imediatamente", "Coletar imagem de memória", "Acionar IR team"],
                soar_auto=True,
            )
            if inc:
                incidents.append(inc)

        elif eid_str in ("4103", "4104"):
            inc = cls._create_incident(
                agent=agent,
                title=f"💻 Execução PowerShell Suspeita em {agent.hostname}",
                description="Script PowerShell registrado pelo ScriptBlock Logging.",
                severity="HIGH",
                mitre_technique="T1059.001",
                mitre_tactic="Execution",
                event=event,
                playbook=["Analisar conteúdo do script", "Verificar processo pai", "Checar conexões de rede oriundas do processo"],
                soar_auto=False,
            )
            if inc:
                incidents.append(inc)

        elif evt_data.get("process_name", "").lower() in cls.SUSPICIOUS_PROCESSES:
            proc = evt_data.get("process_name", "")
            inc = cls._create_incident(
                agent=agent,
                title=f"☠️ Processo Malicioso Detectado: {proc} em {agent.hostname}",
                description=f"Processo '{proc}' está na blacklist de ferramentas de ataque.",
                severity="CRITICAL",
                mitre_technique="T1003",
                mitre_tactic="Credential Access",
                event=event,
                playbook=["Encerrar processo imediatamente", "Isolar host", "Coletar dump de memória", "Verificar persistência"],
                soar_auto=True,
            )
            if inc:
                incidents.append(inc)

        if event.ioc_matched:
            inc = cls._create_incident(
                agent=agent,
                title=f"🎯 IoC Confirmado em {agent.hostname}",
                description=f"Hash/IP/Domínio do evento bate com ameaça conhecida no Threat Intel.",
                severity="CRITICAL",
                mitre_technique="T1071",
                mitre_tactic="Command and Control",
                event=event,
                playbook=["Isolar host", "Identificar origem do artefato", "Remover arquivo malicioso", "Verificar movimento lateral"],
                soar_auto=True,
            )
            if inc:
                incidents.append(inc)

        if evt_data.get("category") == "network" and evt_data.get("dest_port") in (445, 135, 139):
            target_ip = evt_data.get("dest_ip", "")
            if target_ip:
                cls._smb_targets[aid].append((now, target_ip))
                cls._smb_targets[aid] = [(t, ip) for t, ip in cls._smb_targets[aid] if now - t < timedelta(seconds=30)]
                unique_targets = len(set(ip for _, ip in cls._smb_targets[aid]))
                if unique_targets >= 3:
                    inc = cls._create_incident(
                        agent=agent,
                        title=f"🔀 Possível Movimento Lateral em {agent.hostname}",
                        description=f"Conexões SMB/RPC para {unique_targets} hosts diferentes em 30 segundos.",
                        severity="HIGH",
                        mitre_technique="T1021",
                        mitre_tactic="Lateral Movement",
                        event=event,
                        playbook=["Isolar host", "Mapear hosts de destino", "Verificar credenciais comprometidas", "Aplicar segmentação de rede"],
                        soar_auto=False,
                    )
                    if inc:
                        incidents.append(inc)
                        cls._smb_targets[aid] = []

        try:
            db.session.commit()
        except Exception as e:
            log.error(f"Erro ao commitar eventos: {e}")
            db.session.rollback()

        return incidents

    @classmethod
    def _create_incident(cls, agent, title, description, severity, mitre_technique,
                         mitre_tactic, event, playbook, soar_auto=False):
        """Cria um incidente e dispara SOAR se necessário."""

        two_hours_ago = datetime.utcnow() - timedelta(hours=2)
        existing = Incident.query.filter(
            Incident.agent_id == agent.id,
            Incident.mitre_technique == mitre_technique,
            Incident.created_at > two_hours_ago,
            Incident.status == "OPEN",
        ).first()
        if existing:

            linked = json.loads(existing.events_linked or "[]")
            linked.append(event.id)
            existing.events_linked = json.dumps(linked)
            existing.updated_at = datetime.utcnow()
            db.session.flush()
            return None

        soar_done = []
        if soar_auto:
            soar_done = cls._execute_soar(agent, mitre_technique)

        incident = Incident(
            title=title,
            description=description,
            severity=severity,
            status="OPEN",
            agent_id=agent.id,
            mitre_technique=mitre_technique,
            mitre_tactic=mitre_tactic,
            events_linked=json.dumps([event.id]),
            playbook_steps=json.dumps(playbook),
            soar_actions=json.dumps(soar_done),
        )
        db.session.add(incident)
        db.session.flush()

        if severity in ("CRITICAL", "HIGH"):
            send_slack_alert(title, description, severity)

        log.info(f"[SIEM] Incidente criado: {title} | {severity} @ {agent.hostname}")
        return incident

    @classmethod
    def _execute_soar(cls, agent: Agent, technique: str) -> list:
        """Executa ações SOAR automáticas baseadas na técnica MITRE."""
        actions = []
        if technique in ("T1068", "T1070.001", "T1003", "T1071", "T1543.003"):
            agent.isolation_active = True
            agent.status = "isolated"
            agent.pending_command = json.dumps({"command": "ISOLATE", "auto": True, "technique": technique})
            agent.pending_command_time = datetime.utcnow()
            actions.append({"action": "HOST_ISOLATED", "technique": technique, "timestamp": datetime.utcnow().isoformat()})
            log.warning(f"[SOAR] Host {agent.hostname} ISOLADO automaticamente — Técnica: {technique}")

        audit("SOAR_AUTO_ISOLATE", actor="siem_engine", target_type="agent",
              target_id=agent.id, details=f"MITRE: {technique}")
        return actions




@app.route("/api/health")
def health():
    """Healthcheck para Docker."""
    return jsonify({"status": "ok", "server": "Aegis C2", "timestamp": datetime.utcnow().isoformat()})


@app.route("/api/heartbeat", methods=["POST"])
@require_token
def heartbeat():
    """
    Recebe heartbeat de agentes Windows/Android.
    Cria ou atualiza o registro do agente e retorna comando pendente (se houver).
    """
    data = request.get_json(silent=True) or {}
    original_hostname = data.get("original_hostname") or data.get("hostname")
    if not original_hostname:
        return jsonify({"error": "original_hostname obrigatório"}), 400

    agent = Agent.query.filter_by(original_hostname=original_hostname).first()

    if not agent:
        agent = Agent(
            original_hostname=original_hostname,
            hostname=data.get("hostname", original_hostname),
        )
        db.session.add(agent)
        audit("AGENT_REGISTERED", actor="agent", target_type="agent", target_id=original_hostname)
        log.info(f"[C2] Novo agente registrado: {original_hostname}")

    agent.ip_address   = data.get("ip_address", agent.ip_address)
    agent.mac_address  = data.get("mac_address", agent.mac_address)
    agent.os_info      = data.get("os_info", agent.os_info)
    agent.agent_version = data.get("agent_version", agent.agent_version)
    agent.platform     = data.get("platform", agent.platform or "windows")
    agent.last_seen    = datetime.utcnow()
    extra              = data.get("extra_data", {})
    if extra:
        agent.extra_data = json.dumps(extra)

    pending = None
    if agent.pending_command:
        pending = json.loads(agent.pending_command)
        agent.pending_command = None
        agent.pending_command_time = None

    db.session.commit()
    return jsonify({"status": "ok", "agent_id": agent.id, "pending_command": pending})


@app.route("/api/ingest_logs", methods=["POST"])
@require_token
def ingest_logs():
    """
    Ingestão em lote de eventos de segurança vindos do agente Windows.
    Suporta até 500 eventos por chamada.
    """
    data = request.get_json(silent=True) or {}
    original_hostname = data.get("original_hostname")
    events_list = data.get("events", [])

    if not original_hostname:
        return jsonify({"error": "original_hostname obrigatório"}), 400

    agent = Agent.query.filter_by(original_hostname=original_hostname).first()
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


@app.route("/api/ingest_android", methods=["POST"])
@require_token
def ingest_android():
    """Recebe telemetria do agente Android."""
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
    extra = {
        "gps": data.get("gps"),
        "battery": data.get("battery"),
        "apps_count": len(data.get("installed_apps", [])),
        "installed_apps": data.get("installed_apps", [])[:20],
    }
    agent.extra_data = json.dumps(extra)

    pending = None
    if agent.pending_command:
        pending = json.loads(agent.pending_command)
        agent.pending_command = None

    db.session.commit()
    return jsonify({"status": "ok", "pending_command": pending})




@app.route("/api/agent/request_chat", methods=["POST"])
@require_token
def agent_request_chat():
    """Agente informa que o usuário Desktop solicitou Suporte do SOC."""
    data = request.get_json(silent=True) or {}
    log.info(f"Dados recebidos em request_chat: {data}")
    original_hostname = data.get("original_hostname")
    if not original_hostname:
        return jsonify({"error": "original_hostname ausente"}), 400

    agent = Agent.query.filter_by(original_hostname=original_hostname).first()
    if not agent:
        return jsonify({"error": "Agente não encontrado"}), 404

    agent.chat_requested = True
    db.session.commit()
    log.info(f"[C2] Solicitação de Suporte ativada pelo agente: {agent.hostname}")
    return jsonify({"status": "ok"})


@app.route("/api/agent/resolve_chat", methods=["POST"])
@require_token
def resolve_soc_chat():
    """Limpa a TAG de solicitação de suporte de um agente via painel Admin."""
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







@app.route("/api/register", methods=["POST"])
@require_token
def register_agent():
    data = request.get_json(silent=True) or {}
    agent_id = data.get("agent_id")
    command_str = data.get("command", "").strip()
    if not agent_id or not command_str:
        return jsonify({"error": "agent_id e command são obrigatórios"}), 400




    agent = Agent.query.get_or_404(agent_id)
    payload = {"command": "SHELL", "args": command_str}
    agent.pending_command = json.dumps(payload)
    agent.pending_command_time = datetime.utcnow()
    db.session.commit()

    audit("COMMAND_SENT", target_type="agent", target_id=agent_id, details=command_str[:100])
    return jsonify({"status": "ok", "message": f"Comando enviado para {agent.hostname}"})




@app.route("/control/command", methods=["POST"])
@require_token
def send_command():
    data = request.get_json(silent=True) or {}
    agent_id = data.get("agent_id")
    command_str = data.get("command", "").strip()
    if not agent_id or not command_str:
        return jsonify({"error": "agent_id e command são obrigatórios"}), 400

    agent = Agent.query.get_or_404(agent_id)
    payload = {"command": "SHELL", "args": command_str}
    agent.pending_command = json.dumps(payload)
    agent.pending_command_time = datetime.utcnow()
    db.session.commit()

    audit("COMMAND_SENT", target_type="agent", target_id=agent_id, details=command_str[:100])
    return jsonify({"status": "ok", "message": f"Comando enviado para {agent.hostname}"})


@app.route("/control/isolate", methods=["POST"])
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


@app.route("/control/unisolate", methods=["POST"])
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


@app.route("/control/wipe", methods=["POST"])
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



@app.route("/control/screenshot", methods=["POST"])
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


@app.route("/api/screenshot/<int:agent_id>", methods=["POST"])
@require_token
def upload_screenshot(agent_id):
    """Agente faz upload do screenshot em base64."""
    agent = Agent.query.get_or_404(agent_id)
    data = request.get_json(silent=True) or {}
    agent.last_screenshot = data.get("screenshot_b64")
    db.session.commit()
    return jsonify({"status": "ok"})


@app.route("/api/screenshot/<int:agent_id>", methods=["GET"])
def get_screenshot(agent_id):
    agent = Agent.query.get_or_404(agent_id)
    return jsonify({"screenshot_b64": agent.last_screenshot})


@app.route("/api/command_output", methods=["POST"])
@require_token
def command_output():
    """Recebe a saída de um comando shell executado pelo agente."""
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


@app.route("/api/agent/<int:agent_id>/detail")
def agent_detail(agent_id):
    """Retorna informações detalhadas de um agente para contexto da IA."""
    agent = Agent.query.get_or_404(agent_id)
    recent_events = (SecurityEvent.query
                     .filter_by(agent_id=agent_id)
                     .order_by(SecurityEvent.timestamp.desc())
                     .limit(20).all())
    open_incidents = (Incident.query
                      .filter_by(agent_id=agent_id, status="OPEN")
                      .order_by(Incident.created_at.desc())
                      .limit(10).all())
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


@app.route("/control/quick_command", methods=["POST"])
@require_token
def quick_command():
    """Envia um comando pré-definido ao agente (process list, netstat, sysinfo, etc.)."""
    data = request.get_json(silent=True) or {}
    agent_id = data.get("agent_id")
    cmd_type = data.get("type", "").upper()

    QUICK_COMMANDS = {
        "PROCESSLIST": "tasklist /V /FO TABLE",
        "NETSTAT":     "netstat -ano",
        "SYSINFO":     "systeminfo",
        "SERVICES":    "sc queryex type= all state= all",
        "USERS":       "net user",
        "LOCALGROUPS": "net localgroup administrators",
        "STARTUP":     "wmic startup get caption,command",
        "SCHEDTASKS":  "schtasks /query /fo TABLE /v",
        "SHARES":      "net share",
        "FIREWALL":    "netsh advfirewall show allprofiles",
        "ENVVARS":     "set",
        "HOTFIXES":    "wmic qfe list brief",
    }

    if not agent_id or cmd_type not in QUICK_COMMANDS:
        return jsonify({"error": f"agent_id e type válido obrigatórios. Tipos: {list(QUICK_COMMANDS.keys())}"}), 400

    agent = Agent.query.get_or_404(agent_id)
    cmd_str = QUICK_COMMANDS[cmd_type]
    agent.pending_command = json.dumps({"command": "SHELL", "args": cmd_str})
    agent.pending_command_time = datetime.utcnow()
    db.session.commit()

    audit("QUICK_COMMAND", target_type="agent", target_id=agent_id, details=f"{cmd_type}: {cmd_str}")
    return jsonify({"status": "ok", "command": cmd_str, "type": cmd_type})


@app.route("/api/soar/<int:agent_id>", methods=["POST"])
@require_token
def soar_action(agent_id):
    """Executa ações mapeadas pelos botões de SOAR Interativos no C2."""
    data = request.get_json(silent=True) or {}
    action = data.get("action")
    if not action:
        return jsonify({"error": "action obrigatória"}), 400

    agent = Agent.query.get_or_404(agent_id)
    cmd_payload = None
    log_msg = ""

    if action == "force_scan_vulns":
        cmd_payload = {"type": "force_scan_vulns"}
        log_msg = "Scan de Vulnerabilidades Forçado via SOAR"
    elif action == "force_scan_fim":
        cmd_payload = {"type": "force_scan_fim"}
        log_msg = "Verificação de FIM Forçada via SOAR"
    elif action == "force_logs":
        cmd_payload = {"type": "force_logs"}
        log_msg = "Coleta de Event Logs (Dump) Forçada via SOAR"
    elif action == "force_scan_network":

        cmd_payload = {"command": "SHELL", "args": "netstat -ano | findstr LISTENING"}
        log_msg = "Scan de Portas Local (Network) Forçado via SOAR"
    else:
        return jsonify({"error": "action desconhecida"}), 400

    if cmd_payload:
        agent.pending_command = json.dumps(cmd_payload)
        agent.pending_command_time = datetime.utcnow()
        db.session.commit()
        audit("SOAR_ACTION", target_type="agent", target_id=agent_id, details=log_msg)

    return jsonify({"status": "ok"})





@app.route("/login", methods=["GET"])
def login_page():
    if session.get("soc_user"):
        return redirect(url_for("dashboard"))
    return render_template("login.html", error=None, success=None)


@app.route("/login", methods=["POST"])
def do_login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    user = SocUser.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return render_template("login.html", error="Credenciais inválidas.", success=None)
    if user.status == "pending":
        return render_template("login.html", error="Cadastro aguardando aprovação do administrador.", success=None)
    if user.status == "rejected":
        return render_template("login.html", error="Seu cadastro foi recusado. Entre em contato com o administrador.", success=None)
    session.permanent = True
    session["soc_user"] = user.username
    session["soc_display"] = user.display_name or user.username
    session["soc_role"] = user.role
    audit("USER_LOGIN", actor=user.username, target_type="auth", details=f"Login bem-sucedido")
    return redirect(url_for("dashboard"))


@app.route("/logout")
def do_logout():
    actor = session.get("soc_user", "unknown")
    session.clear()
    audit("USER_LOGOUT", actor=actor, target_type="auth")
    return redirect(url_for("login_page"))


@app.route("/register", methods=["POST"])
def do_register():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    display_name = request.form.get("display_name", "").strip()
    email = request.form.get("email", "").strip()
    reason = request.form.get("reason", "").strip()

    if not username or not password:
        return render_template("login.html", error="Username e senha são obrigatórios.", success=None, show_register=True)

    if len(password) < 6:
        return render_template("login.html", error="A senha deve ter ao menos 6 caracteres.", success=None, show_register=True)

    if SocUser.query.filter_by(username=username).first():
        return render_template("login.html", error="Este username já está em uso.", success=None, show_register=True)

    new_user = SocUser(
        username=username,
        display_name=display_name or username,
        password_hash=SocUser.hash_password(password),
        email=email,
        reason=reason,
        status="pending",
        role="analyst",
    )
    db.session.add(new_user)
    db.session.commit()
    audit("USER_REGISTER_REQUEST", actor=username, target_type="auth", details=f"Solicitação de cadastro: {reason[:80]}")
    return render_template("login.html", error=None, success="Solicitação enviada! Aguarde aprovação do administrador.")


@app.route("/admin/users")
@require_admin
def admin_users():
    pending = SocUser.query.filter_by(status="pending").order_by(SocUser.created_at.asc()).all()
    approved = SocUser.query.filter_by(status="active").order_by(SocUser.created_at.desc()).all()
    rejected = SocUser.query.filter_by(status="rejected").order_by(SocUser.created_at.desc()).all()
    return render_template("admin_users.html",
                           pending=pending, approved=approved, rejected=rejected,
                           current_user=session.get("soc_user"),
                           current_role=session.get("soc_role"))


@app.route("/admin/users/<int:user_id>/approve", methods=["POST"])
@require_admin
def approve_user(user_id):
    user = SocUser.query.get_or_404(user_id)
    user.status = "active"
    user.approved_at = datetime.utcnow()
    user.approved_by = session.get("soc_user")
    db.session.commit()
    audit("USER_APPROVED", actor=session.get("soc_user"), target_type="user", target_id=user_id, details=f"Usuário {user.username} aprovado")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/reject", methods=["POST"])
@require_admin
def reject_user(user_id):
    user = SocUser.query.get_or_404(user_id)
    user.status = "rejected"
    user.approved_by = session.get("soc_user")
    db.session.commit()
    audit("USER_REJECTED", actor=session.get("soc_user"), target_type="user", target_id=user_id, details=f"Usuário {user.username} recusado")
    return redirect(url_for("admin_users"))


@app.route("/api/admin/users")
@require_admin
def api_list_users():
    users = SocUser.query.order_by(SocUser.created_at.desc()).all()
    return jsonify([u.to_dict() for u in users])


@app.route("/")
@require_auth
def dashboard():
    return render_template("dashboard.html",
                           current_user=session.get("soc_user"),
                           current_role=session.get("soc_role"),
                           current_display=session.get("soc_display"))


@app.route("/api/agents")
def list_agents():
    platform = request.args.get("platform")
    q = Agent.query
    if platform:
        q = q.filter_by(platform=platform)
    agents = q.order_by(Agent.last_seen.desc()).all()
    return jsonify([a.to_dict() for a in agents])


@app.route("/api/agents/<int:agent_id>", methods=["GET"])
def get_agent(agent_id):
    agent = Agent.query.get_or_404(agent_id)
    return jsonify(agent.to_dict())


@app.route("/api/agents/<int:agent_id>", methods=["PATCH"])
def update_agent(agent_id):
    agent = Agent.query.get_or_404(agent_id)
    data = request.get_json(silent=True) or {}
    if "hostname" in data:
        agent.hostname = data["hostname"]
    if "tags" in data:
        agent.tags = json.dumps(data["tags"])
    db.session.commit()
    audit("AGENT_UPDATED", target_type="agent", target_id=agent_id, details=str(data))
    return jsonify(agent.to_dict())


@app.route("/api/events")
def list_events():
    agent_id = request.args.get("agent_id", type=int)
    severity = request.args.get("severity")
    category = request.args.get("category")
    mitre = request.args.get("mitre")
    ioc_only = request.args.get("ioc_only", "false") == "true"
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 50, type=int), 200)

    q = SecurityEvent.query
    if agent_id:
        q = q.filter_by(agent_id=agent_id)
    if severity:
        q = q.filter_by(severity=severity)
    if category:
        q = q.filter_by(category=category)
    if mitre:
        q = q.filter(SecurityEvent.mitre_technique.like(f"{mitre}%"))
    if ioc_only:
        q = q.filter_by(ioc_matched=True)

    paginated = q.order_by(SecurityEvent.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)
    return jsonify({
        "events": [e.to_dict() for e in paginated.items],
        "total": paginated.total,
        "pages": paginated.pages,
        "current_page": page,
    })


@app.route("/api/incidents")
def list_incidents():
    status = request.args.get("status")
    severity = request.args.get("severity")
    agent_id = request.args.get("agent_id", type=int)
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 25, type=int), 100)

    q = Incident.query
    if status:
        q = q.filter_by(status=status)
    if severity:
        q = q.filter_by(severity=severity)
    if agent_id:
        q = q.filter_by(agent_id=agent_id)

    paginated = q.order_by(Incident.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    return jsonify({
        "incidents": [i.to_dict() for i in paginated.items],
        "total": paginated.total,
        "pages": paginated.pages,
    })


@app.route("/api/incidents", methods=["POST"])
def create_incident():
    data = request.get_json(silent=True) or {}
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


@app.route("/api/incidents/<int:incident_id>", methods=["PATCH"])
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




@app.route("/api/threat_intel/ioc", methods=["GET"])
def list_iocs():
    ioc_type = request.args.get("type")
    q = IOC.query.filter_by(active=True)
    if ioc_type:
        q = q.filter_by(ioc_type=ioc_type)
    iocs = q.order_by(IOC.added_at.desc()).all()
    return jsonify([i.to_dict() for i in iocs])


@app.route("/api/threat_intel/ioc", methods=["POST"])
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


@app.route("/api/threat_intel/ioc/<int:ioc_id>", methods=["DELETE"])
def delete_ioc(ioc_id):
    ioc = IOC.query.get_or_404(ioc_id)
    ioc.active = False
    db.session.commit()
    audit("IOC_DELETED", target_type="ioc", target_id=ioc_id)
    return jsonify({"status": "ok"})


@app.route("/api/ioc/check", methods=["POST"])
def check_ioc_endpoint():
    data = request.get_json(silent=True) or {}
    value = data.get("value", "").strip().lower()
    if not value:
        return jsonify({"error": "value obrigatório"}), 400

    ioc = check_ioc(value)
    if ioc:
        return jsonify({"matched": True, "ioc": ioc.to_dict()})
    return jsonify({"matched": False, "value": value})




@app.route("/api/stats")
def stats():
    agent_id = request.args.get("agent_id", type=int)

    total_agents   = Agent.query.count()
    online_thresh  = datetime.utcnow() - timedelta(minutes=3)
    online_agents  = Agent.query.filter(Agent.last_seen > online_thresh, Agent.isolation_active == False).count()
    isolated_agents = Agent.query.filter_by(isolation_active=True).count()

    evt_q = SecurityEvent.query
    if agent_id:
        evt_q = evt_q.filter_by(agent_id=agent_id)

    total_events = evt_q.count()
    today_start  = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    events_today = evt_q.filter(SecurityEvent.timestamp >= today_start).count()

    by_severity = dict(db.session.query(SecurityEvent.severity, func.count()).group_by(SecurityEvent.severity).all())
    by_category = dict(db.session.query(SecurityEvent.category, func.count()).group_by(SecurityEvent.category).all())

    hours_data = []
    for h in range(23, -1, -1):
        start = datetime.utcnow() - timedelta(hours=h+1)
        end   = datetime.utcnow() - timedelta(hours=h)
        q = SecurityEvent.query.filter(SecurityEvent.timestamp.between(start, end))
        if agent_id:
            q = q.filter_by(agent_id=agent_id)
        hours_data.append({"hour": end.strftime("%H:%M"), "count": q.count()})

    mitre_rows = db.session.query(
        SecurityEvent.mitre_technique, func.count()
    ).filter(SecurityEvent.mitre_technique.isnot(None)).group_by(
        SecurityEvent.mitre_technique
    ).order_by(func.count().desc()).limit(10).all()

    top_mitre = [{"technique": t, "count": c} for t, c in mitre_rows]

    open_incidents = Incident.query.filter_by(status="OPEN").count()
    critical_incidents = Incident.query.filter(Incident.severity == "CRITICAL", Incident.status == "OPEN").count()

    ioc_count = IOC.query.filter_by(active=True).count()
    ioc_hits  = db.session.query(func.sum(IOC.hit_count)).scalar() or 0

    return jsonify({
        "agents": {"total": total_agents, "online": online_agents, "isolated": isolated_agents},
        "events": {"total": total_events, "today": events_today, "by_severity": by_severity, "by_category": by_category},
        "incidents": {"open": open_incidents, "critical": critical_incidents},
        "threat_intel": {"ioc_count": ioc_count, "total_hits": ioc_hits},
        "chart_hours": hours_data,
        "top_mitre": top_mitre,
    })




@app.route("/api/agent/<int:agent_id>/vulnerabilities", methods=["GET"])
def list_vulnerabilities(agent_id):
    """Retorna vulnerabilidades abertas para um agente (Dashboard)."""
    vulns = AgentVulnerability.query.filter_by(agent_id=agent_id, status="OPEN").all()
    return jsonify([v.to_dict() for v in vulns])

@app.route("/api/vulnerabilities", methods=["POST"])
@require_token
def report_vulnerabilities():
    """Agente reporta vulnerabilidades encontradas no endpoint."""
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
                remediation_cmd=v_data.get("remediation_cmd", "")
            )
            db.session.add(new_v)

    db.session.commit()
    return jsonify({"status": "ok", "message": f"{len(vulns)} vulnerabilidades reportadas"})


@app.route("/api/chat/agent/<int:agent_id>/send", methods=["POST"])
def admin_send_chat(agent_id):
    """Admin envia mensagem para o Agente."""
    data = request.get_json(silent=True) or {}
    message = data.get("message", "").strip()
    if not message:
        return jsonify({"error": "Mensagem vazia"}), 400

    agent = Agent.query.get_or_404(agent_id)
    chat_msg = AgentChat(agent_id=agent.id, sender="admin", message=message, is_read=False)
    db.session.add(chat_msg)
    db.session.commit()
    return jsonify({"status": "ok", "msg": chat_msg.to_dict()})

@app.route("/api/chat/agent/poll", methods=["POST"])
@require_token
def agent_poll_chat():
    """Agente checa se há novas mensagens do Admin ou envia sua mensagem."""
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

    db.session.commit()
    return jsonify({"messages": response_msgs})

@app.route("/api/chat/agent/<int:agent_id>/history", methods=["GET"])
def get_agent_chat_history(agent_id):
    """SOC busca o histórico do chat com o Agente."""
    agent = Agent.query.get_or_404(agent_id)
    history = AgentChat.query.filter_by(agent_id=agent.id).order_by(AgentChat.timestamp.asc()).limit(50).all()

    for h in history:
        if h.sender == "agent" and not h.is_read:
            h.is_read = True
    db.session.commit()
    return jsonify([m.to_dict() for m in history])




@app.route("/api/audit")
def get_audit():
    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 50, type=int), 200)
    action_filter = request.args.get("action")
    q = AuditLog.query
    if action_filter:
        q = q.filter(AuditLog.action.like(f"%{action_filter}%"))
    paginated = q.order_by(AuditLog.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)
    return jsonify({
        "logs": [l.to_dict() for l in paginated.items],
        "total": paginated.total,
    })




SYSTEM_PROMPT_SOC = """Você é o AEGIS AI, um especialista em cibersegurança integrado ao painel SOC da plataforma Aegis SIEM & EDR.
Responda em português brasileiro. Seja preciso, técnico e objetivo.
Ao analisar eventos, mencione sempre: tipo de ameaça, técnica MITRE ATT&CK, impacto e recomendações de resposta."""


@app.route("/api/chat", methods=["POST"])
def chat():
    data = request.get_json(silent=True) or {}
    message = data.get("message", "").strip()
    session = data.get("session", "default")
    if not message:
        return jsonify({"error": "message obrigatório"}), 400

    user_msg = ChatMessage(session=session, role="user", content=message)
    db.session.add(user_msg)
    db.session.flush()

    history = ChatMessage.query.filter_by(session=session).order_by(ChatMessage.timestamp.asc()).limit(10).all()

    response_text = None
    model_used = None

    gemini_key = os.getenv("GEMINI_API_KEY")
    if gemini_key and not response_text:
        try:
            import google.generativeai as genai
            genai.configure(api_key=gemini_key)
            model = genai.GenerativeModel("gemini-1.5-flash", system_instruction=SYSTEM_PROMPT_SOC)
            chat_hist = [
                {"role": ("user" if m.role == "user" else "model"), "parts": [m.content]}
                for m in history[:-1]
            ]
            gchat = model.start_chat(history=chat_hist)
            resp = gchat.send_message(message)
            response_text = resp.text
            model_used = "gemini-1.5-flash"
        except Exception as e:
            log.warning(f"Gemini falhou: {e}")

    openai_key = os.getenv("OPENAI_API_KEY")
    if openai_key and not response_text:
        try:
            from openai import OpenAI
            client = OpenAI(api_key=openai_key)
            messages = [{"role": "system", "content": SYSTEM_PROMPT_SOC}]
            for m in history:
                messages.append({"role": m.role, "content": m.content})
            resp = client.chat.completions.create(
                model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
                messages=messages,
                max_tokens=1024,
            )
            response_text = resp.choices[0].message.content
            model_used = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        except Exception as e:
            log.warning(f"OpenAI falhou: {e}")

    if not response_text:
        response_text = (
            "⚠️ Nenhuma chave de AI configurada. Configure GEMINI_API_KEY ou OPENAI_API_KEY no arquivo .env "
            "para ativar o assistente de IA."
        )
        model_used = "offline"

    assist_msg = ChatMessage(session=session, role="assistant", content=response_text, model_used=model_used)
    db.session.add(assist_msg)
    db.session.commit()

    return jsonify({
        "response": response_text,
        "model": model_used,
        "session": session,
        "timestamp": assist_msg.timestamp.isoformat(),
    })


@app.route("/api/chat/history")
def chat_history():
    session = request.args.get("session", "default")
    limit = min(request.args.get("limit", 50, type=int), 200)
    msgs = ChatMessage.query.filter_by(session=session).order_by(ChatMessage.timestamp.asc()).limit(limit).all()
    return jsonify([m.to_dict() for m in msgs])


@app.route("/api/chat/clear", methods=["DELETE"])
def clear_chat():
    session = request.args.get("session", "default")
    ChatMessage.query.filter_by(session=session).delete()
    db.session.commit()
    return jsonify({"status": "ok"})




def init_db():
    with app.app_context():

        sa_event.listen(db.engine, "connect", enable_wal)
        db.create_all()

        if IOC.query.count() == 0:
            sample_iocs = [
                IOC(ioc_type="hash", value="44d88612fea8a8f36de82e1278abb02f",
                    threat_name="EICAR Test", severity="LOW", threat_feed="built-in",
                    description="Hash de teste EICAR — não é ameaça real"),
                IOC(ioc_type="ip", value="185.220.101.0",
                    threat_name="Tor Exit Node", severity="MEDIUM", threat_feed="built-in",
                    description="Nó de saída Tor conhecido"),
                IOC(ioc_type="domain", value="malware-c2.example.com",
                    threat_name="Test C2 Domain", severity="HIGH", threat_feed="built-in",
                    description="Domínio de teste para validação de alertas"),
            ]
            db.session.add_all(sample_iocs)
            db.session.commit()
            log.info("[DB] IoCs de exemplo inseridos.")

        adm_username = os.getenv("AEGIS_ADM_USER", "admin")
        adm_pass = os.getenv("AEGIS_ADM_PASS", "Aegis@2026!")
        if not SocUser.query.filter_by(username=adm_username).first():
            adm = SocUser(
                username=adm_username,
                display_name="Administrador",
                password_hash=SocUser.hash_password(adm_pass),
                role="admin",
                status="active",
                email="admin@aegis.local",
                approved_by="system",
                approved_at=datetime.utcnow(),
            )
            db.session.add(adm)
            db.session.commit()
            log.info(f"[AUTH] Usuário ADM '{adm_username}' criado com sucesso.")
        log.info(f"[DB] Banco inicializado em {DB_PATH} (WAL mode)")


if __name__ == "__main__":
    init_db()
    port = int(os.getenv("AEGIS_PORT", 5000))
    debug = os.getenv("AEGIS_DEBUG", "false").lower() == "true"
    log.info(f"🛡️  Aegis C2 Server iniciando na porta {port} (debug={debug})")
    app.run(host=os.getenv("AEGIS_HOST", "0.0.0.0"), port=port, debug=debug)
else:

    init_db()
