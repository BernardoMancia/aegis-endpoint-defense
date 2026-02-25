import json
import os
import requests as http_requests
from collections import defaultdict
from datetime import datetime, timedelta
from extensions import db, log


def check_ioc(value: str):
    from models.ioc import IOC
    ioc = IOC.query.filter_by(value=value.lower(), active=True).first()
    if ioc:
        ioc.hit_count = (ioc.hit_count or 0) + 1
        ioc.last_seen_at = datetime.utcnow()
        db.session.commit()
    return ioc


def send_slack_alert(title: str, message: str, severity: str = "CRITICAL"):
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
        http_requests.post(webhook, json=payload, timeout=5)
    except Exception as e:
        log.warning(f"Slack webhook falhou: {e}")


class SIEMEngine:
    _auth_failures: dict = defaultdict(list)
    _smb_targets: dict = defaultdict(list)

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
    _last_cleanup = None

    @classmethod
    def _cleanup_old_records(cls):
        now = datetime.utcnow()
        if cls._last_cleanup and (now - cls._last_cleanup).total_seconds() < 86400:
            return
        cls._last_cleanup = now
        try:
            ninety_days = now - timedelta(days=90)
            from models.event import SecurityEvent
            from models.incident import Incident
            
            # Remove eventos mais antigos que 90 dias
            deleted_events = SecurityEvent.query.filter(SecurityEvent.timestamp < ninety_days).delete()
            
            # Remove incidentes fechados e antigos
            deleted_incs = Incident.query.filter(Incident.status != "OPEN", Incident.created_at < ninety_days).delete()
            
            db.session.commit()
            if deleted_events > 0 or deleted_incs > 0:
                log.info(f"[SIEM] Retenção de 90 dias executada: {deleted_events} eventos e {deleted_incs} incidentes removidos.")
        except Exception as e:
            log.error(f"[SIEM] Erro na limpeza de 90 dias: {e}")
            db.session.rollback()

    @classmethod
    def process_events(cls, agent, events: list) -> list:
        cls._cleanup_old_records()
        created_incidents = []
        for evt_data in events:
            event = cls._store_event(agent, evt_data)
            if event:
                incidents = cls._correlate(agent, event, evt_data)
                created_incidents.extend(incidents)
        return created_incidents

    @classmethod
    def _store_event(cls, agent, evt_data: dict):
        from models.event import SecurityEvent
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
    def _correlate(cls, agent, event, evt_data: dict) -> list:
        from models.incident import Incident
        incidents = []
        now = datetime.utcnow()
        aid = agent.id
        eid_str = str(evt_data.get("event_id", ""))

        if eid_str == "4625":
            cls._auth_failures[aid].append(now)
            cls._auth_failures[aid] = [t for t in cls._auth_failures[aid] if now - t < timedelta(seconds=60)]
            if len(cls._auth_failures[aid]) >= 5:
                inc = cls._create_incident(
                    agent=agent, title=f"🔑 Brute Force Detectado em {agent.hostname}",
                    description=f"Detectadas {len(cls._auth_failures[aid])} falhas de autenticação em 60 segundos.",
                    severity="HIGH", mitre_technique="T1110", mitre_tactic="Credential Access", event=event,
                    playbook=["Bloquear conta do usuário alvo", "Verificar logs de origem", "Checar IPs no threat intel"],
                    soar_auto=False,
                )
                if inc:
                    incidents.append(inc)
                    cls._auth_failures[aid] = []

        elif eid_str == "4672":
            inc = cls._create_incident(
                agent=agent, title=f"⚠️ Escalada de Privilégio em {agent.hostname}",
                description="Logon com privilégios especiais detectado (Event ID 4672).",
                severity="CRITICAL", mitre_technique="T1068", mitre_tactic="Privilege Escalation", event=event,
                playbook=["Verificar identidade do usuário", "Analisar processo pai", "Isolar host se não autorizado"],
                soar_auto=True,
            )
            if inc:
                incidents.append(inc)

        elif eid_str in ("7045", "4697"):
            inc = cls._create_incident(
                agent=agent, title=f"🔧 Novo Serviço Instalado em {agent.hostname}",
                description=f"Instalação de serviço detectada — Event ID {eid_str}.",
                severity="HIGH", mitre_technique="T1543.003", mitre_tactic="Persistence", event=event,
                playbook=["Identificar binário do serviço", "Verificar assinatura digital", "Comparar com baseline"],
                soar_auto=False,
            )
            if inc:
                incidents.append(inc)

        elif eid_str == "1102":
            inc = cls._create_incident(
                agent=agent, title=f"🗑️ Logs de Auditoria Apagados em {agent.hostname}",
                description="O log de auditoria do Windows foi limpo — possível tentativa de evasão.",
                severity="CRITICAL", mitre_technique="T1070.001", mitre_tactic="Defense Evasion", event=event,
                playbook=["Isolar host imediatamente", "Coletar imagem de memória", "Acionar IR team"],
                soar_auto=True,
            )
            if inc:
                incidents.append(inc)

        elif eid_str in ("4103", "4104"):
            inc = cls._create_incident(
                agent=agent, title=f"💻 Execução PowerShell Suspeita em {agent.hostname}",
                description="Script PowerShell registrado pelo ScriptBlock Logging.",
                severity="HIGH", mitre_technique="T1059.001", mitre_tactic="Execution", event=event,
                playbook=["Analisar conteúdo do script", "Verificar processo pai", "Checar conexões de rede oriundas do processo"],
                soar_auto=False,
            )
            if inc:
                incidents.append(inc)

        elif evt_data.get("process_name", "").lower() in cls.SUSPICIOUS_PROCESSES:
            proc = evt_data.get("process_name", "")
            inc = cls._create_incident(
                agent=agent, title=f"☠️ Processo Malicioso Detectado: {proc} em {agent.hostname}",
                description=f"Processo '{proc}' está na blacklist de ferramentas de ataque.",
                severity="CRITICAL", mitre_technique="T1003", mitre_tactic="Credential Access", event=event,
                playbook=["Encerrar processo imediatamente", "Isolar host", "Coletar dump de memória"],
                soar_auto=True,
            )
            if inc:
                incidents.append(inc)

        if event.ioc_matched:
            inc = cls._create_incident(
                agent=agent, title=f"🎯 IoC Confirmado em {agent.hostname}",
                description="Hash/IP/Domínio do evento bate com ameaça conhecida no Threat Intel.",
                severity="CRITICAL", mitre_technique="T1071", mitre_tactic="Command and Control", event=event,
                playbook=["Isolar host", "Identificar origem do artefato", "Remover arquivo malicioso"],
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
                        agent=agent, title=f"🔀 Possível Movimento Lateral em {agent.hostname}",
                        description=f"Conexões SMB/RPC para {unique_targets} hosts diferentes em 30 segundos.",
                        severity="HIGH", mitre_technique="T1021", mitre_tactic="Lateral Movement", event=event,
                        playbook=["Isolar host", "Mapear hosts de destino", "Verificar credenciais comprometidas"],
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
        from models.incident import Incident
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
            title=title, description=description, severity=severity, status="OPEN",
            agent_id=agent.id, mitre_technique=mitre_technique, mitre_tactic=mitre_tactic,
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
    def _execute_soar(cls, agent, technique: str) -> list:
        from services.audit_service import audit
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
