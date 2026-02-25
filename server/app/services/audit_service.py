from flask import request
from extensions import db, log
from models.ioc import AuditLog


def audit(action, actor="system", target_type=None, target_id=None, details=None):
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
