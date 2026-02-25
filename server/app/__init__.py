import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from flask import Flask
from dotenv import load_dotenv
from sqlalchemy import event as sa_event

load_dotenv(Path(__file__).resolve().parent.parent.parent / ".env")

from config import Config
from extensions import db, cors, log


def create_app(config_class=Config):
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).resolve().parent.parent / "templates"),
    )
    app.config.from_object(config_class)

    db.init_app(app)
    cors.init_app(app)

    with app.app_context():
        from routes.auth import auth_bp
        from routes.dashboard import dashboard_bp
        from routes.admin import admin_bp
        from routes.agents import agents_bp
        from routes.control import control_bp
        from routes.incidents import incidents_bp
        from routes.threat_intel import threat_intel_bp
        from routes.chat import chat_bp

        app.register_blueprint(auth_bp)
        app.register_blueprint(dashboard_bp)
        app.register_blueprint(admin_bp)
        app.register_blueprint(agents_bp)
        app.register_blueprint(control_bp)
        app.register_blueprint(incidents_bp)
        app.register_blueprint(threat_intel_bp)
        app.register_blueprint(chat_bp)

    return app


def init_db(app):
    from models.ioc import IOC, AuditLog
    from models.agent import Agent
    from models.event import SecurityEvent
    from models.incident import Incident
    from models.chat import ChatMessage, AgentChat, AgentVulnerability
    from models.user import SocUser
    from config import DB_PATH
    from datetime import datetime

    def enable_wal(connection, _):
        cursor = connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA cache_size=-64000")
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

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

        adm_username = app.config["ADM_USER"]
        adm_pass = app.config["ADM_PASS"]
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
            log.info(f"[AUTH] Usuário ADM '{adm_username}' criado.")

        log.info(f"[DB] Banco inicializado em {DB_PATH}")
