import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def _resolve_db_path() -> str:
    env = os.getenv("DATABASE_PATH", "")
    if env:
        p = Path(env) if Path(env).is_absolute() else BASE_DIR / env
        return str(p if str(p).endswith(".db") else p / "aegis.db")
    return str(BASE_DIR / "data" / "aegis.db")


DB_PATH = _resolve_db_path()
os.makedirs(Path(DB_PATH).parent, exist_ok=True)


class Config:
    SECRET_KEY = os.getenv("AEGIS_SECRET_KEY", secrets.token_hex(32))
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{DB_PATH}"
    SQLALCHEMY_ENGINE_OPTIONS = {
        "connect_args": {"check_same_thread": False},
        "pool_size": 10,
        "pool_timeout": 30,
    }
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    API_TOKEN = os.getenv("AEGIS_API_TOKEN", "aegis-default-token-mude-agora") or "aegis-default-token-mude-agora"
    ADM_USER = os.getenv("AEGIS_ADM_USER", "admin")
    ADM_PASS = os.getenv("AEGIS_ADM_PASS", "Aegis@2026!")
    SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    DEBUG = os.getenv("AEGIS_DEBUG", "false").lower() == "true"
    HOST = os.getenv("AEGIS_HOST", "0.0.0.0")
    PORT = int(os.getenv("AEGIS_PORT", 5000))
