import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "app"))

from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from app import create_app, init_db
from config import Config
from extensions import log

app = create_app(Config)
init_db(app)

if __name__ == "__main__":
    log.info(f"🛡️  Aegis C2 Server iniciando na porta {Config.PORT}")
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
