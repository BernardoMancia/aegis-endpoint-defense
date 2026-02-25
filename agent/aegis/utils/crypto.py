import base64
import hashlib
import logging

log = logging.getLogger("aegis-agent")


def take_screenshot() -> str | None:
    try:
        from PIL import ImageGrab
        from io import BytesIO
        img = ImageGrab.grab()
        buf = BytesIO()
        img.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode()
    except Exception as e:
        log.warning(f"Screenshot falhou: {e}")
        return None


def compute_hash(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None
