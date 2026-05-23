import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
IS_VERCEL = os.getenv("VERCEL") == "1"

if IS_VERCEL:
    WRITABLE_ROOT = Path("/tmp/phishing-triage")
    OUTPUT_DIR = WRITABLE_ROOT / "output"
    RUNS_DIR = OUTPUT_DIR / "runs"
    UPLOAD_DIR = OUTPUT_DIR / "uploads"
    DB_PATH = WRITABLE_ROOT / "ioc_history.db"
else:
    OUTPUT_DIR = BASE_DIR / "output"
    RUNS_DIR = OUTPUT_DIR / "runs"
    UPLOAD_DIR = OUTPUT_DIR / "uploads"
    DB_PATH = BASE_DIR / "ioc_history.db"

SAMPLE_DIR = BASE_DIR / "sample_emails"
YARA_RULES_DIR = BASE_DIR / "scanner" / "rules"

VT_API_KEY = os.getenv("VT_API_KEY", "")
VT_BASE_URL = "https://www.virustotal.com/api/v3"
TALOS_LOOKUP_URL = "https://talosintelligence.com/reputation_center/lookup"
VT_URL_POLL_SECONDS = int(os.getenv("VT_URL_POLL_SECONDS", "8" if IS_VERCEL else "15"))

FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "change-me-in-production")
FLASK_HOST = os.getenv("FLASK_HOST", "0.0.0.0")
FLASK_PORT = int(os.getenv("FLASK_PORT", "8080"))
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "10"))

WEB_AUTH_USERNAME = os.getenv("WEB_AUTH_USERNAME", "")
WEB_AUTH_PASSWORD = os.getenv("WEB_AUTH_PASSWORD", "")
WEB_AUTH_PASSWORD_HASH = os.getenv("WEB_AUTH_PASSWORD_HASH", "")
WEB_API_KEY = os.getenv("WEB_API_KEY", "")

# Auth is on by default; set DISABLE_AUTH=true to turn off (local dev only)
AUTH_ENABLED = os.getenv("DISABLE_AUTH", "").lower() != "true"

# Team registration — requires invite code (no open public signup)
ALLOW_REGISTRATION = os.getenv("ALLOW_REGISTRATION", "").lower() == "true"
REGISTRATION_ENABLED = ALLOW_REGISTRATION
REGISTRATION_INVITE_CODE = os.getenv("REGISTRATION_INVITE_CODE", "")

DOMAIN_AGE_SUSPICIOUS_DAYS = int(os.getenv("DOMAIN_AGE_SUSPICIOUS_DAYS", "30"))
DOMAIN_AGE_CRITICAL_DAYS = int(os.getenv("DOMAIN_AGE_CRITICAL_DAYS", "7"))

RISK_THRESHOLDS = {
    "low": (0, 20),
    "medium": (21, 50),
    "high": (51, 80),
    "critical": (81, 100),
}

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
RUNS_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
