"""
CTI Pipeline – central configuration
All values overridable via environment variables or a .env file.
"""
from __future__ import annotations
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# All source files are flat in the project root — BASE_DIR is this directory
BASE_DIR = Path(__file__).resolve().parent

# ── Database ──────────────────────────────────────────────────────────────────
DATABASE_URL: str = os.getenv("CTI_DATABASE_URL", f"sqlite:///{BASE_DIR}/data/cti.db")

# ── LLM ───────────────────────────────────────────────────────────────────────
OLLAMA_BASE_URL: str  = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
LLM_MODEL:       str  = os.getenv("CTI_LLM_MODEL",   "qwen3:8b")
LLM_TEMPERATURE: float = float(os.getenv("CTI_LLM_TEMPERATURE", "0.1"))
LLM_MAX_TOKENS:  int  = int(os.getenv("CTI_LLM_MAX_TOKENS",    "4096"))
LLM_CONTEXT_WINDOW: int = int(os.getenv("CTI_LLM_CONTEXT_WINDOW", "32768"))

# ── RAG / ChromaDB ────────────────────────────────────────────────────────────
RAG_ENABLED:      bool = os.getenv("CTI_RAG_ENABLED", "true").lower() == "true"
CHROMA_PERSIST_DIR: str = os.getenv("CTI_CHROMA_DIR", str(BASE_DIR / "data" / "chromadb"))
EMBED_MODEL:      str  = os.getenv("CTI_EMBED_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
RAG_TOP_K:        int  = int(os.getenv("CTI_RAG_TOP_K", "5"))
ATTACK_STIX_URL:  str  = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

# ── Article extraction ────────────────────────────────────────────────────────
MIN_ARTICLE_LENGTH: int = int(os.getenv("CTI_MIN_ARTICLE_LEN", "500"))
REQUEST_TIMEOUT:    int = int(os.getenv("CTI_REQUEST_TIMEOUT", "30"))
MAX_RETRIES:        int = int(os.getenv("CTI_MAX_RETRIES",     "3"))
USER_AGENT: str = (
    "Mozilla/5.0 (compatible; CTI-Pipeline/1.0; "
    "+https://github.com/your-org/cti-pipeline)"
)

# ── Scheduling ────────────────────────────────────────────────────────────────
RUN_HOUR:   int = int(os.getenv("CTI_RUN_HOUR",   "6"))
RUN_MINUTE: int = int(os.getenv("CTI_RUN_MINUTE", "0"))

# ── Output ────────────────────────────────────────────────────────────────────
REPORT_DIR: Path = BASE_DIR / "reports"
REPORT_DIR.mkdir(parents=True, exist_ok=True)

# ── RSS Feeds ─────────────────────────────────────────────────────────────────
RSS_FEEDS: list[dict] = [
    {"name": "The Hacker News",      "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "BleepingComputer",     "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "The Record",           "url": "https://therecord.media/feed"},
    {"name": "Krebs on Security",    "url": "https://krebsonsecurity.com/feed/"},
    {"name": "Dark Reading",         "url": "https://www.darkreading.com/rss.xml"},
    {"name": "Schneier on Security", "url": "https://www.schneier.com/feed/atom/"},
    {"name": "CyberScoop",           "url": "https://cyberscoop.com/feed/"},
    {"name": "SecurityWeek",         "url": "https://feeds.feedburner.com/securityweek"},
]
