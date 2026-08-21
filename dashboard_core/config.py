"""
Application-wide constants and shared singletons.

Everything here is read at call time by the other modules
(``config.SSH_HOST`` rather than ``from dashboard_core.config import
SSH_HOST``) so that a single monkeypatch of a value in this module is
visible to every consumer.
"""

import os
from pathlib import Path

from fastapi.templating import Jinja2Templates
from dotenv import load_dotenv

load_dotenv()

# This module lives inside the dashboard_core package; templates/, static/
# and data/ live in the project root one level above it.
PACKAGE_DIR = Path(__file__).resolve().parent
BASE_DIR = str(PACKAGE_DIR.parent)

# ---- Wazuh server API: the PRIMARY channel to the manager ----
# Everything Wazuh owns (ossec.conf, decoders/rules, agents, groups,
# agent.conf, syscollector) goes through here.
API_URL = (os.environ.get("WAZUH_API_URL") or "").rstrip("/")
API_USER = os.environ.get("WAZUH_API_USER")
API_PASSWORD = os.environ.get("WAZUH_API_PASSWORD")
# The manager ships a self-signed certificate by default, so verification
# is opt-IN rather than opt-out - set WAZUH_API_VERIFY_SSL=true once a
# trusted certificate (or a CA bundle path) is in place.
API_VERIFY_SSL = (os.environ.get("WAZUH_API_VERIFY_SSL") or "false").strip().lower() in {
    "1", "true", "yes", "on",
}
API_TIMEOUT = int(os.environ.get("WAZUH_API_TIMEOUT", "60"))

# ---- SSH channel to the Wazuh manager ----
# Retained ONLY for the three features the Wazuh API cannot express,
# because they are host-OS concerns rather than Wazuh concerns: Postfix
# (mail relay/SASL), rsyslog rule files, and package installation.
# See docs/architecture/system-overview.md.
SSH_HOST = os.environ.get("WAZUH_SSH_HOST")
SSH_PORT = int(os.environ.get("WAZUH_SSH_PORT", "22"))
SSH_USER = os.environ.get("WAZUH_SSH_USER")
SSH_KEY_PATH = os.environ.get("WAZUH_SSH_KEY_PATH")

# ---- App settings (can be overridden with environment variables) ----
HOST = os.environ.get("DASHBOARD_HOST", "0.0.0.0")
PORT = int(os.environ.get("DASHBOARD_PORT", "5000"))
MAX_ALERTS = int(os.environ.get("DASHBOARD_MAX_ALERTS", "500"))

# ---- RAG assistant: a separate local service, not the Wazuh manager ----
# Gated behind a feature flag (see DEFAULT_FEATURE_FLAGS below) - it is off
# until an operator turns it on from Console > Features, so a dashboard
# that has never heard of this service does not show a broken "Ask" tab.
RAG_API_URL = (os.environ.get("RAG_API_URL") or "http://localhost:8000").rstrip("/")
RAG_API_TIMEOUT = int(os.environ.get("RAG_API_TIMEOUT", "30"))

# ================================================================
# USER SYSTEM + SETTINGS (plain JSON files, no database)
# ================================================================
DATA_DIR = Path(BASE_DIR) / "data"
DATA_DIR.mkdir(exist_ok=True)

APP_LOG_DIR = DATA_DIR / "app_logs"
USERS_FILE = DATA_DIR / "users.json"
SETTINGS_FILE = DATA_DIR / "settings.json"
SECRET_FILE = DATA_DIR / "secret.key"
SESSION_COOKIE = "wazuh_dashboard_session"
SESSION_MAX_AGE = 60 * 60 * 12  # 12 hours

# ================================================================
# MAIL SETTINGS (stored under the "mail" sub-key of data/settings.json -
# it shares the file with the host/port/note fields but never collides
# with them). The PASSWORD (sasl_pass) is NEVER written here in plain
# text - only the "is it set" flag (sasl_pass_set) is persisted. The real
# password is used for the single moment the "update" command is sent to
# the manager over SSH, and never touches disk.
# ================================================================
DEFAULT_MAIL_SETTINGS = {
    "email_to": "",
    "email_from": "",
    "smtp_server": "",
    "email_maxperhour": "",
    "relayhost": "",
    "sasl_user": "",
    "sasl_pass_set": False,
}

# ================================================================
# FEATURE FLAGS (stored under the "features" sub-key of settings.json).
# Every flag defaults to off. This is not a security boundary - anyone
# with a session can flip it back on from Console > Features - it exists
# so an optional integration does not appear in the UI on a dashboard
# that has never been told the other service exists.
# ================================================================
DEFAULT_FEATURE_FLAGS = {
    "rag_assistant": False,
}

# Shared Jinja2 environment - every route module renders through this one.
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))


def asset_version(static_relpath: str) -> int:
    """Cache-busting token for a static/ file: its own mtime as an int.

    Templates append this as a `?v=` query string on style.css/app.js
    links so an edited file is picked up on the next reload instead of
    silently serving whatever the browser cached under the same URL -
    without it, "the CSS is stale, hard-refresh" recurs on every
    frontend change. Falls back to 0 (still cache-busts across restarts
    even if the file is somehow missing) rather than raising.
    """
    try:
        return int(os.path.getmtime(os.path.join(BASE_DIR, "static", static_relpath)))
    except OSError:
        return 0


templates.env.globals["asset_version"] = asset_version


def feature_enabled(name: str) -> bool:
    """Reads a feature flag fresh, at template-render time.

    A Jinja global rather than a value threaded through every route's own
    context dict: `_sidebar.html` is included by every logged-in page, and
    making it depend on a context key would mean every route that forgot
    to pass it renders a sidebar silently missing the flag - the same
    invisible-failure shape `_sidebar.html`'s own docstring warns about
    for the active-nav-item logic. A global sidesteps that: any template
    can call `feature_enabled('rag_assistant')` with no route involved.

    Imports storage lazily - storage imports this module, so importing it
    back at module load time would be circular.
    """
    from dashboard_core import storage
    return bool(storage.load_feature_flags().get(name, False))


templates.env.globals["feature_enabled"] = feature_enabled
