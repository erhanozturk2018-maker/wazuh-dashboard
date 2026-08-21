"""
JSON-file persistence (no database, by design - see
docs/architecture/system-overview.md "non-goals").

Path constants are read through the ``config`` module at call time so tests can
redirect ``config.SETTINGS_FILE`` to a temporary location.
"""

import json
from pathlib import Path

from dashboard_core import config


def load_json(path: Path, default: dict):
    if not path.exists():
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path: Path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_mail_settings() -> dict:
    """Reads the 'mail' sub-key of settings.json and fills any missing
    fields from the defaults (works safely even when the file does not
    exist at all, or the 'mail' key has not been added yet)."""
    settings = load_json(config.SETTINGS_FILE, {})
    mail = settings.get("mail", {})
    if not isinstance(mail, dict):
        mail = {}
    return {**config.DEFAULT_MAIL_SETTINGS, **mail}


def save_mail_settings(mail_data: dict) -> None:
    """Updates only the 'mail' sub-key and writes the file back, leaving
    the host/port/note fields untouched."""
    if config.SETTINGS_FILE.exists():
        settings = load_json(config.SETTINGS_FILE, {})
        if not isinstance(settings, dict):
            settings = {}
    else:
        config.SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        settings = {}
    settings["mail"] = mail_data
    save_json(config.SETTINGS_FILE, settings)


def load_plugin_status() -> dict:
    """Reads the 'plugins' sub-key of settings.json - the last recorded
    per-package verification results. STRICTLY read-only: loading this
    never triggers a manager-side check and never touches checked_at
    (those change only through services.plugins' explicit flows)."""
    settings = load_json(config.SETTINGS_FILE, {})
    plugins = settings.get("plugins", {})
    return plugins if isinstance(plugins, dict) else {}


def save_plugin_entries(entries: dict) -> None:
    """Merges per-package entries (each {"verified", "version",
    "checked_at"}) into the 'plugins' sub-key, leaving every other
    top-level key AND every other package's entry untouched - a scoped
    postfix re-check must never reset rsyslog's checked_at."""
    if config.SETTINGS_FILE.exists():
        settings = load_json(config.SETTINGS_FILE, {})
        if not isinstance(settings, dict):
            settings = {}
    else:
        config.SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        settings = {}
    plugins = settings.get("plugins")
    if not isinstance(plugins, dict):
        plugins = {}
    plugins.update(entries)
    settings["plugins"] = plugins
    save_json(config.SETTINGS_FILE, settings)


def load_feature_flags() -> dict:
    """Reads the 'features' sub-key of settings.json - dashboard-level
    opt-in features unrelated to anything the manager does. Off by
    default: a feature that talks to another local service should not
    appear until an operator has deliberately turned it on."""
    settings = load_json(config.SETTINGS_FILE, {})
    flags = settings.get("features", {})
    if not isinstance(flags, dict):
        flags = {}
    return {**config.DEFAULT_FEATURE_FLAGS, **flags}


def save_feature_flags(flags: dict) -> None:
    """Updates only the 'features' sub-key, leaving every other top-level
    key (host/port/note, mail, plugins) untouched."""
    if config.SETTINGS_FILE.exists():
        settings = load_json(config.SETTINGS_FILE, {})
        if not isinstance(settings, dict):
            settings = {}
    else:
        config.SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
        settings = {}
    settings["features"] = flags
    save_json(config.SETTINGS_FILE, settings)


def load_users() -> dict:
    return load_json(config.USERS_FILE, {})


def load_run_host_port() -> tuple[str, int]:
    """Resolves the address the server should bind to.

    Host/port saved via the Settings page (General tab) take priority;
    otherwise fall back to the DASHBOARD_HOST/DASHBOARD_PORT environment
    variables, then to the defaults in ``config``.

    This lives here rather than in ``main.py`` so the entry point stays a
    plain ``uvicorn.run()`` call, and so swapping the settings backend
    later changes exactly one function.
    """
    saved = load_json(config.SETTINGS_FILE, {})
    if not isinstance(saved, dict):
        saved = {}
    host = saved.get("host") or config.HOST
    port = int(saved.get("port") or config.PORT)
    return host, port
