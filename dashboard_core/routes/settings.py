"""
CONSOLE SETTINGS - this application's own configuration.

What is left here is deliberately narrow. The page used to mix the
dashboard's own bind address with four tabs that reconfigured a separate,
security-sensitive machine, and the interface gave no sign of the
difference: the same "Save changes" button wrote a local JSON file on one
tab and restarted the Wazuh manager on the next.

Manager-facing configuration now lives where it belongs - notification
settings on /alerting, log collection and parsing on /pipeline, agents and
groups on /agents. Three things remain:

  General   the host/port this console binds to, and a free-form note
  Plugins   system packages the SSH-backed features depend on
  Features  opt-in dashboard features unrelated to the manager (routes/rag.py)

Plugins is the one manager-touching item still here, because it is not a
feature in its own right - it verifies the operating-system packages that
mail delivery and remote log intake need in order to work at all.

Features exists for the opposite reason: it is where an integration that
has NOTHING to do with the manager gets turned on, deliberately, before it
appears anywhere else in the UI. No confirmation dialog on activation -
flipping the flag has no side effect on any external system (it does not
write to, restart, or notify anything but this dashboard's own settings
file), so a confirm-are-you-sure step would be friction with nothing behind
it. See config.DEFAULT_FEATURE_FLAGS and storage.load_feature_flags.
"""

import socket

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from dashboard_core import config
from dashboard_core.auth import get_current_user
from dashboard_core.services.plugins import KNOWN_PLUGINS, verify_and_record_plugins
from dashboard_core.storage import (
    load_feature_flags,
    load_json,
    load_plugin_status,
    save_feature_flags,
    save_json,
)

router = APIRouter()

TABS = ("general", "plugins", "features")


def get_local_ips() -> list[str]:
    """Addresses this machine answers on, so the operator can tell the
    manager where to send its webhooks."""
    ips = set()
    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            if not ip.startswith("127."):
                ips.add(ip)
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    return sorted(ips)


def _settings_context(request: Request, user: str, tab: str, saved: bool,
                      error: str | None = None, host_override: dict | None = None) -> dict:
    """Both tabs' data is cheap - local JSON and a socket lookup - so
    unlike /pipeline and /alerting this page still prepares everything on
    every render. Nothing here calls the manager."""
    current = load_json(config.SETTINGS_FILE, {})
    host_data = host_override or {
        "host": current.get("host", ""),
        "port": current.get("port", ""),
        "note": current.get("note", ""),
    }
    return {
        "request": request,
        "username": user,
        "tab": tab if tab in TABS else "general",
        "host": host_data["host"],
        "port": host_data["port"],
        "note": host_data["note"],
        "local_ips": get_local_ips(),
        "current_port": config.PORT,
        "saved": saved,
        "error": error,
        # A READ-ONLY snapshot of the last verification. Rendering this
        # never triggers a check and never moves checked_at - that would
        # make the timestamp meaningless as "when a human last verified
        # this" (docs/knowledge/design-decisions.md).
        "plugins_status": load_plugin_status(),
        "known_plugins": KNOWN_PLUGINS,
        "features": load_feature_flags(),
        "rag_api_url": config.RAG_API_URL,
    }


@router.get("/settings")
async def settings_page(request: Request, saved: str = None, tab: str = "general"):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    return config.templates.TemplateResponse(
        request, "settings.html",
        _settings_context(request, user, tab, bool(saved)),
    )


@router.post("/settings")
async def settings_submit(
    request: Request,
    host: str = Form(""),
    port: str = Form(""),
    note: str = Form(""),
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    port = port.strip()
    if port and not port.isdigit():
        return config.templates.TemplateResponse(
            request, "settings.html",
            _settings_context(
                request, user, "general", False,
                error="Port must contain digits only (e.g. 5000).",
                host_override={"host": host, "port": port, "note": note},
            ),
            status_code=400,
        )

    # Read the existing file first: this write must not clobber the other
    # sub-keys living in the same file, notably "mail" and "plugins".
    data = load_json(config.SETTINGS_FILE, {})
    if not isinstance(data, dict):
        data = {}
    for key in ("host", "port", "note"):
        data.pop(key, None)
    if host.strip():
        data["host"] = host.strip()
    if port:
        data["port"] = int(port)
    if note.strip():
        data["note"] = note.strip()

    save_json(config.SETTINGS_FILE, data)
    return RedirectResponse("/settings?saved=1&tab=general", status_code=303)


# ======================================================================
# MANAGE PLUGINS - one of only two paths that update the recorded plugin
# state and its checked_at. Page loads only ever read it.
# ======================================================================

@router.post("/settings/plugins")
async def plugins_submit(request: Request, plugins: list[str] = Form(default=[])):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    def fail(message: str):
        return config.templates.TemplateResponse(
            request, "settings.html",
            _settings_context(request, user, "plugins", False, error=message),
            status_code=400,
        )

    selected = [p.strip() for p in plugins if p.strip()]
    if not selected:
        return fail("Select at least one package to verify.")
    unknown = [p for p in selected if p not in KNOWN_PLUGINS]
    if unknown:
        return fail(f"Unknown package(s): {', '.join(unknown)}")

    entries, error = verify_and_record_plugins(selected)
    if error:
        return fail(f"Verification failed: {error}")

    return RedirectResponse("/settings?saved=1&tab=plugins", status_code=303)


# ======================================================================
# FEATURES - opt-in dashboard features. Local JSON only; nothing here
# reaches the manager or any other machine.
# ======================================================================

@router.post("/settings/features")
async def features_submit(request: Request, rag_assistant: str = Form("")):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)

    # An unchecked HTML checkbox submits nothing at all, so absence is
    # what "off" looks like - the form posts on toggle either way.
    flags = load_feature_flags()
    flags["rag_assistant"] = bool(rag_assistant)
    save_feature_flags(flags)

    request.state.log_target = "features"
    request.state.log_detail = f"rag_assistant={'on' if flags['rag_assistant'] else 'off'}"
    return RedirectResponse("/settings?saved=1&tab=features", status_code=303)


# ======================================================================
# Where things moved. These keep older links and bookmarks working rather
# than answering them with a 404.
# ======================================================================

@router.get("/settings/mail")
async def mail_moved():
    return RedirectResponse("/alerting?tab=email", status_code=301)


@router.get("/settings/email-alerts")
async def email_alerts_moved():
    return RedirectResponse("/alerting?tab=email", status_code=301)


@router.get("/settings/integrations")
async def integrations_moved():
    return RedirectResponse("/alerting?tab=integrations", status_code=301)


@router.get("/settings/isp")
async def isp_moved():
    return RedirectResponse("/pipeline", status_code=301)


@router.get("/settings/plugins")
async def plugins_page_redirect():
    return RedirectResponse("/settings?tab=plugins", status_code=303)
