"""
The alert surface: the dashboard page, the unauthenticated webhook the manager
POSTs to, the alert read/clear API and the health check.

``/wazuh-webhook`` and ``/health`` are the only two unauthenticated endpoints -
the manager cannot log in (docs/security/dashboard-side.md).
"""

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

from dashboard_core import config
from dashboard_core.alerts import alerts, alerts_lock, extract_fields
from dashboard_core.auth import get_current_user

router = APIRouter()


@router.get("/favicon.ico")
async def favicon():
    return Response(status_code=204)  # "No content" - the browser accepts this silently


@router.get("/")
async def dashboard(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    return config.templates.TemplateResponse(request, "index.html", {"username": user})


@router.post("/wazuh-webhook")
async def receive_alert(request: Request):
    """The address the Wazuh manager (or your own test requests) POSTs to."""
    try:
        raw = await request.json()
    except Exception:
        body = await request.body()
        raw = {"full_log": body.decode("utf-8", errors="ignore")}

    if not isinstance(raw, dict):
        raw = {"full_log": str(raw)}

    record = extract_fields(raw)

    with alerts_lock:
        alerts.insert(0, record)
        if len(alerts) > config.MAX_ALERTS:
            alerts.pop()

    print(f"[+] New alert received: level={record['level']} rule_id={record['rule_id']} ip={record['ip']}")
    return {"status": "ok"}


@router.get("/api/alerts")
async def get_alerts(request: Request):
    if not get_current_user(request):
        return JSONResponse(content={"error": "unauthorized"}, status_code=401)
    with alerts_lock:
        return JSONResponse(content=alerts)


@router.post("/api/clear")
async def clear_alerts(request: Request):
    if not get_current_user(request):
        return JSONResponse(content={"error": "unauthorized"}, status_code=401)
    with alerts_lock:
        alerts.clear()
    return {"status": "cleared"}


@router.get("/health")
async def health():
    """Simple health check - used to verify the server is up."""
    with alerts_lock:
        return {"status": "healthy", "alert_count": len(alerts)}
