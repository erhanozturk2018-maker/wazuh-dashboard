"""
Manager-wide control actions that belong to no single feature page.

Currently one: applying pending configuration changes by restarting the
Wazuh manager. It lives in its own router because it is genuinely
cross-cutting - Pipeline and Alerting both need it, and neither owns it -
and because putting it in `dashboard.py` would mix a manager operation
into the router that owns this application's own alert surface.

**Why an operator ever needs to trigger this by hand.** Configuration
writes restart the manager automatically (`services/manager_control.py`).
This endpoint is the retry path for when that automatic restart fails,
which on this deployment is not hypothetical: the manager saturates and
times out often enough that a save can legitimately land on disk with the
restart never completing. Without a manual path the operator would have
to SSH in to finish a change the dashboard had already made.
"""

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from dashboard_core.auth import get_current_user
from dashboard_core.services import manager_control

router = APIRouter()


@router.post("/api/manager/restart")
async def api_manager_restart(request: Request):
    """Restarts the manager so anything already written becomes active.

    Slow by nature - a full restart plus a per-service liveness check -
    so the client shows a blocking overlay rather than letting this look
    like a hung page.
    """
    if not get_current_user(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    ok, message = manager_control.apply_changes()
    request.state.log_target = "manager"
    request.state.log_detail = str(message)
    if not ok:
        return JSONResponse({"error": str(message)}, status_code=502)
    return JSONResponse({"message": str(message)})
