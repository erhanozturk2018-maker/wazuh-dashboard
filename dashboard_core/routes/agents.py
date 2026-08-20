"""
AGENTS - agent records, group membership, and per-agent service inventory.

The page is /agents; the data endpoints are /api/agents* and /api/groups*.
Validation here is for fast UI feedback only - the manager re-checks
everything it is asked to do.

NOTE: the list (GET /api/agents) is one manager call regardless of agent
count; a single agent's detail, its services, and its key are separate
calls made only when the operator opens that agent. This split is a
contract, not an optimisation detail: adding a column that needs
per-agent data would silently turn one API call into N against a manager
that is measurably slow (docs/architecture/execution-flow.md).
"""

from fastapi import APIRouter, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse

from dashboard_core import config
from dashboard_core.auth import get_current_user
from dashboard_core.services import agents as agents_service
from dashboard_core.validation import AGENT_ID_RE, AGENT_IP_RE, AGENT_NAME_RE

router = APIRouter()

# Group names become directory names on the manager, so the same
# no-path-components discipline as custom file names applies.
GROUP_NAME_RE = AGENT_NAME_RE


def _agent_json_error(message: str, status_code: int) -> JSONResponse:
    if not message:
        message = "Unknown error."
    return JSONResponse(content={"error": message}, status_code=status_code)


def _require_api_user(request: Request) -> JSONResponse | None:
    """Every /api/agents* and /api/groups* endpoint requires a session.
    Unlike the page routes it answers with a 401 JSON body rather than a
    redirect - the client calls these with fetch and expects the same
    pattern as /api/alerts."""
    if not get_current_user(request):
        return _agent_json_error("unauthorized", 401)
    return None


@router.get("/agents")
async def agents_page(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    return config.templates.TemplateResponse(request, "agents.html", {"username": user})


# ----------------------------------------------------------------------
# AGENTS
# ----------------------------------------------------------------------

@router.get("/api/agents")
async def api_agents_list(request: Request):
    unauthorized = _require_api_user(request)
    if unauthorized:
        return unauthorized
    ok, result = agents_service.list_agents()
    if not ok:
        return _agent_json_error(str(result), 502)
    return JSONResponse(content={"agents": result})


@router.get("/api/agents/{agent_id}")
async def api_agent_detail(request: Request, agent_id: str):
    unauthorized = _require_api_user(request)
    if unauthorized:
        return unauthorized
    if not AGENT_ID_RE.match(agent_id):
        return _agent_json_error("Invalid agent id.", 400)
    ok, result = agents_service.get_agent(agent_id)
    if not ok:
        return _agent_json_error(str(result), 502)
    return JSONResponse(content={"agent": result})


@router.get("/api/agents/{agent_id}/services")
async def api_agent_services(request: Request, agent_id: str, search: str = ""):
    """The agent's service inventory.

    This is snapshot data: each entry carries the scan time it was
    observed at, and the client must show it rather than presenting a
    service state as current.
    """
    unauthorized = _require_api_user(request)
    if unauthorized:
        return unauthorized
    if not AGENT_ID_RE.match(agent_id):
        return _agent_json_error("Invalid agent id.", 400)

    ok, result = agents_service.list_services(agent_id, search=search.strip() or None)
    if not ok:
        return _agent_json_error(str(result), 502)
    return JSONResponse(content={"services": result})


@router.post("/api/agents")
async def api_agent_add(request: Request, ip: str = Form(""), name: str = Form("")):
    unauthorized = _require_api_user(request)
    if unauthorized:
        return unauthorized

    ip = ip.strip()
    name = name.strip()
    if not ip or not name:
        return _agent_json_error("Both IP and name are required.", 400)
    if not AGENT_IP_RE.match(ip):
        return _agent_json_error("IP must be an IPv4 address, a CIDR range, or 'any'.", 400)
    if not AGENT_NAME_RE.match(name):
        return _agent_json_error(
            "Name may only contain letters, digits, dot, underscore and hyphen.", 400
        )

    ok, result = agents_service.add_agent(name, ip)
    request.state.log_target = name
    request.state.log_detail = "-" if ok else str(result)
    if not ok:
        return _agent_json_error(str(result), 502)
    # The key is returned in THIS response only and is never stored
    # anywhere on the dashboard (docs/security/dashboard-side.md).
    return JSONResponse(content={"agent": result})


@router.post("/api/agents/{agent_id}/delete")
async def api_agent_delete(request: Request, agent_id: str, confirm_name: str = Form("")):
    unauthorized = _require_api_user(request)
    if unauthorized:
        return unauthorized
    if not AGENT_ID_RE.match(agent_id):
        return _agent_json_error("Invalid agent id.", 400)

    # The record this id points at may have shifted since the list was
    # fetched, so the caller must state the name it believes it is
    # deleting. The service layer refuses on a mismatch.
    confirm_name = confirm_name.strip()
    if not confirm_name:
        return _agent_json_error("confirm_name is required.", 400)

    ok, result = agents_service.delete_agent(agent_id, confirm_name)
    request.state.log_target = confirm_name
    request.state.log_detail = "-" if ok else str(result)
    if not ok:
        return _agent_json_error(str(result), 502)
    return JSONResponse(content={"message": str(result)})


@router.post("/api/agents/{agent_id}/key")
async def api_agent_key(request: Request, agent_id: str):
    unauthorized = _require_api_user(request)
    if unauthorized:
        return unauthorized
    if not AGENT_ID_RE.match(agent_id):
        return _agent_json_error("Invalid agent id.", 400)
    ok, result = agents_service.get_agent_key(agent_id)
    if not ok:
        return _agent_json_error(str(result), 502)
    return JSONResponse(content={"key": result})


# ----------------------------------------------------------------------
# GROUPS
# ----------------------------------------------------------------------

@router.get("/api/groups")
async def api_groups_list(request: Request):
    unauthorized = _require_api_user(request)
    if unauthorized:
        return unauthorized
    ok, result = agents_service.list_groups()
    if not ok:
        return _agent_json_error(str(result), 502)
    return JSONResponse(content={"groups": result})


@router.get("/api/groups/{group}/agents")
async def api_group_agents(request: Request, group: str):
    unauthorized = _require_api_user(request)
    if unauthorized:
        return unauthorized
    if not GROUP_NAME_RE.match(group):
        return _agent_json_error("Invalid group name.", 400)
    ok, result = agents_service.list_group_agents(group)
    if not ok:
        return _agent_json_error(str(result), 502)
    return JSONResponse(content={"agents": result})


@router.post("/api/groups")
async def api_group_create(request: Request, name: str = Form("")):
    unauthorized = _require_api_user(request)
    if unauthorized:
        return unauthorized
    name = name.strip()
    if not GROUP_NAME_RE.match(name):
        return _agent_json_error(
            "Group name may only contain letters, digits, dot, underscore and hyphen.",
            400,
        )
    ok, result = agents_service.create_group(name)
    request.state.log_target = name
    request.state.log_detail = "-" if ok else str(result)
    if not ok:
        return _agent_json_error(str(result), 502)
    return JSONResponse(content={"message": str(result)})


@router.post("/api/groups/{group}/delete")
async def api_group_delete(request: Request, group: str, confirm_name: str = Form("")):
    unauthorized = _require_api_user(request)
    if unauthorized:
        return unauthorized
    if not GROUP_NAME_RE.match(group):
        return _agent_json_error("Invalid group name.", 400)
    # Deleting a group silently un-configures every agent in it, so the
    # operator types the name back - the same guard the agent delete uses.
    if confirm_name.strip() != group:
        return _agent_json_error(
            "Type the group's name to confirm the deletion.", 400
        )
    ok, result = agents_service.delete_group(group)
    request.state.log_target = group
    request.state.log_detail = "-" if ok else str(result)
    if not ok:
        return _agent_json_error(str(result), 502)
    return JSONResponse(content={"message": str(result)})


@router.post("/api/agents/{agent_id}/group")
async def api_agent_assign_group(
    request: Request, agent_id: str, group: str = Form(""), action: str = Form("assign")
):
    unauthorized = _require_api_user(request)
    if unauthorized:
        return unauthorized
    if not AGENT_ID_RE.match(agent_id):
        return _agent_json_error("Invalid agent id.", 400)
    group = group.strip()
    if not GROUP_NAME_RE.match(group):
        return _agent_json_error("Invalid group name.", 400)
    if action not in ("assign", "unassign"):
        return _agent_json_error("Action must be 'assign' or 'unassign'.", 400)

    if action == "assign":
        ok, result = agents_service.assign_agent(agent_id, group)
    else:
        ok, result = agents_service.unassign_agent(agent_id, group)

    request.state.log_target = f"{agent_id}/{group}"
    request.state.log_detail = "-" if ok else str(result)
    if not ok:
        return _agent_json_error(str(result), 502)
    return JSONResponse(content={"message": str(result)})
