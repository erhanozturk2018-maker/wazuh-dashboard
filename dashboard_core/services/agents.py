"""
Agents, agent groups, and per-agent service inventory, through the Wazuh API.

Replaces the SSH path to ``agent-manager-tool.py``. Three things about
this module are worth knowing before changing it:

**The list stays lightweight on purpose.** ``list_agents()`` returns only
id/name/ip/status. That was a hard constraint under SSH (per-agent detail
meant one subprocess each) and it stays one here for a different reason:
this manager's API is measurably slow and bimodal, so a table that costs
one call per row would make the agents page the slowest screen in the
product. Detail is fetched only when an operator opens one agent.

**Delete keeps its confirmation check even though the API does not ask
for one.** The caller must pass the name it believes belongs to that id;
if the manager disagrees, the delete is refused. Agent ids get reused and
the operator may be looking at a stale page, so this guard is the only
thing standing between "remove the agent I clicked" and "remove whatever
now holds that id". The SSH tool enforced it manager-side; with the API
there is no manager-side tool left, so it lives here.

**The service inventory is snapshot data, not live state.** Every entry
carries the ``scan.time`` it was observed at, and observed times on this
manager range across weeks within a single inventory. Callers must show
that timestamp rather than presenting a service's state as current.
"""

from dashboard_core.services import wazuh_api

# Wazuh's own service inventory reports different fields per platform:
# Linux fills state/sub_state ("active"/"running") and leaves start_type
# blank; Windows fills state ("RUNNING"/"STOPPED") and start_type
# ("SYSTEM_START"/"DEMAND_START"/...) and leaves sub_state blank. Both
# observed directly - normalize() below flattens that difference so the
# UI does not have to branch on platform.
_BLANK = {"", " ", None}


def _items(payload) -> list[dict]:
    if not isinstance(payload, dict):
        return []
    return payload.get("data", {}).get("affected_items", []) or []


def _first(payload) -> dict | None:
    items = _items(payload)
    return items[0] if items else None


# ----------------------------------------------------------------------
# AGENTS
# ----------------------------------------------------------------------

def list_agents() -> tuple[bool, list[dict] | str]:
    """id/name/ip/status for every agent - one call regardless of count."""
    ok, payload = wazuh_api.request(
        "GET", "/agents?select=id,name,ip,status&limit=1000"
    )
    if not ok:
        return False, str(payload)
    return True, [
        {
            "id": a.get("id", ""),
            "name": a.get("name", ""),
            "ip": a.get("ip", ""),
            "status": a.get("status", ""),
        }
        for a in _items(payload)
    ]


def get_agent(agent_id: str) -> tuple[bool, dict | str]:
    """Full detail for one agent: os, version, lastKeepAlive, group
    membership and group_config_status."""
    ok, payload = wazuh_api.request("GET", f"/agents?agents_list={agent_id}")
    if not ok:
        return False, str(payload)
    agent = _first(payload)
    if agent is None:
        return False, f"No agent with id '{agent_id}'."
    return True, agent


def get_agent_key(agent_id: str) -> tuple[bool, str]:
    """The agent's registration key.

    Measured shape: ``data.affected_items[0].key`` is a dict entry, unlike
    the plain string ``manage_agents -j -e`` used to return over SSH. The
    key is passed straight to the browser and never persisted.
    """
    ok, payload = wazuh_api.request("GET", f"/agents/{agent_id}/key")
    if not ok:
        return False, str(payload)
    entry = _first(payload)
    key = (entry or {}).get("key", "")
    if not key:
        return False, f"The manager returned no key for agent '{agent_id}'."
    return True, key


def add_agent(name: str, ip: str = "any") -> tuple[bool, dict | str]:
    """Registers an agent and returns ``{"id", "name", "key"}``.

    Nothing is pushed to the monitored host - the dashboard can reach the
    manager, never the endpoint. Carrying the key over is a manual step.
    """
    ok, payload = wazuh_api.request(
        "POST", "/agents", json_body={"name": name, "ip": ip}
    )
    if not ok:
        return False, str(payload)
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, dict) or not data.get("id"):
        return False, f"The agent was not created as expected: {payload}"
    return True, {"id": data.get("id"), "name": name, "key": data.get("key", "")}


def delete_agent(agent_id: str, confirm_name: str) -> tuple[bool, str]:
    """Removes an agent, but only if ``confirm_name`` still matches what
    the manager has registered under that id. See the module docstring."""
    ok, agent = get_agent(agent_id)
    if not ok:
        return False, f"Could not verify the agent before deleting: {agent}"

    actual = agent.get("name", "")
    if actual != confirm_name:
        return False, (
            f"Refusing to delete: agent '{agent_id}' is registered as "
            f"'{actual}', not '{confirm_name}'. Reload the list and retry."
        )

    ok, payload = wazuh_api.request(
        "DELETE",
        f"/agents?agents_list={agent_id}&status=all&older_than=0s",
    )
    if not ok:
        return False, str(payload)
    return True, f"Agent '{agent_id}' removed."


# ----------------------------------------------------------------------
# GROUPS
# ----------------------------------------------------------------------

def list_groups() -> tuple[bool, list[dict] | str]:
    ok, payload = wazuh_api.request("GET", "/groups?limit=1000")
    if not ok:
        return False, str(payload)
    return True, [
        {
            "name": g.get("name", ""),
            "_id": g.get("name", ""),
            "count": g.get("count", 0),
            "config_sum": g.get("configSum", ""),
        }
        for g in _items(payload)
    ]


def create_group(name: str) -> tuple[bool, str]:
    ok, payload = wazuh_api.request("POST", "/groups", json_body={"group_id": name})
    if not ok:
        return False, str(payload)
    return True, f"Group '{name}' created."


def delete_group(name: str) -> tuple[bool, str]:
    if name == "default":
        return False, "The 'default' group cannot be deleted."
    ok, payload = wazuh_api.request("DELETE", f"/groups?groups_list={name}")
    if not ok:
        return False, str(payload)
    return True, f"Group '{name}' deleted."


def list_group_agents(name: str) -> tuple[bool, list[dict] | str]:
    ok, payload = wazuh_api.request(
        "GET", f"/groups/{name}/agents?select=id,name,status&limit=1000"
    )
    if not ok:
        return False, str(payload)
    return True, [
        {"id": a.get("id", ""), "name": a.get("name", ""), "status": a.get("status", "")}
        for a in _items(payload)
    ]


def assign_agent(agent_id: str, group: str) -> tuple[bool, str]:
    ok, payload = wazuh_api.request("PUT", f"/agents/{agent_id}/group/{group}")
    if not ok:
        return False, str(payload)
    return True, f"Agent '{agent_id}' added to '{group}'."


def unassign_agent(agent_id: str, group: str) -> tuple[bool, str]:
    ok, payload = wazuh_api.request("DELETE", f"/agents/{agent_id}/group/{group}")
    if not ok:
        return False, str(payload)
    return True, f"Agent '{agent_id}' removed from '{group}'."


# ----------------------------------------------------------------------
# GROUP CONFIGURATION (agent.conf)
# ----------------------------------------------------------------------

def read_group_config(group: str) -> tuple[bool, str]:
    """A group's agent.conf as raw XML."""
    ok, payload = wazuh_api.request(
        "GET", f"/groups/{group}/files/agent.conf?raw=true"
    )
    if not ok:
        return False, str(payload)
    return True, payload if isinstance(payload, str) else str(payload)


def write_group_config(group: str, content: str) -> tuple[bool, str]:
    """Replaces a group's agent.conf.

    Measured: this endpoint rejects ``application/octet-stream`` with
    HTTP 415 and names ``application/xml``, unlike the decoder/rule upload
    endpoints which want octet-stream. The inconsistency is the API's, not
    a mistake here - do not "unify" the two without re-testing both.
    """
    if not (content or "").strip():
        return False, "The configuration cannot be empty."
    ok, payload = wazuh_api.request(
        "PUT",
        f"/groups/{group}/configuration",
        raw_body=content,
        content_type="application/xml",
    )
    if not ok:
        return False, str(payload)
    return True, f"Configuration for '{group}' saved."


# ----------------------------------------------------------------------
# SERVICE INVENTORY (syscollector)
# ----------------------------------------------------------------------

def normalize_service(entry: dict) -> dict:
    """Flattens one inventory entry into a platform-independent shape.

    Linux and Windows populate different fields for the same concept, so
    the raw entry cannot be rendered directly without the UI branching on
    platform. ``running`` is deliberately a tri-state: True/False when the
    state is recognised, None when it is not, so an unfamiliar value is
    displayed as unknown rather than silently reported as stopped.
    """
    service = entry.get("service", {}) or {}
    state = str(service.get("state") or "").strip()
    sub_state = str(service.get("sub_state") or "").strip()
    lowered = state.lower()

    if lowered in {"active", "running"}:
        running = True
    elif lowered in {"inactive", "stopped", "failed", "dead"}:
        running = False
    else:
        running = None

    detail = sub_state if sub_state not in _BLANK else str(
        service.get("start_type") or ""
    ).strip()

    return {
        "name": service.get("name") or service.get("id") or "",
        "description": (service.get("description") or "").strip(),
        "state": state,
        "detail": detail if detail not in _BLANK else "",
        "running": running,
        "enabled": (service.get("enabled") or "").strip(),
        "executable": (entry.get("process", {}) or {}).get("executable", "").strip(),
        # Always carried: this is snapshot data and the UI must say when
        # it was taken. See the module docstring.
        "scanned_at": (entry.get("scan", {}) or {}).get("time", ""),
    }


def list_services(
    agent_id: str, *, search: str | None = None, limit: int = 500
) -> tuple[bool, list[dict] | str]:
    """The agent's service inventory, optionally filtered by the manager.

    ``search`` is applied server-side, which makes "does this agent have
    service X" a single cheap call rather than a full inventory fetch
    plus client-side filtering.
    """
    path = f"/syscollector/{agent_id}/services?limit={limit}"
    if search:
        path += f"&search={search}"

    ok, payload = wazuh_api.request("GET", path)
    if not ok:
        return False, str(payload)
    return True, [normalize_service(entry) for entry in _items(payload)]


def find_service(agent_id: str, name: str) -> tuple[bool, dict | str]:
    """Answers "is this exact service present on this agent?".

    Returns ``{"exact": dict|None, "candidates": [...]}``.

    The distinction is not pedantry. The API's ``search`` is a substring
    match across every field including the description, so searching a
    Windows agent for "Spooler" also returns *PrintScanBrokerService*,
    whose description happens to mention a spooler. Handing back the first
    result as though it were the answer would tell an operator that
    "Spooler" exists and is stopped while they are actually looking at a
    different service - and a check configured on a service the host does
    not run is precisely how this feature would manufacture false alerts.

    So an exact name match is reported as ``exact``; anything else is only
    ever offered as a ``candidates`` suggestion for the operator to choose
    from.
    """
    ok, services = list_services(agent_id, search=name, limit=50)
    if not ok:
        return False, services

    lowered = name.strip().lower()
    exact = next((s for s in services if s["name"].lower() == lowered), None)
    return True, {
        "exact": exact,
        "candidates": [s for s in services if s is not exact],
    }
