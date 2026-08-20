"""
================================================================================
Purpose
================================================================================
Protects the agent-management API surface in `dashboard_core/routes/agents.py`:
the agents page, `/api/agents*`, `/api/groups*`, and the per-agent service
inventory. These routes are the dashboard's only way to list, inspect,
register, remove and re-key Wazuh agents, to manage the groups that
targeted configuration is distributed through, and to ask what a given
machine is actually running. All are session-gated, unlike `/health` and
`/wazuh-webhook`.

There is no local persistence phase anywhere in this flow: the manager's
own database is the single source of truth on every request, and the
list/detail split is a load-bearing performance contract rather than an
implementation detail (`docs/architecture/execution-flow.md`, Flow 4).

================================================================================
What is mocked, and why there
================================================================================
The seam is `wazuh_api.request` (the `api_stub` fixture) rather than the
service functions. That is one layer lower than the previous version of
this module, which mocked `agent_command()` and therefore exercised only
the route body. Stubbing the transport instead means route, service and
error-mapping are all under test together, while nothing reaches a real
manager. `api_stub` raises on any call a test did not register, so a test
cannot quietly pass on a request it never meant to make.

================================================================================
Responsibilities
================================================================================
- Every `/api/*` route requires a session and answers 401 with a JSON body
  rather than a redirect - the HTML page redirects to /login instead, and
  the fetch client depends on that difference.
- Dashboard-side validation runs BEFORE any manager call: agent id, IP and
  name patterns, group-name pattern, and the required confirmations.
- Manager replies are translated into the dashboard's own shapes, and a
  manager failure becomes a 502 carrying a readable message.
- A registration key reaches the caller in the response body only and is
  never written under `data/` - the same write-only handling as `sasl_pass`.
- Destructive actions refuse to proceed on a mismatched confirmation, and
  crucially make no delete call at all in that case.

================================================================================
Out of scope, covered elsewhere
================================================================================
- The service layer's own logic - `tests/services/test_agents_service.py`.
- The API client's transport, retry and error shaping -
  `tests/services/test_wazuh_api.py`.
- Client-side rendering of the agents page - no browser testing here.
"""

import json

import pytest

from dashboard_core import config


def envelope(items, message="ok"):
    return {
        "data": {
            "affected_items": items,
            "total_affected_items": len(items),
            "failed_items": [],
        },
        "message": message,
        "error": 0,
    }


# ======================================================================
# AUTH GATING - a JSON 401 for the API, a redirect for the page
# ======================================================================

@pytest.mark.parametrize("method,url", [
    ("get", "/api/agents"),
    ("get", "/api/agents/001"),
    ("get", "/api/agents/001/services"),
    ("post", "/api/agents"),
    ("post", "/api/agents/001/delete"),
    ("post", "/api/agents/001/key"),
    ("get", "/api/groups"),
    ("get", "/api/groups/default/agents"),
    ("post", "/api/groups"),
    ("post", "/api/groups/default/delete"),
    ("post", "/api/agents/001/group"),
])
def test_api_routes_answer_401_json_when_unauthenticated(unauthenticated_client, method, url):
    response = getattr(unauthenticated_client, method)(url)
    assert response.status_code == 401
    assert "error" in response.json()


def test_the_page_redirects_instead_of_401(unauthenticated_client):
    response = unauthenticated_client.get("/agents", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


# ======================================================================
# LIST / DETAIL
# ======================================================================

def test_list_returns_the_summary_shape(authenticated_client, api_stub):
    api_stub.set("/agents", envelope([
        {"id": "001", "name": "web-01", "ip": "10.0.0.5", "status": "active"},
    ]))
    response = authenticated_client.get("/api/agents")
    assert response.status_code == 200
    assert response.json() == {
        "agents": [{"id": "001", "name": "web-01", "ip": "10.0.0.5", "status": "active"}]
    }


def test_list_handles_no_agents(authenticated_client, api_stub):
    api_stub.set("/agents", envelope([]))
    response = authenticated_client.get("/api/agents")
    assert response.status_code == 200
    assert response.json() == {"agents": []}


def test_list_maps_a_manager_failure_to_502(authenticated_client, api_stub):
    api_stub.fail("/agents", "manager unreachable")
    response = authenticated_client.get("/api/agents")
    assert response.status_code == 502
    assert "manager unreachable" in response.json()["error"]


def test_detail_returns_the_agent(authenticated_client, api_stub):
    api_stub.set("/agents?agents_list=001", envelope([
        {"id": "001", "name": "web-01", "version": "Wazuh v4.14.6"},
    ]))
    response = authenticated_client.get("/api/agents/001")
    assert response.status_code == 200
    assert response.json()["agent"]["version"] == "Wazuh v4.14.6"


def test_detail_rejects_a_malformed_id_before_calling_the_manager(authenticated_client, api_stub):
    response = authenticated_client.get("/api/agents/not-an-id")
    assert response.status_code == 400
    assert api_stub.calls == []


def test_detail_maps_a_missing_agent_to_502(authenticated_client, api_stub):
    api_stub.set("/agents?agents_list=999", envelope([]))
    response = authenticated_client.get("/api/agents/999")
    assert response.status_code == 502
    assert "no agent with id" in response.json()["error"].lower()


# ======================================================================
# SERVICE INVENTORY
# ======================================================================

def test_services_returns_normalized_entries(authenticated_client, api_stub):
    api_stub.set("/syscollector/001/services", envelope([{
        "service": {"name": "cron", "state": "active", "sub_state": "running"},
        "process": {"executable": "/usr/lib/systemd/system/cron.service"},
        "scan": {"time": "2026-08-17T07:42:56+00:00"},
    }]))
    response = authenticated_client.get("/api/agents/001/services")
    assert response.status_code == 200
    service = response.json()["services"][0]
    assert service["name"] == "cron"
    assert service["running"] is True
    # Snapshot data must always carry when it was taken.
    assert service["scanned_at"] == "2026-08-17T07:42:56+00:00"


def test_services_forwards_the_search_to_the_manager(authenticated_client, api_stub):
    api_stub.set("/syscollector/001/services", envelope([]))
    authenticated_client.get("/api/agents/001/services?search=cron")
    assert "search=cron" in api_stub.paths()[-1]


def test_services_rejects_a_malformed_id_before_calling(authenticated_client, api_stub):
    response = authenticated_client.get("/api/agents/bad/services")
    assert response.status_code == 400
    assert api_stub.calls == []


# ======================================================================
# ADD - validation first, then the key handling
# ======================================================================

def test_add_registers_and_returns_the_key(authenticated_client, api_stub):
    api_stub.set("/agents", {"data": {"id": "003", "key": "SECRETKEY"}, "error": 0})
    response = authenticated_client.post("/api/agents", data={"ip": "any", "name": "probe"})
    assert response.status_code == 200
    assert response.json()["agent"] == {"id": "003", "name": "probe", "key": "SECRETKEY"}


@pytest.mark.parametrize("payload,reason", [
    ({"ip": "", "name": "probe"}, "missing ip"),
    ({"ip": "any", "name": ""}, "missing name"),
    ({"ip": "999.999.999.999", "name": "probe"}, "malformed ip"),
    ({"ip": "any", "name": "bad name!"}, "malformed name"),
])
def test_add_validates_before_calling_the_manager(authenticated_client, api_stub, payload, reason):
    response = authenticated_client.post("/api/agents", data=payload)
    assert response.status_code == 400, reason
    assert api_stub.calls == [], f"{reason}: reached the manager anyway"


def test_add_maps_a_manager_failure_to_502(authenticated_client, api_stub):
    api_stub.fail("/agents", "manager unreachable")
    response = authenticated_client.post("/api/agents", data={"ip": "any", "name": "probe"})
    assert response.status_code == 502


def test_the_key_is_never_written_to_disk(authenticated_client, api_stub):
    """The key is returned once, in this response body, and nowhere else -
    the same write-only handling documented for sasl_pass."""
    api_stub.set("/agents", {"data": {"id": "003", "key": "SUPERSECRET"}, "error": 0})
    response = authenticated_client.post("/api/agents", data={"ip": "any", "name": "probe"})
    assert "SUPERSECRET" in response.text

    for path in config.DATA_DIR.rglob("*"):
        if path.is_file():
            assert "SUPERSECRET" not in path.read_text(encoding="utf-8", errors="ignore"), path


# ======================================================================
# DELETE - the confirmation guard is the whole point
# ======================================================================

def test_delete_requires_a_confirm_name(authenticated_client, api_stub):
    response = authenticated_client.post("/api/agents/001/delete", data={"confirm_name": ""})
    assert response.status_code == 400
    assert api_stub.calls == []


def test_delete_refuses_a_mismatched_name_and_makes_no_delete_call(authenticated_client, api_stub):
    api_stub.set("/agents?agents_list=001", envelope([{"id": "001", "name": "web-01"}]))
    response = authenticated_client.post(
        "/api/agents/001/delete", data={"confirm_name": "something-else"}
    )
    assert response.status_code == 502
    assert "refusing to delete" in response.json()["error"].lower()
    assert all(method != "DELETE" for method, _, _ in api_stub.calls)


def test_delete_proceeds_on_a_matching_name(authenticated_client, api_stub):
    api_stub.set("/agents?agents_list=001", envelope([{"id": "001", "name": "web-01"}]))
    api_stub.set("/agents?agents_list=001&status=all", envelope(["001"]))
    response = authenticated_client.post(
        "/api/agents/001/delete", data={"confirm_name": "web-01"}
    )
    assert response.status_code == 200
    assert "removed" in response.json()["message"]


def test_delete_rejects_a_malformed_id_before_calling(authenticated_client, api_stub):
    response = authenticated_client.post("/api/agents/xx/delete", data={"confirm_name": "x"})
    assert response.status_code == 400
    assert api_stub.calls == []


# ======================================================================
# RE-KEY
# ======================================================================

def test_key_returns_the_agents_key(authenticated_client, api_stub):
    api_stub.set("/agents/001/key", envelope([{"id": "001", "key": "ABC123"}]))
    response = authenticated_client.post("/api/agents/001/key")
    assert response.status_code == 200
    assert response.json() == {"key": "ABC123"}


def test_key_maps_a_manager_failure_to_502(authenticated_client, api_stub):
    api_stub.fail("/agents/001/key", "manager unreachable")
    response = authenticated_client.post("/api/agents/001/key")
    assert response.status_code == 502


# ======================================================================
# GROUPS
# ======================================================================

def test_groups_list(authenticated_client, api_stub):
    api_stub.set("/groups", envelope([{"name": "default", "count": 2, "configSum": "x"}]))
    response = authenticated_client.get("/api/groups")
    assert response.status_code == 200
    assert response.json()["groups"][0]["name"] == "default"


def test_group_members(authenticated_client, api_stub):
    api_stub.set("/groups/default/agents", envelope([
        {"id": "001", "name": "web-01", "status": "active"},
    ]))
    response = authenticated_client.get("/api/groups/default/agents")
    assert response.status_code == 200
    assert response.json()["agents"][0]["id"] == "001"


def test_group_create(authenticated_client, api_stub):
    api_stub.set("/groups", {"message": "Group created.", "error": 0})
    response = authenticated_client.post("/api/groups", data={"name": "ldap_servers"})
    assert response.status_code == 200
    assert api_stub.calls[0][2]["json_body"] == {"group_id": "ldap_servers"}


def test_group_create_rejects_a_name_with_path_components(authenticated_client, api_stub):
    """A group name becomes a directory name on the manager, so anything
    resembling a path must not reach it."""
    response = authenticated_client.post("/api/groups", data={"name": "../etc"})
    assert response.status_code == 400
    assert api_stub.calls == []


def test_group_delete_requires_the_name_typed_back(authenticated_client, api_stub):
    """Deleting a group silently un-configures every agent in it."""
    response = authenticated_client.post(
        "/api/groups/ldap/delete", data={"confirm_name": "wrong"}
    )
    assert response.status_code == 400
    assert api_stub.calls == []


def test_group_delete_proceeds_when_confirmed(authenticated_client, api_stub):
    api_stub.set("/groups?groups_list=ldap", envelope(["ldap"]))
    response = authenticated_client.post(
        "/api/groups/ldap/delete", data={"confirm_name": "ldap"}
    )
    assert response.status_code == 200


def test_agent_group_assignment(authenticated_client, api_stub):
    api_stub.set("/agents/001/group/ldap", envelope(["001"]))
    response = authenticated_client.post(
        "/api/agents/001/group", data={"group": "ldap", "action": "assign"}
    )
    assert response.status_code == 200
    assert api_stub.calls[-1][0] == "PUT"

    response = authenticated_client.post(
        "/api/agents/001/group", data={"group": "ldap", "action": "unassign"}
    )
    assert response.status_code == 200
    assert api_stub.calls[-1][0] == "DELETE"


def test_agent_group_assignment_rejects_an_unknown_action(authenticated_client, api_stub):
    response = authenticated_client.post(
        "/api/agents/001/group", data={"group": "ldap", "action": "sideways"}
    )
    assert response.status_code == 400
    assert api_stub.calls == []
