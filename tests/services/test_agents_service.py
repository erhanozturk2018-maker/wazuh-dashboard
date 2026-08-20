"""
Agents, groups, and service inventory over the Wazuh API.

Replaces the agent half of the old tests/services/test_manager_service.py.
Two of that file's concerns are gone rather than moved: there is no
restart banner to scan past on stdout, and the key arrives as a dict entry
rather than as a bare string.
"""

import pytest

from dashboard_core.services import agents


def _envelope(items, message="ok"):
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
# AGENTS
# ======================================================================

def test_list_agents_is_one_call_and_returns_a_summary(api_stub):
    api_stub.set("/agents", _envelope([
        {"id": "000", "name": "WazuhManager", "ip": "127.0.0.1", "status": "active"},
        {"id": "001", "name": "web-01", "ip": "10.0.0.5", "status": "disconnected"},
    ]))
    ok, rows = agents.list_agents()
    assert ok
    assert rows == [
        {"id": "000", "name": "WazuhManager", "ip": "127.0.0.1", "status": "active"},
        {"id": "001", "name": "web-01", "ip": "10.0.0.5", "status": "disconnected"},
    ]
    # One call regardless of how many agents came back - a per-agent call
    # here would make the agents page cost N requests against a manager
    # whose individual calls have been measured taking tens of seconds.
    assert len(api_stub.calls) == 1


def test_get_agent_returns_the_single_match(api_stub):
    api_stub.set("/agents?agents_list=001", _envelope([
        {"id": "001", "name": "web-01", "version": "Wazuh v4.14.6",
         "group_config_status": "synced"},
    ]))
    ok, agent = agents.get_agent("001")
    assert ok and agent["group_config_status"] == "synced"


def test_get_agent_reports_a_missing_id(api_stub):
    api_stub.set("/agents?agents_list=999", _envelope([]))
    ok, message = agents.get_agent("999")
    assert ok is False and "no agent with id" in message.lower()


def test_get_agent_key_reads_the_dict_entry(api_stub):
    """The API nests the key in an affected_items entry. The SSH tool it
    replaced returned a bare string, so this shape is worth pinning."""
    api_stub.set("/agents/001/key", _envelope([{"id": "001", "key": "AAAABBBBCCCC"}]))
    ok, key = agents.get_agent_key("001")
    assert ok and key == "AAAABBBBCCCC"


def test_get_agent_key_reports_an_empty_key(api_stub):
    api_stub.set("/agents/001/key", _envelope([{"id": "001", "key": ""}]))
    ok, message = agents.get_agent_key("001")
    assert ok is False and "no key" in message


def test_add_agent_returns_id_and_key(api_stub):
    api_stub.set("/agents", {"data": {"id": "003", "key": "NEWKEY"}, "error": 0})
    ok, created = agents.add_agent("probe", "any")
    assert ok
    assert created == {"id": "003", "name": "probe", "key": "NEWKEY"}


def test_add_agent_reports_an_unexpected_shape(api_stub):
    api_stub.set("/agents", {"data": {}, "error": 0})
    ok, message = agents.add_agent("probe", "any")
    assert ok is False and "not created as expected" in message


# ----------------------------------------------------------------------
# The delete confirmation guard. The API asks for no confirmation, so
# this is the only thing standing between "remove the agent I clicked"
# and "remove whatever now holds that id".
# ----------------------------------------------------------------------

def test_delete_refuses_when_the_name_does_not_match(api_stub):
    api_stub.set("/agents?agents_list=001", _envelope([{"id": "001", "name": "web-01"}]))
    ok, message = agents.delete_agent("001", "something-else")
    assert ok is False
    assert "refusing to delete" in message.lower()
    # Critically: no DELETE was attempted.
    assert all(method != "DELETE" for method, _, _ in api_stub.calls)


def test_delete_proceeds_when_the_name_matches(api_stub):
    api_stub.set("/agents?agents_list=001", _envelope([{"id": "001", "name": "web-01"}]))
    api_stub.set("/agents?agents_list=001&status=all", _envelope(["001"]))
    ok, message = agents.delete_agent("001", "web-01")
    assert ok and "removed" in message
    assert any(method == "DELETE" for method, _, _ in api_stub.calls)


def test_delete_aborts_if_the_agent_cannot_be_verified(api_stub):
    api_stub.fail("/agents?agents_list=001", "manager unreachable")
    ok, message = agents.delete_agent("001", "web-01")
    assert ok is False and "could not verify" in message.lower()


# ======================================================================
# GROUPS
# ======================================================================

def test_list_groups(api_stub):
    api_stub.set("/groups", _envelope([
        {"name": "default", "count": 2, "configSum": "abc"},
    ]))
    ok, groups = agents.list_groups()
    assert ok and groups[0]["name"] == "default" and groups[0]["count"] == 2


def test_create_group(api_stub):
    api_stub.set("/groups", {"message": "Group created.", "error": 0})
    ok, message = agents.create_group("ldap_servers")
    assert ok and "created" in message
    method, path, kwargs = api_stub.calls[0]
    assert method == "POST" and kwargs["json_body"] == {"group_id": "ldap_servers"}


def test_the_default_group_cannot_be_deleted(api_stub):
    """Removing it would un-configure every agent that has no other
    group, and the manager recreates it anyway."""
    ok, message = agents.delete_group("default")
    assert ok is False and "cannot be deleted" in message
    assert api_stub.calls == []


def test_delete_group(api_stub):
    api_stub.set("/groups?groups_list=ldap", _envelope(["ldap"]))
    ok, message = agents.delete_group("ldap")
    assert ok and "deleted" in message


def test_assign_and_unassign_use_the_right_verbs(api_stub):
    api_stub.set("/agents/001/group/ldap", _envelope(["001"]))
    ok, _ = agents.assign_agent("001", "ldap")
    assert ok and api_stub.calls[-1][0] == "PUT"

    ok, _ = agents.unassign_agent("001", "ldap")
    assert ok and api_stub.calls[-1][0] == "DELETE"


# ======================================================================
# agent.conf
# ======================================================================

def test_read_group_config_returns_raw_xml(api_stub):
    api_stub.set("/groups/default/files/agent.conf", "<agent_config>\n</agent_config>\n")
    ok, content = agents.read_group_config("default")
    assert ok and content.startswith("<agent_config>")


def test_write_group_config_sends_application_xml(api_stub):
    """Measured against the live API: this endpoint answers HTTP 415 to
    application/octet-stream and names application/xml, while the sibling
    decoder/rule upload endpoints want octet-stream. The inconsistency is
    the API's; pinning it here stops a well-meaning "unification"."""
    api_stub.set("/groups/ldap/configuration", {"message": "updated", "error": 0})
    ok, _ = agents.write_group_config("ldap", "<agent_config></agent_config>")
    assert ok
    _, _, kwargs = api_stub.calls[-1]
    assert kwargs["content_type"] == "application/xml"


def test_write_group_config_rejects_empty_content(api_stub):
    ok, message = agents.write_group_config("ldap", "   ")
    assert ok is False and "cannot be empty" in message
    assert api_stub.calls == []


# ======================================================================
# SERVICE INVENTORY
# ======================================================================

LINUX_ENTRY = {
    "service": {"name": "cron", "state": "active", "sub_state": "running",
                "enabled": "enabled", "description": "Regular background daemon"},
    "process": {"executable": "/usr/lib/systemd/system/cron.service"},
    "scan": {"time": "2026-08-17T07:42:56+00:00"},
}

WINDOWS_ENTRY = {
    "service": {"name": "Spooler", "state": "STOPPED", "sub_state": " ",
                "start_type": "DEMAND_START", "enabled": " ",
                "description": "Print spooler"},
    "process": {"executable": "C:\\WINDOWS\\System32\\spoolsv.exe"},
    "scan": {"time": "2026-08-17T07:56:15+00:00"},
}


def test_normalize_flattens_the_platform_difference():
    """Linux fills sub_state and leaves start_type blank; Windows does the
    reverse. The UI should not have to branch on platform."""
    linux = agents.normalize_service(LINUX_ENTRY)
    windows = agents.normalize_service(WINDOWS_ENTRY)

    assert linux["running"] is True and linux["detail"] == "running"
    assert windows["running"] is False and windows["detail"] == "DEMAND_START"
    assert linux["scanned_at"] and windows["scanned_at"]


@pytest.mark.parametrize("state,expected", [
    ("active", True), ("running", True), ("RUNNING", True),
    ("inactive", False), ("STOPPED", False), ("failed", False), ("dead", False),
    ("something-new", None), ("", None),
])
def test_running_is_tri_state(state, expected):
    """An unrecognised state must read as unknown, never as stopped -
    reporting a healthy service as down is the failure that would erode
    trust in the whole feature."""
    result = agents.normalize_service({"service": {"name": "x", "state": state}})
    assert result["running"] is expected


def test_scan_time_is_always_carried():
    """This is snapshot data - observed scan times on a real manager
    spanned weeks within one inventory - so the UI must be able to say
    when it was taken."""
    result = agents.normalize_service(LINUX_ENTRY)
    assert result["scanned_at"] == "2026-08-17T07:42:56+00:00"


def test_list_services_passes_the_search_to_the_manager(api_stub):
    """Server-side filtering is what makes "does this agent run X" one
    cheap call instead of fetching a whole inventory."""
    api_stub.set("/syscollector/001/services", _envelope([LINUX_ENTRY]))
    ok, services = agents.list_services("001", search="cron")
    assert ok and services[0]["name"] == "cron"
    assert "search=cron" in api_stub.paths()[-1]


def test_find_service_reports_an_exact_match(api_stub):
    api_stub.set("/syscollector/001/services", _envelope([LINUX_ENTRY]))
    ok, result = agents.find_service("001", "cron")
    assert ok
    assert result["exact"]["name"] == "cron"
    assert result["candidates"] == []


def test_find_service_never_passes_a_near_miss_off_as_the_answer(api_stub):
    """The API's search matches descriptions too: asking a Windows agent
    for "Spooler" also returns PrintScanBrokerService, whose description
    mentions a spooler. Returning that as the answer would tell an
    operator the service exists when it does not - and a check configured
    against a service the host never runs is how this feature would
    manufacture false alerts."""
    near_miss = {
        "service": {"name": "PrintScanBrokerService", "state": "STOPPED",
                    "description": "support for the low priv spooler"},
        "process": {}, "scan": {"time": "2026-08-17T00:00:00+00:00"},
    }
    api_stub.set("/syscollector/002/services", _envelope([near_miss]))
    ok, result = agents.find_service("002", "Spooler")
    assert ok
    assert result["exact"] is None
    assert [c["name"] for c in result["candidates"]] == ["PrintScanBrokerService"]


def test_find_service_matches_case_insensitively(api_stub):
    api_stub.set("/syscollector/001/services", _envelope([LINUX_ENTRY]))
    ok, result = agents.find_service("001", "CRON")
    assert ok and result["exact"] is not None


def test_service_lookup_surfaces_a_manager_failure(api_stub):
    api_stub.fail("/syscollector/001/services", "the manager did not answer within 60s")
    ok, message = agents.find_service("001", "cron")
    assert ok is False and "did not answer" in message
