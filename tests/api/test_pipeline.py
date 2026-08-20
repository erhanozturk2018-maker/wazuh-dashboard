"""
================================================================================
Purpose
================================================================================
Protects the Pipeline page and its routes (`dashboard_core/routes/pipeline.py`) -
the screen that owns how logs reach the manager and how it makes sense of
them. Replaces tests/api/test_isp.py, which covered the same features
under the old "ISP" name and against the SSH argument vectors that no
longer exist.

Two sub-tabs, four manager-side resources:

    Collect   ossec.conf <localfile>, per-group agent.conf, rsyslog files
    Parse     /var/ossec/etc/decoders|rules/*.xml

================================================================================
Responsibilities
================================================================================
- Dashboard-side validation runs BEFORE anything reaches the manager:
  file names must be bare *.xml with no path components, content must be
  well-formed XML, and the kind must be one this page owns. Each of these
  is asserted together with "and no write was attempted", because a
  rejection that still sends the request is not a rejection.
- The correct Content-Type per endpoint. These are NOT uniform across the
  Wazuh API - the file-upload endpoints take application/octet-stream
  while the group-configuration endpoint answers 415 to that and demands
  application/xml. Both are pinned here so a well-meaning unification
  fails loudly.
- A log source may be a file to read OR a command to run. The previous
  implementation understood only the file shape, which left command
  entries unaddressable; both shapes are covered.
- Listing a file collection never fetches content - that would cost one
  manager call per file on every page render, against an API whose
  individual calls have been measured taking tens of seconds. Content is
  fetched only when a file is opened.

================================================================================
Out of scope
================================================================================
- The ossec.conf editing logic itself - tests/services/test_ossec_config.py.
- rsyslog's SSH transport - tests/services/test_ssh_service.py.
"""

import pytest

WELL_FORMED = '<decoder name="custom"><program_name>x</program_name></decoder>'
MALFORMED = '<decoder name="custom"><program_name>x</decoder>'


def writes(stub):
    """Every call that was not a read."""
    return [(m, p, kw) for m, p, kw in stub.calls if m != "GET"]


# ======================================================================
# PARSE - custom decoder/rule files
# ======================================================================

def test_add_decoder_uploads_and_redirects_to_the_parse_tab(authenticated_client, api_stub):
    api_stub.set("/decoders/files/custom_decoders.xml", {"error": 0, "data": {"failed_items": []}})

    response = authenticated_client.post("/pipeline/files", data={
        "action": "add", "kind": "decoder",
        "name": "custom_decoders.xml", "content": WELL_FORMED,
    }, follow_redirects=False)

    assert response.status_code == 303
    assert "tab=parse" in response.headers["location"]

    method, path, kwargs = writes(api_stub)[0]
    assert method == "PUT"
    assert "relative_dirname=etc/decoders" in path
    assert "overwrite=false" in path          # add is create-only
    assert kwargs["raw_body"] == WELL_FORMED
    assert kwargs["content_type"] == "application/octet-stream"


def test_update_rule_sets_overwrite(authenticated_client, api_stub):
    api_stub.set("/rules/files/local_rules.xml", {"error": 0, "data": {"failed_items": []}})

    response = authenticated_client.post("/pipeline/files", data={
        "action": "update", "kind": "rule",
        "name": "local_rules.xml", "content": '<group name="custom,"></group>',
    }, follow_redirects=False)

    assert response.status_code == 303
    _, path, _ = writes(api_stub)[0]
    assert "overwrite=true" in path
    assert "relative_dirname=etc/rules" in path


def test_delete_targets_the_named_file(authenticated_client, api_stub):
    api_stub.set("/decoders/files/old.xml", {"error": 0, "data": {"failed_items": []}})

    response = authenticated_client.post("/pipeline/files", data={
        "action": "delete", "kind": "decoder", "name": "old.xml",
    }, follow_redirects=False)

    assert response.status_code == 303
    method, path, _ = writes(api_stub)[0]
    assert method == "DELETE"
    assert "/decoders/files/old.xml" in path


def test_an_uploaded_file_wins_over_the_textarea(authenticated_client, api_stub):
    api_stub.set("/decoders/files/uploaded.xml", {"error": 0, "data": {"failed_items": []}})

    response = authenticated_client.post(
        "/pipeline/files",
        data={"action": "add", "kind": "decoder", "name": "uploaded.xml",
              "content": '<decoder name="typed"/>'},
        files={"xml_file": ("uploaded.xml", WELL_FORMED.encode(), "text/xml")},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert writes(api_stub)[0][2]["raw_body"] == WELL_FORMED


@pytest.mark.parametrize("payload,reason", [
    ({"action": "add", "kind": "decoder", "name": "broken.xml", "content": MALFORMED},
     "malformed XML"),
    ({"action": "add", "kind": "decoder", "name": "../../etc/passwd.xml", "content": WELL_FORMED},
     "path traversal in the name"),
    ({"action": "add", "kind": "decoder", "name": "noextension", "content": WELL_FORMED},
     "name without .xml"),
    ({"action": "add", "kind": "malware", "name": "x.xml", "content": WELL_FORMED},
     "unknown kind"),
    ({"action": "sideways", "kind": "decoder", "name": "x.xml", "content": WELL_FORMED},
     "unknown action"),
])
def test_invalid_submissions_never_reach_the_manager(authenticated_client, api_stub, payload, reason):
    api_stub.set("/decoders/files", {"error": 0, "data": {"affected_items": [], "failed_items": []}})
    api_stub.set("/rules/files", {"error": 0, "data": {"affected_items": [], "failed_items": []}})

    response = authenticated_client.post("/pipeline/files", data=payload)
    assert response.status_code == 400, reason
    assert writes(api_stub) == [], f"{reason}: a write was attempted anyway"


def test_a_manager_rejection_renders_an_error(authenticated_client, api_stub):
    api_stub.set("/decoders/files/x.xml", None)
    api_stub.fail("/decoders/files/x.xml", "a decoder named 'x.xml' already exists")
    api_stub.set("/decoders/files", {"error": 0, "data": {"affected_items": [], "failed_items": []}})
    api_stub.set("/rules/files", {"error": 0, "data": {"affected_items": [], "failed_items": []}})

    response = authenticated_client.post("/pipeline/files", data={
        "action": "add", "kind": "decoder", "name": "x.xml", "content": WELL_FORMED,
    })
    assert response.status_code == 400
    assert "already exists" in response.text


def test_the_file_listing_does_not_fetch_content(authenticated_client, api_stub):
    """One call per collection, never one per file."""
    api_stub.set("/decoders/files", {"error": 0, "data": {
        "affected_items": [{"filename": "a.xml", "relative_dirname": "etc/decoders"},
                           {"filename": "b.xml", "relative_dirname": "etc/decoders"}],
        "failed_items": []}})
    api_stub.set("/rules/files", {"error": 0, "data": {"affected_items": [], "failed_items": []}})

    response = authenticated_client.get("/pipeline?tab=parse")
    assert response.status_code == 200
    assert len(api_stub.calls) == 2
    assert all("raw=true" not in path for path in api_stub.paths())


def test_content_is_fetched_on_demand(authenticated_client, api_stub):
    api_stub.set("/decoders/files/local_decoder.xml", WELL_FORMED)
    response = authenticated_client.get("/api/pipeline/files/decoder/local_decoder.xml")
    assert response.status_code == 200
    assert response.json()["content"] == WELL_FORMED
    assert "raw=true" in api_stub.paths()[0]


def test_the_on_demand_endpoint_validates_its_inputs(authenticated_client, api_stub):
    assert authenticated_client.get("/api/pipeline/files/decoder/..%2Fpasswd.xml").status_code in (400, 404)
    assert authenticated_client.get("/api/pipeline/files/malware/x.xml").status_code == 400
    assert api_stub.calls == []


def test_the_on_demand_endpoint_requires_a_session(unauthenticated_client):
    response = unauthenticated_client.get("/api/pipeline/files/decoder/x.xml")
    assert response.status_code == 401


# ======================================================================
# COLLECT - log sources
# ======================================================================

def test_add_a_file_log_source(authenticated_client, api_with_config):
    response = authenticated_client.post("/pipeline/localfiles", data={
        "action": "add", "log_format": "syslog", "location": "/var/log/nginx.log",
    }, follow_redirects=False)

    assert response.status_code == 303
    assert "tab=collect" in response.headers["location"]
    written = next(kw["raw_body"] for m, p, kw in api_with_config.calls
                   if m == "PUT" and "/manager/configuration" in p)
    assert "/var/log/nginx.log" in written


def test_add_a_command_log_source(authenticated_client, api_with_config):
    """The shape the previous implementation could not express."""
    response = authenticated_client.post("/pipeline/localfiles", data={
        "action": "add", "log_format": "full_command",
        "command": "systemctl is-active sshd", "alias": "sshd_check", "frequency": "60",
    }, follow_redirects=False)

    assert response.status_code == 303
    written = next(kw["raw_body"] for m, p, kw in api_with_config.calls
                   if m == "PUT" and "/manager/configuration" in p)
    assert "systemctl is-active sshd" in written
    assert "sshd_check" in written


def test_a_command_log_source_without_an_alias_is_rejected(authenticated_client, api_with_config):
    """The alias is what makes the entry addressable afterwards, and what a
    decoder matches on. Without it the entry becomes unmanageable."""
    # Rejection re-renders the Collect tab, which also lists groups.
    api_with_config.set("/groups", {"error": 0, "data": {"affected_items": [], "failed_items": []}})

    response = authenticated_client.post("/pipeline/localfiles", data={
        "action": "add", "log_format": "full_command", "command": "uptime",
    })
    assert response.status_code == 400
    assert "alias is required" in response.text.lower()


def test_delete_a_command_log_source_by_its_alias(authenticated_client, api_with_config):
    """cron_check exists in the sample config as a full_command entry with
    no <location> - exactly the kind that used to be unreachable."""
    response = authenticated_client.post("/pipeline/localfiles", data={
        "action": "delete", "entry_id": "cron_check",
    }, follow_redirects=False)

    assert response.status_code == 303
    written = next(kw["raw_body"] for m, p, kw in api_with_config.calls
                   if m == "PUT" and "/manager/configuration" in p)
    assert "cron_check" not in written
    assert "/var/log/auth.log" in written      # the neighbour survives


def test_delete_without_an_id_is_rejected(authenticated_client, api_with_config):
    api_with_config.set("/groups", {"error": 0, "data": {"affected_items": [], "failed_items": []}})
    response = authenticated_client.post("/pipeline/localfiles", data={"action": "delete"})
    assert response.status_code == 400


# ======================================================================
# COLLECT - per-group agent.conf
# ======================================================================

def test_group_config_is_read_on_demand(authenticated_client, api_stub):
    api_stub.set("/groups/default/files/agent.conf", "<agent_config>\n</agent_config>\n")
    response = authenticated_client.get("/api/pipeline/groups/default/config")
    assert response.status_code == 200
    assert response.json()["content"].startswith("<agent_config>")


def test_group_config_write_uses_application_xml(authenticated_client, api_stub):
    """This endpoint rejects application/octet-stream with HTTP 415 while
    the file-upload endpoints above require it. Pinned deliberately."""
    api_stub.set("/groups/ldap/configuration", {"error": 0, "data": {"failed_items": []}})

    response = authenticated_client.post(
        "/pipeline/groups/ldap/config",
        data={"content": "<agent_config></agent_config>"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert writes(api_stub)[0][2]["content_type"] == "application/xml"


def test_malformed_group_config_is_rejected_before_writing(authenticated_client, api_stub):
    api_stub.set("/manager/configuration?raw=true", "<ossec_config>\n</ossec_config>\n")
    empty = {"error": 0, "data": {"affected_items": [], "failed_items": []}}
    api_stub.set("/groups", empty)
    api_stub.set("/agents", empty)

    response = authenticated_client.post(
        "/pipeline/groups/ldap/config",
        data={"content": "<agent_config><localfile></agent_config>"},
    )
    assert response.status_code == 400
    assert writes(api_stub) == []


# ======================================================================
# The old address must keep working
# ======================================================================

def test_the_old_isp_url_redirects(authenticated_client):
    response = authenticated_client.get("/isp", follow_redirects=False)
    assert response.status_code == 301
    assert response.headers["location"] == "/pipeline"


# ======================================================================
# THE MANAGER'S MISLEADING UPLOAD REJECTION
# ======================================================================
# The file endpoints answer EVERY rejection with "XML syntax error",
# including for a document that is provably well-formed - the route has
# already parsed it by then. Measured against 4.14.6: ^(Spooler|Fax)$ in
# a <field> is refused (OSRegex has no grouping) while the identical file
# with ^Spooler$|^Fax$ is accepted, and both are valid XML. Passing that
# message straight through sends the operator to look at the one thing
# that is definitely not wrong.

def test_a_bogus_xml_syntax_rejection_is_explained_not_parroted(
        authenticated_client, api_stub):
    api_stub.set("/rules/files/local_rules.xml", None)
    api_stub.fail("/rules/files/local_rules.xml",
                  "XML syntax error - Please, ensure file content has correct XML")
    api_stub.set("/decoders/files", {"error": 0, "data": {"affected_items": [], "failed_items": []}})
    api_stub.set("/rules/files", {"error": 0, "data": {"affected_items": [], "failed_items": []}})

    response = authenticated_client.post("/pipeline/files", data={
        "action": "update", "kind": "rule", "name": "local_rules.xml",
        "content": WELL_FORMED,
    })
    assert response.status_code == 400
    # Names the actual likely cause and a concrete way out...
    assert "OSRegex" in response.text
    assert "pcre2" in response.text
    # ...and still shows what the manager said, so nothing is hidden.
    assert "XML syntax error" in response.text


def test_other_manager_rejections_are_left_alone(authenticated_client, api_stub):
    """The hint is only true because the XML was already validated here.
    A different refusal says what it means and must not be dressed up."""
    api_stub.set("/rules/files/local_rules.xml", None)
    api_stub.fail("/rules/files/local_rules.xml", "Permission denied")
    api_stub.set("/decoders/files", {"error": 0, "data": {"affected_items": [], "failed_items": []}})
    api_stub.set("/rules/files", {"error": 0, "data": {"affected_items": [], "failed_items": []}})

    response = authenticated_client.post("/pipeline/files", data={
        "action": "update", "kind": "rule", "name": "local_rules.xml",
        "content": WELL_FORMED,
    })
    assert response.status_code == 400
    assert "Permission denied" in response.text
    assert "OSRegex" not in response.text
