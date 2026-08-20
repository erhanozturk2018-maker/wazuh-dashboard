"""
================================================================================
Purpose
================================================================================
The composed view: a browser request travelling all the way through a
route, its service layer, and out to the manager - with only the outermost
transport mocked. Where the per-module tests ask "does this function do its
job", this module asks "does the whole path still hold together", and in
particular whether the ordering guarantees survive.

Two transports now, and the split is the point:

    Wazuh API   everything Wazuh owns - ossec.conf blocks, decoders,
                agents, groups. Stubbed at `wazuh_api.request`.
    SSH         the host-OS remainder - Postfix, rsyslog, packages.
                Stubbed at the individual sender.

================================================================================
The ordering guarantee this module exists to protect
================================================================================
Manager reconfiguration is validate -> apply -> persist, and persistence
happens LAST and only on success. `data/settings.json` is meant to reflect
what is actually live on the manager, not what an operator attempted: if
the apply step fails, the local record must stay unchanged so the UI keeps
showing the last known-good state rather than a value that never took
effect (`docs/architecture/execution-flow.md`, Flow 3 - this guarantee
applies to the mail/SSH path specifically; the API-backed ossec.conf path
in Flow 2 keeps no local copy to persist at all).

Several tests here therefore assert on what is NOT written as much as on
what is. A test that only checks the happy path would let eager
persistence through unnoticed.

================================================================================
Secrets
================================================================================
Two values are write-only by design: the SASL relay password and an
agent's registration key. Both are accepted, used for exactly one call,
and returned or discarded - never persisted. The tests that cover them
scan every file under `data/` rather than checking one known location,
because the failure being guarded against is a value leaking somewhere
nobody thought to look.
"""

import json
from unittest.mock import patch

import pytest

import conftest


@pytest.fixture
def settings_file(tmp_path, monkeypatch):
    path = tmp_path / "settings.json"
    monkeypatch.setattr("dashboard_core.config.SETTINGS_FILE", path)
    monkeypatch.setattr("dashboard_core.config.DATA_DIR", tmp_path)
    return path


def written_config(stub):
    """The ossec.conf body this test caused to be written."""
    for method, path, kwargs in stub.calls:
        if method == "PUT" and "/manager/configuration" in path:
            return kwargs["raw_body"]
    raise AssertionError(f"no configuration write happened; calls: {stub.paths()}")


def no_config_written(stub):
    return all(
        not (method == "PUT" and "/manager/configuration" in path)
        for method, path, _ in stub.calls
    )


MAIL_FORM = {
    "email_to": "ops@example.com",
    "email_from": "wazuh@example.com",
    "smtp_server": "127.0.0.1",
    "email_maxperhour": "12",
    "relayhost": "[smtp.example.com]:587",
    "sasl_user": "relay-user",
}


# ======================================================================
# MAIL - validate, apply over SSH, persist last
# ======================================================================

def test_mail_success_persists_only_the_non_secret_fields(
    authenticated_client, settings_file, api_with_config
):
    with patch("dashboard_core.routes.alerting.run_mail_command_via_ssh",
               return_value=(True, "applied")):
        response = authenticated_client.post(
            "/alerting/mail", data={**MAIL_FORM, "sasl_pass": "hunter2",
                                    "sasl_pass_confirm": "hunter2"})

    assert response.status_code == 200
    saved = json.loads(settings_file.read_text())["mail"]
    assert saved["email_to"] == "ops@example.com"
    assert saved["sasl_user"] == "relay-user"
    # Only the fact that a password exists, never the password.
    assert saved["sasl_pass_set"] is True
    assert "sasl_pass" not in saved


def test_mail_failure_persists_nothing(
    authenticated_client, settings_file, api_with_config
):
    """The apply step failed, so the local record must still describe the
    last state that actually took effect - which here is no state at all."""
    with patch("dashboard_core.routes.alerting.run_mail_command_via_ssh",
               return_value=(False, "postfix check failed")):
        response = authenticated_client.post(
            "/alerting/mail", data={**MAIL_FORM, "sasl_pass": "", "sasl_pass_confirm": ""})

    assert response.status_code == 400
    assert not settings_file.exists()


def test_mail_blank_password_keeps_the_existing_flag(
    authenticated_client, settings_file, api_with_config
):
    settings_file.write_text(json.dumps({"mail": {"sasl_pass_set": True}}))
    with patch("dashboard_core.routes.alerting.run_mail_command_via_ssh",
               return_value=(True, "applied")):
        authenticated_client.post(
            "/alerting/mail", data={**MAIL_FORM, "sasl_pass": "", "sasl_pass_confirm": ""})

    assert json.loads(settings_file.read_text())["mail"]["sasl_pass_set"] is True


def test_mail_password_never_lands_anywhere_on_disk(
    authenticated_client, settings_file, tmp_path, api_with_config
):
    with patch("dashboard_core.routes.alerting.run_mail_command_via_ssh",
               return_value=(True, "applied")) as mock_mail:
        authenticated_client.post(
            "/alerting/mail", data={**MAIL_FORM, "sasl_pass": "SUPERSECRET",
                                    "sasl_pass_confirm": "SUPERSECRET"})

    # It reached the manager exactly once, as an argument...
    assert mock_mail.call_args.kwargs["sasl_pass"] == "SUPERSECRET"
    # ...and nowhere else.
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert "SUPERSECRET" not in path.read_text(encoding="utf-8", errors="ignore"), path


def test_mail_password_mismatch_is_rejected_before_the_manager_is_called(
    authenticated_client, settings_file, api_with_config
):
    with patch("dashboard_core.routes.alerting.run_mail_command_via_ssh") as mock_mail:
        response = authenticated_client.post(
            "/alerting/mail", data={**MAIL_FORM, "sasl_pass": "a", "sasl_pass_confirm": "b"})

    assert response.status_code == 400
    mock_mail.assert_not_called()
    assert not settings_file.exists()


# ======================================================================
# AGENTS - no persistence phase at all
# ======================================================================

def test_agent_key_is_returned_but_never_persisted(
    authenticated_client, settings_file, tmp_path, api_stub
):
    api_stub.set("/agents", {"data": {"id": "007", "key": "AGENTKEY"}, "error": 0})
    response = authenticated_client.post(
        "/api/agents", data={"ip": "10.0.0.5", "name": "new-agent"})

    assert response.status_code == 200
    assert response.json()["agent"]["key"] == "AGENTKEY"
    for path in tmp_path.rglob("*"):
        if path.is_file():
            assert "AGENTKEY" not in path.read_text(encoding="utf-8", errors="ignore"), path


def test_agent_add_rejects_an_invalid_ip_before_reaching_the_manager(
    authenticated_client, api_stub
):
    response = authenticated_client.post(
        "/api/agents", data={"ip": "999.999.999.999", "name": "new-agent"})
    assert response.status_code == 400
    assert api_stub.calls == []


def test_agent_delete_carries_the_confirmation_through_unchanged(
    authenticated_client, api_stub
):
    api_stub.set("/agents?agents_list=007", conftest.api_envelope(
        [{"id": "007", "name": "old-agent"}]))
    api_stub.set("/agents?agents_list=007&status=all", conftest.api_envelope(["007"]))

    response = authenticated_client.post(
        "/api/agents/007/delete", data={"confirm_name": "old-agent"})

    assert response.status_code == 200
    # Verified first, deleted second - never the other way round.
    methods = [m for m, _, _ in api_stub.calls]
    assert methods == ["GET", "DELETE"]


def test_agent_delete_without_a_confirmation_never_calls_the_manager(
    authenticated_client, api_stub
):
    response = authenticated_client.post("/api/agents/007/delete", data={"confirm_name": ""})
    assert response.status_code == 400
    assert api_stub.calls == []


def test_agent_add_surfaces_an_unreachable_manager_as_502(authenticated_client, api_stub):
    api_stub.fail("/agents", "could not reach https://manager:55000 within 60s")
    response = authenticated_client.post(
        "/api/agents", data={"ip": "10.0.0.5", "name": "new-agent"})
    assert response.status_code == 502
    assert "could not reach" in response.json()["error"]


# ======================================================================
# INTEGRATIONS - ossec.conf blocks, keyed by name
# ======================================================================

def test_integration_add_writes_the_block(authenticated_client, api_with_config):
    response = authenticated_client.post("/alerting/integrations", data={
        "action": "add", "name": "pagerduty", "alert_format": "json",
        "api_key": "abc123", "level": "12",
    }, follow_redirects=False)

    assert response.status_code == 303
    written = written_config(api_with_config)
    assert "<name>pagerduty</name>" in written
    assert "<api_key>abc123</api_key>" in written
    # The block that was already there survives.
    assert "custom-webhook" in written


def test_integration_add_without_required_fields_writes_nothing(
    authenticated_client, api_with_config
):
    response = authenticated_client.post("/alerting/integrations", data={
        "action": "add", "name": "", "alert_format": "",
    })
    assert response.status_code == 400
    assert no_config_written(api_with_config)


def test_integration_update_refuses_a_rename(authenticated_client, api_with_config):
    """Renaming would move the block's identity mid-edit; the supported
    path is remove and re-add."""
    response = authenticated_client.post("/alerting/integrations", data={
        "action": "update", "original_name": "custom-webhook", "name": "renamed",
        "alert_format": "json",
    })
    assert response.status_code == 400
    assert no_config_written(api_with_config)


def test_integration_update_changes_only_the_submitted_fields(
    authenticated_client, api_with_config
):
    response = authenticated_client.post("/alerting/integrations", data={
        "action": "update", "original_name": "custom-webhook",
        "alert_format": "json", "level": "7",
    }, follow_redirects=False)

    assert response.status_code == 303
    written = written_config(api_with_config)
    assert "<level>7</level>" in written
    assert "<name>custom-webhook</name>" in written


def test_integration_delete_removes_only_that_block(authenticated_client, api_with_config):
    response = authenticated_client.post("/alerting/integrations", data={
        "action": "delete", "original_name": "custom-webhook",
    }, follow_redirects=False)

    assert response.status_code == 303
    written = written_config(api_with_config)
    assert "custom-webhook" not in written
    # Unrelated neighbours are untouched.
    assert "<email_alerts>" in written
    assert "/var/log/auth.log" in written


# ======================================================================
# EMAIL ALERT RULES - addressed by position, guarded by confirmation
# ======================================================================

def test_email_rule_add_writes_the_block(authenticated_client, api_with_config):
    response = authenticated_client.post("/alerting/rules", data={
        "action": "add", "email_to": "oncall@example.com", "level": "12",
    }, follow_redirects=False)

    assert response.status_code == 303
    written = written_config(api_with_config)
    assert "oncall@example.com" in written
    assert "first@example.com" in written      # the existing rule survives


def test_email_rule_add_without_a_recipient_writes_nothing(
    authenticated_client, api_with_config
):
    response = authenticated_client.post("/alerting/rules", data={
        "action": "add", "email_to": "", "level": "12",
    })
    assert response.status_code == 400
    assert no_config_written(api_with_config)


def test_email_rule_update_with_a_matching_confirmation_succeeds(
    authenticated_client, api_with_config
):
    response = authenticated_client.post("/alerting/rules", data={
        "action": "update", "id": "0", "confirm_email_to": "first@example.com",
        "email_to": "first@example.com", "level": "5",
    }, follow_redirects=False)

    assert response.status_code == 303
    assert "<level>5</level>" in written_config(api_with_config)


def test_email_rule_update_without_an_id_writes_nothing(
    authenticated_client, api_with_config
):
    response = authenticated_client.post("/alerting/rules", data={
        "action": "update", "id": "", "email_to": "x@example.com",
    })
    assert response.status_code == 400
    assert no_config_written(api_with_config)


def test_email_rule_delete_with_a_matching_confirmation_succeeds(
    authenticated_client, api_with_config
):
    response = authenticated_client.post("/alerting/rules", data={
        "action": "delete", "id": "0", "confirm_email_to": "first@example.com",
    }, follow_redirects=False)

    assert response.status_code == 303
    written = written_config(api_with_config)
    assert "first@example.com" not in written
    assert "custom-webhook" in written          # neighbours survive


def test_email_rule_delete_without_an_id_writes_nothing(
    authenticated_client, api_with_config
):
    response = authenticated_client.post("/alerting/rules", data={
        "action": "delete", "id": "", "confirm_email_to": "first@example.com",
    })
    assert response.status_code == 400
    assert no_config_written(api_with_config)


def test_a_stale_confirmation_is_refused_and_writes_nothing(
    authenticated_client, api_with_config
):
    """The whole reason positions carry a confirmation: the operator's
    page may be describing a list that has since shifted, and applying
    the edit anyway would hit a different rule than the one they clicked."""
    response = authenticated_client.post("/alerting/rules", data={
        "action": "update", "id": "0", "confirm_email_to": "someone-else@example.com",
        "email_to": "someone-else@example.com", "level": "3",
    })

    assert response.status_code == 400
    assert no_config_written(api_with_config)
    assert "shifted" in response.text.lower()
