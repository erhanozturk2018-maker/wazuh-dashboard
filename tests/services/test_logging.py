"""
================================================================================
Purpose
================================================================================
This module protects the `log_requests` middleware in `dashboard_core/app.py`
end to end: that state-changing requests (not reads) are logged, that the
result column correctly reflects success/failure, and that the username
resolution has the two-tier fallback this project deliberately chose -
`request.state.log_user` (set by a route that already knows the username
mid-request, e.g. `/login` before the session cookie exists yet) takes
priority over `get_current_user(request)` (the cookie-based fallback used
by every other authenticated route).

================================================================================
Responsibilities
================================================================================
- Verify GET requests are never logged (read-only, would be pure noise).
- Verify POST/PUT/DELETE/PATCH requests are logged regardless of outcome.
- Verify `result` is "success" for a 2xx/3xx response and "failed" for a
  4xx/5xx response.
- Verify `/login` resolves its username from `request.state.log_user`
  (the cookie does not exist yet at request time on the FIRST successful
  login - see docs/architecture - this is why the cookie-only fallback
  used previously silently produced "-" for every login row).
- Verify an already-authenticated POST (e.g. `/logout`) resolves its
  username from the session cookie via `get_current_user()`, with no
  route-level `request.state` assignment needed.
- Verify `target`/`detail` default to "-" when a route sets neither, and
  are populated correctly when a route does (mail update, agent add/delete,
  ISP file add/delete) - each read from `request.state`, never recomputed
  by the middleware itself.

This suite reuses the project's `authenticated_client`/`unauthenticated_client`
fixtures and mocks at the same sender-function boundary as every other route
test (`run_mail_command_via_ssh`, `agent_command`, `custom_file_save`) -
`no_real_ssh` (conftest.py, autouse) is the backstop if a mock is missed.
================================================================================
"""

import csv
from datetime import date
from unittest.mock import patch

import conftest
import pytest

from dashboard_core import config
from dashboard_core.services import logs as logs_module


@pytest.fixture(autouse=True)
def isolated_log_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "APP_LOG_DIR", tmp_path)
    return tmp_path


def _read_rows(tmp_path):
    log_file = tmp_path / f"{date.today():%Y-%m-%d}.csv"
    if not log_file.exists():
        return []
    with open(log_file, newline="") as f:
        return list(csv.DictReader(f))


def test_get_request_is_never_logged(unauthenticated_client, isolated_log_dir):
    unauthenticated_client.get("/login")
    assert _read_rows(isolated_log_dir) == []


def test_login_success_is_logged_with_username_from_request_state(unauthenticated_client, isolated_log_dir):
    with patch("dashboard_core.routes.auth.authenticate", return_value=True):
        unauthenticated_client.post("/login", data={"username": "erhan", "password": "whatever"})

    rows = _read_rows(isolated_log_dir)
    assert len(rows) == 1
    assert rows[0]["category"] == "login"
    assert rows[0]["user"] == "erhan"  # from request.state.log_user, NOT the cookie
    assert rows[0]["result"] == "success"


def test_login_failure_is_logged_as_failed(unauthenticated_client, isolated_log_dir):
    with patch("dashboard_core.auth.authenticate", return_value=False):
        unauthenticated_client.post("/login", data={"username": "erhan", "password": "wrong"})

    rows = _read_rows(isolated_log_dir)
    assert len(rows) == 1
    assert rows[0]["result"] == "failed"
    # authenticate() returned False before a username was ever attached -
    # this is the one case where "-" for user is the CORRECT outcome, not a bug
    assert rows[0]["user"] == "-"


def test_logout_resolves_username_from_session_cookie(authenticated_client, isolated_log_dir):
    # authenticated_client fixture logs in as "testuser" via a real session
    # cookie (conftest.py) - /logout sets no request.state, so this row
    # only exists if the get_current_user() fallback actually ran.
    authenticated_client.post("/logout")

    rows = _read_rows(isolated_log_dir)
    assert len(rows) == 1
    assert rows[0]["action"] == "POST /logout"
    assert rows[0]["user"] == "testuser"
    assert rows[0]["result"] == "success"


def test_mail_update_logs_target_and_detail_from_ssh_response(
    authenticated_client, isolated_log_dir, api_stub
):
    # A successful save redirects to the Email tab, which the client
    # follows and which then reads the alert rules from the manager.
    api_stub.set("/manager/configuration", conftest.OSSEC_CONF_SAMPLE)
    with patch(
        "dashboard_core.routes.alerting.run_mail_command_via_ssh",
        return_value=(True, "mail settings applied"),
    ):
        authenticated_client.post("/alerting/mail", data={
            "email_to": "ops@example.com", "email_from": "wazuh@example.com",
            "smtp_server": "smtp.example.com", "email_maxperhour": "10",
            "relayhost": "", "sasl_user": "", "sasl_pass": "", "sasl_pass_confirm": "",
        })

    rows = _read_rows(isolated_log_dir)
    assert len(rows) == 1
    assert rows[0]["detail"] == "mail settings applied"
    assert rows[0]["result"] == "success"


def test_mail_update_failure_logs_ssh_error_as_detail(
    authenticated_client, isolated_log_dir, api_stub
):
    # The failure path re-renders the Email tab in place, which also reads
    # the alert rules.
    api_stub.set("/manager/configuration", conftest.OSSEC_CONF_SAMPLE)
    with patch(
        "dashboard_core.routes.alerting.run_mail_command_via_ssh",
        return_value=(False, "SSH connection timed out"),
    ):
        authenticated_client.post("/alerting/mail", data={
            "email_to": "ops@example.com", "email_from": "wazuh@example.com",
            "smtp_server": "smtp.example.com", "email_maxperhour": "10",
            "relayhost": "", "sasl_user": "", "sasl_pass": "", "sasl_pass_confirm": "",
        })

    rows = _read_rows(isolated_log_dir)
    assert len(rows) == 1
    assert rows[0]["detail"] == "SSH connection timed out"
    assert rows[0]["result"] == "failed"


def test_agent_add_logs_agent_name_as_target(authenticated_client, isolated_log_dir, api_stub):
    api_stub.set("/agents", {"data": {"id": "007", "key": "abc"}, "error": 0})
    authenticated_client.post("/api/agents", data={"ip": "10.0.0.5", "name": "new-agent"})

    rows = _read_rows(isolated_log_dir)
    assert len(rows) == 1
    assert rows[0]["target"] == "new-agent"
    assert rows[0]["result"] == "success"
    # The registration key must never reach the audit log.
    assert "abc" not in rows[0]["detail"]


def test_pipeline_decoder_add_logs_kind_and_name_as_target(
    authenticated_client, isolated_log_dir, api_stub
):
    api_stub.set("/decoders/files/custom-teams.xml", {"error": 0, "data": {"failed_items": []}})
    # The redirect lands on the Parse tab, which lists both collections.
    api_stub.set("/decoders/files", {"error": 0, "data": {"affected_items": [], "failed_items": []}})
    api_stub.set("/rules/files", {"error": 0, "data": {"affected_items": [], "failed_items": []}})
    authenticated_client.post("/pipeline/files", data={
        "action": "add", "kind": "decoder", "name": "custom-teams.xml",
        "content": "<decoder name=\"x\"><prematch>x</prematch></decoder>",
    })

    rows = _read_rows(isolated_log_dir)
    assert len(rows) == 1
    assert rows[0]["target"] == "decoder:custom-teams.xml"


def test_route_that_sets_no_state_defaults_target_and_detail_to_dash(authenticated_client, isolated_log_dir):
    # /logout sets neither log_target nor log_detail - both columns must
    # fall back to "-", never to an empty string or a Python "None".
    authenticated_client.post("/logout")

    rows = _read_rows(isolated_log_dir)
    assert rows[0]["target"] == "-"
    assert rows[0]["detail"] == "-"