"""
The package check/install flow (Console -> Packages), the read-only
guarantee around settings.json's "plugins" key, the scoped postfix
re-check on a mail failure, and the rsyslog routes on the Pipeline page.

Mock boundary is the project's standard one for what is still SSH-backed -
the senders (`run_deps_command_via_ssh`, `run_rsyslog_command_via_ssh`,
`run_mail_command_via_ssh`), patched where they are USED (services.plugins /
services.rsyslog / routes.alerting respectively). Routes that also render a
manager-backed page use `api_with_config` for the Wazuh API side.

The core contract pinned here: ``checked_at`` changes ONLY when (1) the
operator confirms the check, or (2) a Postfix-dependent operation fails
and triggers the postfix-only re-check. Page loads never touch it.
"""

import json
from datetime import datetime
import conftest
from unittest.mock import patch

CHECK_BOTH_OK = (
    True,
    '{"error": 0, "data": {'
    '"rsyslog": {"installed": true, "version": "8.2312.0-3ubuntu9"}, '
    '"postfix": {"installed": true, "version": "3.8.6-1build2"}}}',
)


def _plugins_in(settings_path):
    return json.loads(settings_path.read_text())["plugins"]


# ============================================================
# Manage Plugins - the explicit confirm flow
# ============================================================

def test_plugins_confirm_writes_settings_shape(authenticated_client, monkeypatch, tmp_path):
    settings_path = tmp_path / "settings.json"
    monkeypatch.setattr("dashboard_core.config.SETTINGS_FILE", settings_path)

    with patch("dashboard_core.services.plugins.run_deps_command_via_ssh") as mock_deps:
        mock_deps.return_value = CHECK_BOTH_OK

        response = authenticated_client.post("/settings/plugins", data={
            "plugins": ["rsyslog", "postfix"],
        }, follow_redirects=False)

        assert response.status_code == 303
        # both already installed -> exactly one check, no install, no re-check
        assert mock_deps.call_args_list[0][0][0] == ["check", "rsyslog", "postfix"]
        assert len(mock_deps.call_args_list) == 1

    saved = _plugins_in(settings_path)
    assert saved["rsyslog"]["verified"] is True
    assert saved["rsyslog"]["version"] == "8.2312.0-3ubuntu9"
    assert saved["postfix"]["verified"] is True
    assert saved["postfix"]["version"] == "3.8.6-1build2"
    # checked_at is a parseable ISO 8601 timestamp
    for entry in saved.values():
        datetime.fromisoformat(entry["checked_at"])


def test_plugins_confirm_installs_missing_then_rechecks(authenticated_client, monkeypatch, tmp_path):
    settings_path = tmp_path / "settings.json"
    monkeypatch.setattr("dashboard_core.config.SETTINGS_FILE", settings_path)

    check_rsyslog_missing = (
        True,
        '{"error": 0, "data": {'
        '"rsyslog": {"installed": false, "version": null}, '
        '"postfix": {"installed": true, "version": "3.8.6-1build2"}}}',
    )
    install_ok = (
        True,
        '{"error": 0, "data": {"rsyslog": {"installed": true, "version": "8.2312.0-3ubuntu9"}}}',
    )

    with patch("dashboard_core.services.plugins.run_deps_command_via_ssh") as mock_deps:
        mock_deps.side_effect = [check_rsyslog_missing, install_ok, CHECK_BOTH_OK]

        response = authenticated_client.post("/settings/plugins", data={
            "plugins": ["rsyslog", "postfix"],
        }, follow_redirects=False)

        assert response.status_code == 303
        sent = [c[0][0] for c in mock_deps.call_args_list]
        # check -> install ONLY what was missing -> re-check
        assert sent == [
            ["check", "rsyslog", "postfix"],
            ["install", "rsyslog"],
            ["check", "rsyslog", "postfix"],
        ]

    saved = _plugins_in(settings_path)
    assert saved["rsyslog"] == {
        "verified": True,
        "version": "8.2312.0-3ubuntu9",
        "checked_at": saved["rsyslog"]["checked_at"],
    }


def test_plugins_rejects_unknown_plugin(authenticated_client, monkeypatch, tmp_path):
    settings_path = tmp_path / "settings.json"
    monkeypatch.setattr("dashboard_core.config.SETTINGS_FILE", settings_path)

    with patch("dashboard_core.services.plugins.run_deps_command_via_ssh") as mock_deps:
        response = authenticated_client.post("/settings/plugins", data={
            "plugins": ["netcat"],
        })

        assert response.status_code == 400
        mock_deps.assert_not_called()
    assert not settings_path.exists()


def test_plugins_failure_persists_nothing(authenticated_client, monkeypatch, tmp_path):
    settings_path = tmp_path / "settings.json"
    monkeypatch.setattr("dashboard_core.config.SETTINGS_FILE", settings_path)

    with patch("dashboard_core.services.plugins.run_deps_command_via_ssh") as mock_deps:
        mock_deps.return_value = (False, "SSH error: connection timed out")

        response = authenticated_client.post("/settings/plugins", data={
            "plugins": ["rsyslog"],
        })

        assert response.status_code == 400
    assert not settings_path.exists()


def test_plugins_preserves_other_settings_keys(authenticated_client, monkeypatch, tmp_path):
    settings_path = tmp_path / "settings.json"
    settings_path.write_text(json.dumps({
        "host": "10.0.0.5", "port": 5000,
        "mail": {"sasl_pass_set": True},
    }))
    monkeypatch.setattr("dashboard_core.config.SETTINGS_FILE", settings_path)

    with patch("dashboard_core.services.plugins.run_deps_command_via_ssh") as mock_deps:
        mock_deps.return_value = CHECK_BOTH_OK

        authenticated_client.post("/settings/plugins", data={
            "plugins": ["rsyslog", "postfix"],
        }, follow_redirects=False)

    saved = json.loads(settings_path.read_text())
    assert saved["host"] == "10.0.0.5"
    assert saved["mail"] == {"sasl_pass_set": True}
    assert "plugins" in saved


# ============================================================
# Read-only guarantee - page loads never touch checked_at
# ============================================================

def test_page_loads_never_recheck_or_touch_checked_at(
        authenticated_client, monkeypatch, tmp_path, api_with_config):
    api_with_config.set("/groups", {"error": 0, "data": {"affected_items": [], "failed_items": []}})
    api_with_config.set("/decoders/files", {"error": 0, "data": {"affected_items": [], "failed_items": []}})
    api_with_config.set("/rules/files", {"error": 0, "data": {"affected_items": [], "failed_items": []}})
    settings_path = tmp_path / "settings.json"
    original = {
        "plugins": {
            "rsyslog": {"verified": True, "version": "8.1", "checked_at": "2026-01-01T00:00:00+00:00"},
            "postfix": {"verified": True, "version": "3.8", "checked_at": "2026-01-01T00:00:00+00:00"},
        }
    }
    settings_path.write_text(json.dumps(original))
    monkeypatch.setattr("dashboard_core.config.SETTINGS_FILE", settings_path)

    with patch("dashboard_core.services.plugins.run_deps_command_via_ssh") as mock_deps:
        # load the settings page on several tabs - all reads, including the
        # Plugins tab that actually renders the stored status
        for tab in ("general", "plugins"):
            response = authenticated_client.get(f"/settings?tab={tab}")
            assert response.status_code == 200

        # Pipeline is a separate page from Console - it must be read-only too
        for tab in ("collect", "parse"):
            response = authenticated_client.get(f"/pipeline?tab={tab}")
            assert response.status_code == 200

        mock_deps.assert_not_called()

    # byte-for-byte unchanged: no checked_at drift, no rewrite
    assert json.loads(settings_path.read_text()) == original


# ============================================================
# Scoped postfix re-check on a mail (Postfix-dependent) failure
# ============================================================

def test_mail_failure_triggers_postfix_only_recheck(
        authenticated_client, monkeypatch, tmp_path, api_with_config):
    settings_path = tmp_path / "settings.json"
    stale = "2026-01-01T00:00:00+00:00"
    settings_path.write_text(json.dumps({
        "plugins": {
            "rsyslog": {"verified": True, "version": "8.1", "checked_at": stale},
            "postfix": {"verified": True, "version": "3.8", "checked_at": stale},
        }
    }))
    monkeypatch.setattr("dashboard_core.config.SETTINGS_FILE", settings_path)

    with patch("dashboard_core.routes.alerting.run_mail_command_via_ssh") as mock_mail, \
         patch("dashboard_core.services.plugins.run_deps_command_via_ssh") as mock_deps:
        mock_mail.return_value = (False, "postfix check failed (exit 1): fatal")
        mock_deps.return_value = (
            True,
            '{"error": 0, "data": {"postfix": {"installed": false, "version": null}}}',
        )

        response = authenticated_client.post("/alerting/mail", data={
            "email_to": "user@example.com",
            "email_from": "noreply@example.com",
            "smtp_server": "smtp.example.com",
        })

        assert response.status_code == 400
        # exactly ONE scoped re-check of postfix - not the whole list
        assert [c[0][0] for c in mock_deps.call_args_list] == [["check", "postfix"]]
        # the refreshed status is surfaced alongside the original error
        assert "postfix check failed" in response.text
        assert "NOT installed" in response.text

    saved = _plugins_in(settings_path)
    # only postfix's entry moved; rsyslog's checked_at is untouched
    assert saved["postfix"]["verified"] is False
    assert saved["postfix"]["checked_at"] != stale
    assert saved["rsyslog"] == {"verified": True, "version": "8.1", "checked_at": stale}


def test_mail_success_does_not_recheck(authenticated_client, monkeypatch, tmp_path):
    settings_path = tmp_path / "settings.json"
    monkeypatch.setattr("dashboard_core.config.SETTINGS_FILE", settings_path)

    with patch("dashboard_core.routes.alerting.run_mail_command_via_ssh") as mock_mail, \
         patch("dashboard_core.services.plugins.run_deps_command_via_ssh") as mock_deps:
        mock_mail.return_value = (True, "ok")

        response = authenticated_client.post("/alerting/mail", data={
            "email_to": "user@example.com",
            "email_from": "noreply@example.com",
            "smtp_server": "smtp.example.com",
        }, follow_redirects=False)

        assert response.status_code == 303
        mock_deps.assert_not_called()


# ============================================================
# localfile toggles (ossec.conf Logcollector entries)
# ============================================================

def _mutating_calls(mock_send):
    return [c[0][0] for c in mock_send.call_args_list if c[0][0][0] != "list"]


# ============================================================
# rsyslog rule files
# ============================================================

def test_rsyslog_add_forwards_to_sender(authenticated_client):
    with patch("dashboard_core.services.rsyslog.run_rsyslog_command_via_ssh") as mock_send:
        mock_send.return_value = (True, "ok")

        response = authenticated_client.post("/pipeline/rsyslog", data={
            "action": "add",
            "name": "wazuh-tcp.conf",
            "content": 'module(load="imtcp")',
        }, follow_redirects=False)

        assert response.status_code == 303
        sent = [c[0][0] for c in mock_send.call_args_list if c[0][0][0] != "list"]
        assert sent[0][0] == "add"
        assert json.loads(sent[0][1]) == {
            "name": "wazuh-tcp.conf", "content": 'module(load="imtcp")',
        }


def test_rsyslog_update_and_delete_forward_name(authenticated_client):
    with patch("dashboard_core.services.rsyslog.run_rsyslog_command_via_ssh") as mock_send:
        mock_send.return_value = (True, "ok")

        authenticated_client.post("/pipeline/rsyslog", data={
            "action": "update", "name": "wazuh-tcp.conf", "content": "input()",
        }, follow_redirects=False)
        authenticated_client.post("/pipeline/rsyslog", data={
            "action": "delete", "name": "wazuh-tcp.conf",
        }, follow_redirects=False)

        sent = [c[0][0] for c in mock_send.call_args_list if c[0][0][0] != "list"]
        assert sent[0][0] == "update"
        assert sent[0][1] == "wazuh-tcp.conf"
        assert json.loads(sent[0][2]) == {"content": "input()"}
        assert sent[1] == ["delete", "wazuh-tcp.conf"]


def test_rsyslog_rejects_non_project_name(authenticated_client, api_with_config):
    with patch("dashboard_core.services.rsyslog.run_rsyslog_command_via_ssh") as mock_send:
        mock_send.return_value = (True, "ok")

        response = authenticated_client.post("/pipeline/rsyslog", data={
            "action": "add",
            "name": "50-default.conf",
            "content": "x",
        })

        assert response.status_code == 400
        assert [c for c in mock_send.call_args_list if c[0][0][0] != "list"] == []
