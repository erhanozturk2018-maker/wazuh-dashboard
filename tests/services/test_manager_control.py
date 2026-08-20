"""
The restart guarantee: a written change actually takes effect.

This file exists because of a real, shipped regression. Under the SSH-only
design the forced-command wrapper restarted services on the way out of any
mutating call, so no caller had to remember. When ossec.conf, decoders and
rules moved to the Wazuh API they stopped passing through that wrapper and
the guarantee went with them: saves reported success, the file on disk was
correct, and nothing changed. It was found by an operator raising an alert
level from 3 to 7 and still receiving level-3 alerts.

Nothing in the suite caught it, because every test asserted on the write
and none on what happened after. That is what these cover.

The restart itself is the autouse `restarts` recorder from conftest.
"""

from dashboard_core.services import custom_files, manager_control, ossec_config


# ======================================================================
# THE GUARANTEE - a write restarts the manager
# ======================================================================

def test_an_ossec_conf_write_restarts_the_manager(api_with_config, restarts):
    ok, _ = ossec_config.add_block("integration", {
        "name": "slack", "alert_format": "json",
        "hook_url": "https://hooks.slack.com/x",
    })
    assert ok
    assert restarts.count == 1, "the change is on disk but never went live"


def test_deleting_an_ossec_conf_block_also_restarts(api_with_config, restarts):
    ok, _ = ossec_config.delete_block("integration", "custom-webhook")
    assert ok
    assert restarts.count == 1


def test_a_decoder_write_restarts_the_manager(api_stub, restarts):
    api_stub.set("/decoders/files/local_decoder.xml", {
        "data": {"affected_items": ["local_decoder.xml"], "failed_items": []},
        "error": 0,
    })
    ok, _ = custom_files.save_file(
        "decoder", "local_decoder.xml", "<decoder name='x'></decoder>",
        overwrite=True,
    )
    assert ok
    assert restarts.count == 1


def test_a_failed_write_does_not_restart(api_with_config, restarts):
    """Nothing changed, so there is nothing to make live - and this
    manager is slow enough that a pointless restart is a real cost."""
    api_with_config.fail("/manager/configuration", "manager is unreachable")
    ok, _ = ossec_config.add_block("integration", {
        "name": "slack", "alert_format": "json",
        "hook_url": "https://hooks.slack.com/x",
    })
    assert ok is False
    assert restarts.count == 0


# ======================================================================
# WHEN THE RESTART FAILS
# ======================================================================

def test_a_failed_restart_keeps_the_write_successful(api_with_config, restarts):
    """The change IS on disk. Reporting it as a failure would invite the
    operator to apply something already applied."""
    restarts.fail("connection timed out")

    ok, message = ossec_config.add_block("integration", {
        "name": "slack", "alert_format": "json",
        "hook_url": "https://hooks.slack.com/x",
    })
    assert ok is True
    assert manager_control.RESTART_FAILED_HINT in message
    # The underlying reason travels with it - "could not restart" alone
    # gives the operator nothing to act on.
    assert "connection timed out" in message


def test_a_successful_restart_adds_no_noise(api_with_config):
    ok, message = ossec_config.add_block("integration", {
        "name": "slack", "alert_format": "json",
        "hook_url": "https://hooks.slack.com/x",
    })
    assert ok is True
    assert manager_control.RESTART_FAILED_HINT not in message


def test_needs_restart_retry_recognises_its_own_hint():
    assert manager_control.needs_restart_retry(
        f"Added. {manager_control.RESTART_FAILED_HINT} (timed out)")
    assert not manager_control.needs_restart_retry("Added.")
    assert not manager_control.needs_restart_retry("")
    assert not manager_control.needs_restart_retry(None)


# ======================================================================
# THE MANUAL RETRY ENDPOINT
# ======================================================================

def test_apply_changes_endpoint_restarts(authenticated_client, restarts):
    response = authenticated_client.post("/api/manager/restart")
    assert response.status_code == 200
    assert restarts.count == 1


def test_apply_changes_endpoint_reports_a_failure(authenticated_client, restarts):
    restarts.fail("manager did not come back")
    response = authenticated_client.post("/api/manager/restart")
    assert response.status_code == 502
    assert "manager did not come back" in response.json()["error"]


def test_apply_changes_endpoint_needs_a_session(unauthenticated_client, restarts):
    """An unauthenticated caller could otherwise bounce the manager at
    will - the cheapest denial of service in the application."""
    response = unauthenticated_client.post("/api/manager/restart")
    assert response.status_code == 401
    assert restarts.count == 0


# ======================================================================
# CARRYING A FAILED RESTART ACROSS THE REDIRECT
# ======================================================================
# The save succeeds, so the route redirects - and a redirect drops the
# message. Without the flag the operator is told "Changes saved." and
# never learns the change is not live, which is the original bug wearing
# a different hat.

def test_a_failed_restart_flags_the_redirect(authenticated_client, api_with_config, restarts):
    restarts.fail()
    response = authenticated_client.post(
        "/alerting/integrations",
        data={"action": "add", "name": "slack", "alert_format": "json",
              "hook_url": "https://hooks.slack.com/x"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "restart_failed=1" in response.headers["location"]


def test_a_successful_restart_leaves_the_redirect_clean(
        authenticated_client, api_with_config):
    response = authenticated_client.post(
        "/alerting/integrations",
        data={"action": "add", "name": "slack", "alert_format": "json",
              "hook_url": "https://hooks.slack.com/x"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "restart_failed" not in response.headers["location"]


def test_the_flag_renders_a_retry_control(authenticated_client, api_with_config):
    """The banner is the only route back from a half-applied change - if
    it renders without the button the operator has to SSH in."""
    page = authenticated_client.get("/alerting?saved=1&tab=integrations&restart_failed=1")
    assert page.status_code == 200
    # The banner element, not the string - `data-apply-changes` also
    # appears in the overlay partial's script, which is on every render.
    assert "msg-warn msg-action" in page.text
    assert "<button type=\"button\" class=\"btn btn-sm\" data-apply-changes>" in page.text
    assert manager_control.RESTART_FAILED_HINT in page.text
    # Not also claiming success: the two states are mutually exclusive.
    assert "Changes saved." not in page.text


def test_without_the_flag_a_save_still_says_saved(authenticated_client, api_with_config):
    page = authenticated_client.get("/alerting?saved=1&tab=integrations")
    assert "Changes saved." in page.text
    assert "msg-warn msg-action" not in page.text
    assert manager_control.RESTART_FAILED_HINT not in page.text
