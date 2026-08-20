import json

import paramiko
import pytest
import requests
from fastapi.testclient import TestClient

from dashboard_core.app import app
from dashboard_core.auth import make_session_token
from dashboard_core.config import SESSION_COOKIE
from dashboard_core.services import wazuh_api


@pytest.fixture(autouse=True)
def no_real_manager(monkeypatch):
    """Stop the suite from reaching a real Wazuh manager on either channel.

    The dashboard now talks to the manager two ways, and both need
    blocking or the suite's runtime becomes hostage to whatever host is
    in `.env` - the operator's actual manager:

      HTTP  the Wazuh API (services/wazuh_api.py), used for everything
            Wazuh owns. This is the one that matters most now: page
            renders call it, so an unguarded test would hammer a live
            manager just by following a redirect.
      SSH   the three remaining host-OS features (mail/rsyslog/deps).

    Both are blocked at the transport, not at each caller: one seam
    covers every current caller and any future one, and it cannot be
    forgotten when a new one is added.

    This is a backstop, not a substitute for mocking. Tests that need a
    call to *return* something mock it themselves - see the `api_stub`
    fixture for the HTTP side.
    """
    def _blocked_ssh(*args, **kwargs):
        raise RuntimeError(
            "A test attempted a real SSH connection. Mock the sender for "
            "this test - e.g. patch('dashboard_core.services.rsyslog."
            "run_rsyslog_command_via_ssh'). See tests/conftest.py."
        )

    def _blocked_http(*args, **kwargs):
        raise RuntimeError(
            "A test attempted a real Wazuh API call. Use the `api_stub` "
            "fixture, or patch 'dashboard_core.services.wazuh_api.request' "
            "for this test. See tests/conftest.py."
        )

    monkeypatch.setattr(paramiko.SSHClient, "connect", _blocked_ssh)
    monkeypatch.setattr(requests.Session, "request", _blocked_http)
    monkeypatch.setattr(requests.Session, "post", _blocked_http)
    # A session cached from an earlier test must not leak into this one.
    wazuh_api.reset_session()


@pytest.fixture(autouse=True)
def restarts(monkeypatch):
    """Records manager restarts instead of performing them.

    Every configuration write now restarts the manager on its way out
    (`services/manager_control.py`), so without this the SSH backstop
    above turns every one of those tests into a *failed*-restart test -
    still passing, because none of them assert on the whole message, but
    passing for the wrong reason and asserting nothing about the restart.

    Patched at `manager_control`'s own import of the sender rather than
    at `apply_changes`, so the success/failure shaping above it stays
    under test. Default is a restart that works; `fail()` flips it.

        def test_x(restarts):
            restarts.fail("manager did not come back")
            ...
            assert restarts.count == 1
    """
    class Restarts:
        def __init__(self):
            self.count = 0
            self.reply = (True, "Wazuh manager restarted.")

        def fail(self, message="manager did not come back"):
            self.reply = (False, message)
            return self

        def __call__(self):
            self.count += 1
            return self.reply

    recorder = Restarts()
    monkeypatch.setattr(
        "dashboard_core.services.manager_control.run_restart_command_via_ssh",
        recorder,
    )
    return recorder


@pytest.fixture
def api_stub(monkeypatch):
    """Canned replies for `wazuh_api.request`, keyed by path fragment.

    `wazuh_api.request` is THE seam for everything that used to go through
    the five SSH senders - one function instead of five, because the API
    client centralises transport, retries and error shaping. Patch it and
    the whole manager side of the app is under test control.

    Usage:

        def test_x(authenticated_client, api_stub):
            api_stub.set("/manager/configuration?raw=true", OSSEC_CONF)
            api_stub.fail("/agents", "manager is unreachable")

    Anything not registered raises, so a test cannot silently pass on a
    call it never intended to make. `calls` records (method, path) in
    order for assertions about what was actually sent.
    """
    class Stub:
        def __init__(self):
            self.replies = {}
            self.calls = []

        def set(self, fragment, payload):
            """Reply successfully to any path containing `fragment`."""
            self.replies[fragment] = (True, payload)
            return self

        def fail(self, fragment, message):
            self.replies[fragment] = (False, message)
            return self

        def set_json(self, fragment, affected_items, error=0):
            """Shorthand for the API's usual envelope."""
            return self.set(fragment, {
                "data": {
                    "affected_items": affected_items,
                    "total_affected_items": len(affected_items),
                    "failed_items": [],
                },
                "error": error,
            })

        def __call__(self, method, path, **kwargs):
            self.calls.append((method, path, kwargs))
            # Longest match wins, not insertion order: a test registering
            # "/groups/ldap/configuration" must beat a general "/groups"
            # from a fixture regardless of which was set first.
            matches = [(f, r) for f, r in self.replies.items() if f in path]
            if matches:
                return max(matches, key=lambda pair: len(pair[0]))[1]
            raise AssertionError(
                f"Unstubbed Wazuh API call: {method} {path}. "
                f"Register it with api_stub.set(...) if the test expects it."
            )

        def paths(self):
            return [path for _, path, _ in self.calls]

        def bodies(self):
            """Raw bodies actually sent, in order - for asserting on what
            was written rather than only that something was."""
            return [kw.get("raw_body") or kw.get("json_body") for _, _, kw in self.calls]

    stub = Stub()
    monkeypatch.setattr(wazuh_api, "request", stub)
    return stub


@pytest.fixture
def authenticated_client():
    test_client = TestClient(app)
    token = make_session_token("testuser")
    test_client.cookies.set(SESSION_COOKIE, token)
    return test_client


@pytest.fixture
def unauthenticated_client():
    return TestClient(app)


# A minimal but structurally real ossec.conf: two <ossec_config> roots, a
# <global> block, and one of each editable block type. Tests that exercise
# the block CRUD need the multi-root shape because that is exactly what
# the lxml wrapper exists to handle.
OSSEC_CONF_SAMPLE = """<ossec_config>
  <global>
    <email_notification>yes</email_notification>
    <email_to>soc@example.com</email_to>
  </global>

  <alerts>
    <email_alert_level>10</email_alert_level>
  </alerts>

  <email_alerts>
    <email_to>first@example.com</email_to>
    <level>12</level>
  </email_alerts>

  <integration>
    <name>custom-webhook</name>
    <hook_url>http://127.0.0.1:5000/wazuh-webhook</hook_url>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>

<ossec_config>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>full_command</log_format>
    <command>systemctl is-active cron</command>
    <alias>cron_check</alias>
    <frequency>60</frequency>
  </localfile>
</ossec_config>
"""


@pytest.fixture
def ossec_conf():
    return OSSEC_CONF_SAMPLE


@pytest.fixture
def api_with_config(api_stub):
    """An api_stub already serving the sample ossec.conf for reads and
    accepting writes - the common setup for block CRUD tests."""
    api_stub.set("/manager/configuration?raw=true", OSSEC_CONF_SAMPLE)
    api_stub.set("/manager/configuration/validation", {
        "data": {"affected_items": [{"name": "manager", "status": "OK"}],
                 "failed_items": []},
        "error": 0,
    })
    api_stub.set("/manager/configuration", {
        "data": {"affected_items": ["manager"], "failed_items": []},
        "error": 0,
    })
    # The manager-backed pages also list these while rendering. Empty
    # replies keep a test focused on ossec.conf from having to restate
    # them; a test that cares registers its own and wins on length.
    empty = {"data": {"affected_items": [], "failed_items": []}, "error": 0}
    for path in ("/groups", "/decoders/files", "/rules/files", "/agents"):
        api_stub.set(path, empty)
    return api_stub


def api_envelope(affected_items, error=0, message="ok"):
    """Build the API's standard reply shape for ad-hoc stubbing."""
    return {
        "data": {
            "affected_items": affected_items,
            "total_affected_items": len(affected_items),
            "total_failed_items": 0,
            "failed_items": [],
        },
        "message": message,
        "error": error,
    }


def json_body_of(call):
    """The JSON body of a recorded api_stub call, whatever form it took."""
    _, _, kwargs = call
    body = kwargs.get("json_body")
    if body is not None:
        return body
    raw = kwargs.get("raw_body")
    return json.loads(raw) if raw else None
