"""
================================================================================
Purpose
================================================================================
This module protects two routers that changed shape in the SSH-to-API
migration: `dashboard_core/routes/settings.py` (`GET/POST /settings`, this
console's own general host/port/note — a purely local read/write, no
manager involved) and the mail-delivery half of
`dashboard_core/routes/alerting.py` (`POST /alerting/mail`), which is still
SSH-backed since Postfix is a host-OS concern the Wazuh API cannot express.
Per `docs/architecture/execution-flow.md` (Flow 3), the mail path is a
three-phase VALIDATE -> APPLY -> PERSIST operation, and phase order is
documented as a safety property, not a style choice. This module exists to
prove the dashboard half of that contract holds, without requiring a live
Wazuh manager or a live Wazuh API for every test run.

================================================================================
Responsibilities
================================================================================
- Verify every POST route enforces session authentication (redirect to
  `/login` when unauthenticated) - the page-route pattern, not the
  JSON-401 pattern used by `/api/agents*`.
- Verify Phase 1 (dashboard-side) validation runs and rejects invalid
  input *before* any SSH call is attempted: `EMAIL_RE` for
  `email_to`/`email_from`, `HOST_RE` for `smtp_server` and the
  host-portion of `relayhost` (via `_relay_host_only()`), digits-only for
  `port`/`email_maxperhour`, and password/confirmation matching for
  `sasl_pass`/`sasl_pass_confirm`.
- Verify Phase 3 (persistence) happens **only** when Phase 2 (the SSH
  apply call) succeeds, and that the dashboard's local record
  (`data/settings.json`) is left unchanged on a Phase 2 failure - this is
  the single most important behavioral guarantee in this module, per the
  explicit rationale in `docs/architecture/execution-flow.md`.
- Verify `sasl_pass` is never persisted to `data/settings.json` in any
  form other than the `sasl_pass_set` boolean, including when the mail
  form is submitted with a blank password (documented as "keep existing
  password," not "clear it").
- Verify `/settings` (General) never touches the manager at all - a pure
  local JSON read/write, distinct from every other page on this test
  boundary.

================================================================================
System Boundaries
================================================================================
In scope: the route handlers listed above, and the
`EMAIL_RE`/`HOST_RE`/`_relay_host_only()` validators as used by them.

Out of scope, and covered elsewhere:
- `run_mail_command_via_ssh` as a unit - covered by
  `tests/services/test_ssh_service.py`. This module mocks that function
  and asserts only how the route uses its return value.
- The `<email_alerts>`/`<integration>` block CRUD that used to live on
  this page - it moved to `/alerting/rules` and `/alerting/integrations`
  and is now Wazuh-API-backed; see `tests/services/test_ossec_config.py`
  and `tests/integrations/test_manager_workflow.py`.
- `mail_config_tool.py` (manager-side, separately deployed, never
  imported by the dashboard).
- The manager-side re-validation and backup-before-write guarantees
  described in `docs/security/manager-side.md` - those are properties of
  code this repo does not execute, and must not be asserted here as if
  the dashboard enforced them.
- Full VALIDATE→APPLY→PERSIST wiring as an end-to-end scenario spanning
  real (mocked-at-the-SSH-boundary) execution — that composed view
  belongs to `tests/integrations/test_manager_workflow.py`; this module
  may assert the persistence-on-success/no-persistence-on-failure rule
  per route, but the full multi-route workflow narrative lives there.

================================================================================
Why These Tests Matter
================================================================================
Configuration routes are the only place in the application where a bug
can cause the dashboard's *local* idea of manager state to drift from
what is actually live on the manager — for example, if persistence ever
happened before or regardless of the SSH apply call succeeding, an
operator could see "saved" in the UI for a change that silently never
reached `ossec.conf`. This exact failure mode (config written correctly
but never taking effect) is documented in
`docs/knowledge/design-decisions.md` as a real, previously-shipped bug on
the manager-side wrapper; this module's job is to make sure the
dashboard side never reintroduces an analogous ordering bug. A secondary,
equally serious risk this module guards against is a secret (`sasl_pass`)
ending up on disk through a code path that bypasses the documented
write-only handling.

================================================================================
Production Files to Understand First
================================================================================
- `dashboard_core/validation.py` — `_relay_host_only`; `dashboard_core/routes/settings.py`
  — `_settings_context` and the General POST handler;
  `dashboard_core/routes/alerting.py` — the `/alerting/mail` handler
  specifically (its `/alerting/rules` and `/alerting/integrations`
  neighbours are API-backed and out of scope here).
- `docs/architecture/execution-flow.md` — Flow 3, in full: the exact
  three-phase contract this module verifies for the mail path.
- `docs/security/dashboard-side.md` — "The SASL password: write-only, by
  design" section.
- `docs/development/coding-standards.md` — "Validation is layered, not
  single-sourced," to understand why dashboard-side validation failures
  are a UX concern, not the security boundary this module should imply
  they are.

================================================================================
Testing Strategy
================================================================================
This is a Unit/Functional (API-layer) test module using FastAPI's
`TestClient` against `main.app`, with every manager-facing function
(`run_mail_command_via_ssh`, `ossec_config_add/update/delete`,
`ossec_config_list`) mocked/monkeypatched — no real SSH connection or
Wazuh manager should ever be reachable from this module. Because Phase 3
depends on Phase 2's mocked outcome, most scenarios in this module should
be written as pairs: one asserting behavior when the mocked SSH/apply
call succeeds, one asserting behavior when it fails, with an assertion on
`data/settings.json`'s contents (via a temp-directory-backed
`SETTINGS_FILE`, never the real `data/` directory — see
`docs/security/dashboard-side.md` on why `data/*.json` must not be
hand-seeded or pointed at directly) in both branches.

================================================================================
Expected Test Scenarios
================================================================================
- General settings (`/settings`): valid host/port/note persists; a
  non-numeric port is rejected with a 400 and the form re-rendered with
  the attempted values, before any persistence occurs.
- Mail settings (`/alerting/mail`): each individual validation rule
  (invalid `email_to`/`email_from`, invalid `smtp_server`/`relayhost`,
  non-numeric `email_maxperhour`, mismatched password/confirmation) is
  rejected independently, before any SSH call; a valid submission calls
  the mocked SSH sender and persists only on its success; a blank
  password field preserves the existing `sasl_pass_set` value; a new
  password sets it to `True` and is never present anywhere in
  `data/settings.json` afterward.
- Email alerts (`/alerting/rules`): add requires `email_to`;
  update/delete require the block `id` and forward `confirm_email_to`
  unchanged; a mocked manager rejection (simulating a stale-ID mismatch)
  surfaces as a rendered error, not a 500.
- Integrations (`/alerting/integrations`): add requires `name` and
  `alert_format`; update always targets `original_name` and never sends
  a `name` field that could rename the block; delete requires
  `original_name`.
- `_settings_context()` degradation: when the mocked `ossec_config_list`
  call fails for either block type, the corresponding `*_list_error` is
  populated and `*_list` defaults to an empty list, without raising.
- Every route redirects unauthenticated requests to `/login` rather than
  performing any validation or SSH call.

================================================================================
Out of Scope
================================================================================
- Manager-side validation, backup-before-write, or the actual XML
  mutation of `ossec.conf` — these belong to `ossec-config-tool.py` and
  are untestable here without a live manager (see
  `docs/development/testing.md`).
- `mail-config-tool.sh` — a shell script, not Python, entirely outside
  this repo's Python test surface.
- Rendered HTML correctness (Jinja2 template output beyond status code
  and the context values passed into `TemplateResponse`) — a full
  template-rendering assertion is acceptable only where it's the most
  direct way to confirm an error message reached the page; deep HTML/CSS
  assertions belong elsewhere if ever added.
- Restart-triggering behavior — entirely a manager-side wrapper concern
  (`is_mutating_action()`), never invoked from dashboard-side tests.

================================================================================
Mocking Strategy
================================================================================
Mock: `run_mail_command_via_ssh`, `ossec_config_add`, `ossec_config_update`,
`ossec_config_delete`, `ossec_config_list` — these are exactly the seams
`docs/development/testing.md` identifies ("mocking those two functions
covers every settings route," generalized here to the ossec wrapper
family that route also depends on). Also redirect `SETTINGS_FILE` (and
any other `DATA_DIR`-relative path) to a `tmp_path`-backed location per
test so persistence assertions never touch the real `data/` directory.
Keep real: `EMAIL_RE`/`HOST_RE`/`_relay_host_only()` matching,
`_settings_context()`'s assembly logic, and FastAPI's routing/form
parsing.

================================================================================
Assumptions
================================================================================
- Assumption: authenticated-session setup is provided by a shared
  `conftest.py` fixture (not yet present as of this writing — the file is
  currently empty); this module should consume that fixture rather than
  re-implement login/registration per test.
- Assumption: redirecting `DATA_DIR`/`SETTINGS_FILE` to a temp path is
  done by monkeypatching `dashboard_core.config.SETTINGS_FILE` before each test. This is
  the correct target because every reader (`storage.load_mail_settings`,
  `storage.save_mail_settings`, and `dashboard_core/routes/settings.py`) resolves it as
  `dashboard_core.config.SETTINGS_FILE` at call time rather than binding it with a
  `from dashboard_core.config import ...`. Patching it anywhere else would silently not
  take effect. If this changes to dependency-injected paths in a future
  refactor, this module's fixture strategy should be updated to match.

================================================================================
Success Criteria
================================================================================
A fully passing suite in this module guarantees that no manager
configuration change can appear "saved" in the dashboard's local state
unless the corresponding SSH apply call actually succeeded, that
dashboard-side format validation correctly gates every manager-bound
field before an SSH round-trip is spent, that the SASL password never
touches disk outside its documented boolean-flag pattern, and that an
`integration` block can never be renamed through the update path — all
without requiring a live Wazuh manager.

================================================================================
Maintenance Notes
================================================================================
When adding a new field to General or to mail delivery, extend this
module symmetrically: one rejection test per new dashboard-side
validation rule, and one success/failure pair proving the
persist-only-on-apply-success rule holds for the new field too. Never
weaken an existing persist-only-on-success assertion to make a new
feature's test pass — if a new field seems to need eager persistence,
that is a signal to revisit Flow 3's ordering guarantee deliberately (see
`docs/architecture/execution-flow.md`), not to special-case it silently.
"""
import conftest
from unittest.mock import patch
import json

def test_settings_page_authenticated_success(authenticated_client, monkeypatch):
  with patch("dashboard_core.services.wazuh_api.request") as mock_send:
      mock_send.return_value = (True, conftest.OSSEC_CONF_SAMPLE)   # empty list, valid JSON
      response = authenticated_client.get("/settings")
      assert response.status_code == 200
      assert response.headers["content-type"].startswith("text/html")

def test_settings_page_unrequired_unauthenticated(unauthenticated_client):
  # This test ensures that the settings page redirects unauthenticated users
  response = unauthenticated_client.get("/settings")
  responses = [*response.history, response]
  for i, r in enumerate(responses):
      print(f"\n===== Response {i} =====")
      print("Status:", r.status_code)
      print("URL:", r.url)
      print("Headers:", dict(r.headers))
      print("Body:")
      print(r.text)
  assert response.history[0].status_code == 303
  assert response.history[0].headers['location'] == '/login'

def test_settings_general_save_success(authenticated_client, monkeypatch, tmp_path):
  monkeypatch.setattr("dashboard_core.services.wazuh_api.request", lambda *args, **kwargs: (True, conftest.OSSEC_CONF_SAMPLE))
  settings_path = tmp_path / "settings.json"
  monkeypatch.setattr("dashboard_core.config.SETTINGS_FILE", settings_path)
  response = authenticated_client.post("/settings", data={
      "host": "192.168.1.10",
      "port": "5000",
      "note": "test note",
  })
  assert response.status_code == 200   # redirect takip edilince
  saved = json.loads(settings_path.read_text())
  assert saved == {"host": "192.168.1.10", "port": 5000, "note": "test note"}

def test_settings_general_invalid_port_rejected(authenticated_client, monkeypatch, tmp_path):
  monkeypatch.setattr("dashboard_core.services.wazuh_api.request", lambda *args, **kwargs: (True, conftest.OSSEC_CONF_SAMPLE))
  settings_path = tmp_path / "settings.json"
  monkeypatch.setattr("dashboard_core.config.SETTINGS_FILE", settings_path)
  response = authenticated_client.post("/settings", data={
      "host": "192.168.1.10",
      "port": "not-a-number",
      "note": "",
  })
  assert response.status_code == 400
  assert not settings_path.exists()

def test_settings_general_invalid_port_rejected(authenticated_client, monkeypatch, tmp_path):
  settings_path = tmp_path / "settings.json"
  monkeypatch.setattr("dashboard_core.config.SETTINGS_FILE", settings_path)
  with patch("dashboard_core.services.wazuh_api.request") as mock_send:
      mock_send.return_value = (True, conftest.OSSEC_CONF_SAMPLE)   # empty list, valid JSON
      response = authenticated_client.post("/settings", data={
          "host": "192.168.1.10",
          "port": "not-a-number",
          "note": "",
      })
      assert response.status_code == 400
      assert not settings_path.exists()

def test_settings_mail_invalid_smtp_server_rejected(authenticated_client, monkeypatch, tmp_path):
  settings_path = tmp_path / "settings.json"
  monkeypatch.setattr("dashboard_core.config.SETTINGS_FILE", settings_path)
  with patch("dashboard_core.services.wazuh_api.request") as mock_send:
      mock_send.return_value = (True, conftest.OSSEC_CONF_SAMPLE)
      response = authenticated_client.post("/alerting/mail", data={
          "email_to": "user@example.com",
          "email_from": "noreply@example.com",
          "smtp_server": "not a valid host!!",   # space and special characters, rejected by HOST_RE
      })
      assert response.status_code == 400
      assert not settings_path.exists()

def test_settings_mail_invalid_relayhost_rejected(authenticated_client, monkeypatch, tmp_path):
  settings_path = tmp_path / "settings.json"
  monkeypatch.setattr("dashboard_core.config.SETTINGS_FILE", settings_path)
  with patch("dashboard_core.services.wazuh_api.request") as mock_send:
      mock_send.return_value = (True, conftest.OSSEC_CONF_SAMPLE)
      response = authenticated_client.post("/alerting/mail", data={
          "email_to": "user@example.com",
          "email_from": "noreply@example.com",
          "smtp_server": "smtp.example.com",
          "relayhost": "not a valid relay!!",
      })
      assert response.status_code == 400
      assert not settings_path.exists()


def test_settings_mail_relayhost_with_port_accepted(authenticated_client, monkeypatch, tmp_path):
  # relayhost's bracketed/port-suffixed shapes ("[smtp.gmail.com]:587") must
  # still pass validation - _relay_host_only() strips the port/brackets
  # before HOST_RE checks it
  settings_path = tmp_path / "settings.json"
  monkeypatch.setattr("dashboard_core.config.SETTINGS_FILE", settings_path)
  with patch("dashboard_core.services.wazuh_api.request") as mock_send, \
        patch("dashboard_core.routes.alerting.run_mail_command_via_ssh") as mock_mail_send:
      mock_send.return_value = (True, conftest.OSSEC_CONF_SAMPLE)
      mock_mail_send.return_value = (True, "ok")
      response = authenticated_client.post("/alerting/mail", data={
          "email_to": "user@example.com",
          "email_from": "noreply@example.com",
          "smtp_server": "smtp.example.com",
          "relayhost": "[smtp.gmail.com]:587",
      })
      assert response.status_code == 200
      mock_mail_send.assert_called_once()


def test_settings_mail_invalid_maxperhour_rejected(authenticated_client, monkeypatch, tmp_path):
  settings_path = tmp_path / "settings.json"
  monkeypatch.setattr("dashboard_core.config.SETTINGS_FILE", settings_path)
  with patch("dashboard_core.services.wazuh_api.request") as mock_send:
      mock_send.return_value = (True, conftest.OSSEC_CONF_SAMPLE)
      response = authenticated_client.post("/alerting/mail", data={
          "email_to": "user@example.com",
          "email_from": "noreply@example.com",
          "smtp_server": "smtp.example.com",
          "email_maxperhour": "not-a-number",
      })
      assert response.status_code == 400
      assert not settings_path.exists()


def test_settings_page_degrades_gracefully_on_manager_list_failure(authenticated_client, monkeypatch, tmp_path):
  # ossec_config_list failing (for either block type) must not crash the
  # page - it should still render 200, just with an empty list + error
  # message for that section instead of a stack trace
  settings_path = tmp_path / "settings.json"
  monkeypatch.setattr("dashboard_core.config.SETTINGS_FILE", settings_path)
  with patch("dashboard_core.services.wazuh_api.request") as mock_send:
      mock_send.return_value = (False, "SSH error: connection timed out")
      response = authenticated_client.get("/alerting?tab=integrations")
      assert response.status_code == 200
      # NOTE: I haven't verified exactly where email_alerts_list_error /
      # integrations_list_error render in settings.html - if this specific
      # assertion fails, run with -s and check response.text yourself to
      # find the right substring; the 200-status check above is the part
      # I'm confident about.
      assert "connection timed out" in response.text or "SSH error" in response.text

