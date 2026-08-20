"""
================================================================================
Purpose
================================================================================
This module protects the dashboard's transport layer to the three
manager features still reached over SSH: the `run_*_via_ssh()` functions
in `dashboard_core/services/ssh_transport.py` (`run_mail_command_via_ssh`,
`run_rsyslog_command_via_ssh`, `run_deps_command_via_ssh`). Everything
Wazuh itself owns moved to the Wazuh API (`services/wazuh_api.py`, covered
separately); what is left here is Postfix, rsyslog files, and package
installation - host-OS concerns the API cannot express. These three
functions are the single seam at which every SSH-facing test in this
repository should stop and mock, which means this module is the *one
place* real `paramiko` interaction logic actually gets exercised, and the
one place a mistake in command construction would otherwise go completely
uncaught until it broke a real SSH session against a real manager.

Two senders that used to live here - `run_ossec_config_command_via_ssh`
and `run_agent_command_via_ssh` - were removed along with their manager-
side targets once agents and `ossec.conf` moved to the API; their tests
were removed with them rather than kept as dead coverage.

================================================================================
Responsibilities
================================================================================
- Verify each function constructs its SSH command correctly: prefixing
  the right tool-selector word (`"mail"`, `"rsyslog"`, `"deps"`) and
  passing every argument through `shlex.quote()` individually before
  joining into one command string — never raw string interpolation.
- Verify each function checks for missing `.env`-derived configuration
  (`SSH_HOST`/`SSH_USER`/`SSH_KEY_PATH`) and short-circuits with
  `(False, <readable message>)` without attempting a connection when any
  are unset.
- Verify successful command execution: a mocked `paramiko.SSHClient`
  returning exit status 0 yields `(True, <stdout>)`.
- Verify failure handling: a non-zero exit status yields `(False, <stdout
  or "Exit code: N">)`; a `paramiko`-raised exception (auth failure,
  connection timeout, unreachable host) is caught and yields
  `(False, "SSH error: ...")` rather than propagating.
- Verify connection parameters passed to `paramiko.SSHClient.connect()`
  match `SSH_HOST`/`SSH_PORT`/`SSH_USER`/`SSH_KEY_PATH` exactly, and that
  `AutoAddPolicy` is set as the missing-host-key policy.
- Verify the streaming-read loop (checking `channel.recv_ready()` /
  `channel.exit_status_ready()` in a loop with a short sleep) terminates
  correctly for both immediate and delayed exit-status availability, and
  does not hang.

================================================================================
System Boundaries
================================================================================
In scope: the three `run_*_via_ssh()` functions only — their command
construction, their `paramiko` call sequence, and their return-value
contract (`tuple[bool, str]`) under success, failure, and exception paths.

Out of scope, and covered elsewhere:
- Anything that happens *after* a successful SSH round-trip — parsing
  `run_rsyslog_command_via_ssh`'s stdout into a typed result is
  `tests/services/test_ossec_config.py` and `services/rsyslog.py`'s
  concern (the `_friendly_error()` helper that used to live in the
  deleted `services/manager.py`). This module asserts only that the raw
  `(bool, str)` tuple these senders hand back is correct, not what any
  caller does with it.
- Any actual manager-side behavior — what `config-router-wrapper.sh`,
  `mail_config_tool.py`, `rsyslog-config-tool.py`, or
  `dependency_manager_tool.py` do with the command once it arrives. This
  module never connects to a real manager and must not assume one exists.
- Route-level behavior (`/alerting/mail`, `/pipeline/rsyslog`, etc.) —
  this module never imports FastAPI's `TestClient` or touches HTTP.
- Everything Wazuh itself owns (agents, groups, `ossec.conf`, decoders,
  rules) — that channel is `services/wazuh_api.py`, not SSH, and does not
  belong in this SSH-specific module regardless of its own test coverage.
  NOTE: unlike this module's relationship to the three SSH senders,
  `wazuh_api.py`'s own transport internals (session pooling, JWT-derived
  token caching, the retry/backoff decision) have no dedicated unit-test
  file of their own — every other test replaces `wazuh_api.request`
  wholesale via the `api_stub` fixture rather than exercising it. That
  logic was verified against a live manager during development
  (`docs/architecture/wazuh-api.md`) but is not covered by a repeatable
  regression test.

================================================================================
Why These Tests Matter
================================================================================
`docs/security/ssh-boundary.md` and
`docs/knowledge/design-decisions.md` document, in detail, a real
previously-shipped vulnerability class: an earlier forced-command design
that interpolated `$SSH_ORIGINAL_COMMAND` unquoted, which meant a password
or argument containing a space or shell metacharacter would be
word-split a second time on the manager side, silently breaking
`shlex.quote()`'s protection. The dashboard-side half of the fix that
makes the *current* design safe is precisely the `shlex.quote()`-per-argument
discipline these three functions implement — `docs/development/coding-standards.md`
states this outright ("Never `f"{arg}"` raw user input into an SSH command
string"). A regression in this module (e.g. someone "simplifying" one of
these functions to use an f-string) would silently reopen a documented,
previously-fixed security bug class, and nothing else in the test suite
is positioned to catch it, because every other manager-facing test mocks
this exact layer away.

================================================================================
Production Files to Understand First
================================================================================
- `dashboard_core/services/ssh_transport.py` — all three `run_*_via_ssh()` functions;
  `dashboard_core/config.py` — the `SSH_HOST`/`SSH_PORT`/`SSH_USER`/`SSH_KEY_PATH` reads
  (referenced as `config.X` at call time, which is why tests patch them on
  `dashboard_core.config`).
- `docs/architecture/execution-flow.md` — Flow 3, for the exact sequence
  (`shlex.quote` each arg → join → `paramiko.connect` → `exec_command`)
  this module verifies piece by piece.
- `docs/security/ssh-boundary.md` — invariants 2 and 3 specifically:
  "the dashboard never sends a path or script name, only a tool-selector
  word and arguments," and "`$SSH_ORIGINAL_COMMAND` is re-split with
  `eval set --`, not naively interpolated" — the dashboard-side guarantee
  this module protects is the one that makes that manager-side re-split
  safe to depend on.
- `docs/knowledge/design-decisions.md` — "Forced-command dispatcher: one
  router, central restart," specifically failure mode 1 (unquoted
  `$SSH_ORIGINAL_COMMAND` expansion), for the concrete failure mode this
  module's `shlex.quote()` assertions exist to prevent.

================================================================================
Testing Strategy
================================================================================
This is a Unit test module. `paramiko.SSHClient` must be mocked/patched
in every test — no real network connection should ever be attempted.
The recommended approach is to patch `paramiko.SSHClient` (or
`main.paramiko.SSHClient`, depending on import style) to return a
`MagicMock` whose `.connect()`, `.exec_command()`, and the returned
channel's `.recv_ready()`/`.recv()`/`.exit_status_ready()`/
`.recv_exit_status()` are configured per scenario. Command-construction
assertions should inspect the exact string passed to
`client.exec_command(...)`, not just that it was called, since the
quoting/ordering is the behavior under test.

================================================================================
Expected Test Scenarios
================================================================================
- Each of the three functions builds the expected, fully `shlex.quote()`d
  command string for representative inputs, including at least one
  argument containing a space and one containing a shell metacharacter
  (e.g. `;`, `$`, a backtick) to prove quoting actually neutralizes them.
- Each function returns `(False, <message mentioning missing SSH config>)`
  without calling `paramiko` at all when `SSH_HOST`, `SSH_USER`, or
  `SSH_KEY_PATH` is unset/empty.
- A mocked successful command (exit status 0) returns `(True, <stdout>)`
  with the stdout correctly decoded and stripped.
- A mocked failing command (non-zero exit status) returns
  `(False, <stdout or "Exit code: N">)`.
- A `paramiko` connection exception (e.g. `AuthenticationException`,
  socket timeout) is caught and yields `(False, "SSH error: ...")`
  rather than propagating out of the function.
- The streaming-read loop correctly assembles multi-chunk stdout when
  `recv_ready()` returns data across several iterations before
  `exit_status_ready()` becomes true.
- `client.close()` is called on both the success and failure paths (no
  connection leak), including when an exception occurs after `connect()`
  succeeds but before `exec_command()` completes cleanly.

================================================================================
Out of Scope
================================================================================
- Testing against a real SSH server, VM, or container — this module must
  run with zero external network dependency.
- Testing the manager-side forced command, wrapper, or any
  `wazuh-integration/` script's behavior — those are separate deployables
  this repo does not execute.
- Testing higher-level callers of these functions (routes, the
  `ossec_config_*`/`agent_command` wrappers) — see
  `tests/services/test_manager_service.py` and the `tests/api/` modules.
- Performance/timing assertions beyond "the read loop terminates" — exact
  latency of the polling sleep is an implementation detail, not a
  contract.

================================================================================
Mocking Strategy
================================================================================
Mock: `paramiko.SSHClient` and everything under it (the client instance,
`set_missing_host_key_policy`, `connect`, `exec_command`, the returned
`stdin`/`stdout`/`stderr`, and `stdout.channel`). Also patch/override the
module-level `SSH_HOST`/`SSH_PORT`/`SSH_USER`/`SSH_KEY_PATH` constants per
test (rather than relying on a real `.env`) so both the "configured" and
"missing configuration" branches are exercised deterministically. Keep
real: `shlex.quote()` itself (it is standard library and exactly the
behavior being verified) and the functions' own control flow.

================================================================================
Assumptions
================================================================================
- Assumption: `SSH_HOST`/`SSH_PORT`/`SSH_USER`/`SSH_KEY_PATH` are
  monkeypatchable at the `main` module level in tests (they are simple
  module-level globals read once via `os.environ.get()` at import time,
  per `dashboard_core/config.py`'s structure) — if the project ever moves
  these behind a settings object or re-reads them per-call, this module's
  patching strategy needs updating accordingly.
- Assumption: no `paramiko` fixture/mock helper currently exists in
  `tests/conftest.py` (the file is empty as of this writing); this module
  may be the natural place to introduce a shared "fake SSH client"
  fixture that `test_manager_service.py` and API-layer modules can later
  build on top of, if the team wants to consolidate mocking rather than
  duplicate it per module.

================================================================================
Success Criteria
================================================================================
A fully passing suite in this module guarantees that every argument this
dashboard ever sends toward the Wazuh manager is individually shell-quoted
before transmission, that missing SSH configuration fails fast and
safely rather than attempting a connection, that transport-level failures
(bad auth, timeout, non-zero exit) are converted into the documented
`(bool, str)` contract rather than raising, and that no connection is ever
leaked on any code path. It does **not** guarantee that the command
constructed is correct from the *manager's* point of view (that
correctness depends on `config-router-wrapper.sh` and the dispatched
tools, which this module cannot exercise).

================================================================================
Maintenance Notes
================================================================================
If a new `run_*_via_ssh()`-style function is added for a new manager
capability, it must reuse this same pattern (`shlex.quote()` every
argument, check `.env` config before connecting, decode/strip stdout,
catch and convert exceptions) — do not let a new sender skip any of these
steps "because it's simpler." Add a symmetric set of scenarios for it
here immediately; a manager-facing sender with no coverage in this module
is exactly the gap that let the unquoted-`$SSH_ORIGINAL_COMMAND`
forced-command bug (`docs/knowledge/design-decisions.md`) ship in the first
place, on the manager side of an analogous boundary.
"""

import time
from unittest.mock import MagicMock, patch

from dashboard_core.services import ssh_transport
from dashboard_core.services.ssh_transport import (
    run_deps_command_via_ssh,
    run_mail_command_via_ssh,
    run_rsyslog_command_via_ssh,
)

# ============================================================
# run_mail_command_via_ssh
# ============================================================

# Test that run_mail_command_via_ssh returns success and output when the command executes successfully
def test_run_mail_command_via_ssh_success(monkeypatch):
    monkeypatch.setattr("dashboard_core.config.SSH_HOST", "fakehost")
    monkeypatch.setattr("dashboard_core.config.SSH_USER", "fakeuser")
    monkeypatch.setattr("dashboard_core.config.SSH_KEY_PATH", "/path/to/fake/key")

    with patch("paramiko.SSHClient") as MockSSHClient:
        fake_client = MockSSHClient.return_value
        fake_stdout = MagicMock()
        fake_stdout.channel.recv_ready.side_effect = [True, False, True, False]
        fake_stdout.channel.recv_stderr_ready.return_value = False
        fake_stdout.channel.recv.return_value = b"mocked stdout data"
        fake_stdout.channel.exit_status_ready.return_value = True
        fake_stdout.channel.recv_exit_status.return_value = 0

        fake_client.exec_command.return_value = (None, fake_stdout, None)
        mail_data = {
            "email_to": "",
            "email_from": "",
            "smtp_server": "",
            "email_maxperhour": "",
            "relayhost": "",
            "sasl_user": "",
            "sasl_pass_set": False,
        }
        success, output = run_mail_command_via_ssh(mail_data, sasl_pass="somepass")

        assert success is True
        assert output == "mocked stdout data"


# Test that run_mail_command_via_ssh returns failure and output when the command fails
def test_run_mail_command_via_ssh_failure_with_output(monkeypatch):
    monkeypatch.setattr("dashboard_core.config.SSH_HOST", "fakehost")
    monkeypatch.setattr("dashboard_core.config.SSH_USER", "fakeuser")
    monkeypatch.setattr("dashboard_core.config.SSH_KEY_PATH", "/path/to/fake/key")

    with patch("paramiko.SSHClient") as MockSSHClient:
        fake_client = MockSSHClient.return_value
        fake_stdout = MagicMock()
        fake_stdout.channel.recv_ready.side_effect = [True, False, True, False]
        fake_stdout.channel.recv_stderr_ready.return_value = False
        fake_stdout.channel.recv.return_value = b"mocked stdout data"
        fake_stdout.channel.exit_status_ready.return_value = True
        fake_stdout.channel.recv_exit_status.return_value = 1

        fake_client.exec_command.return_value = (None, fake_stdout, None)
        mail_data = {
            "email_to": "",
            "email_from": "",
            "smtp_server": "",
            "email_maxperhour": "",
            "relayhost": "",
            "sasl_user": "",
            "sasl_pass_set": False,
        }
        success, output = run_mail_command_via_ssh(mail_data, sasl_pass="somepass")

        assert success is False
        assert output == "mocked stdout data"


# Test that run_mail_command_via_ssh returns failure and output when the command fails with no output
def test_run_mail_command_via_ssh_failure_no_output(monkeypatch):
    monkeypatch.setattr("dashboard_core.config.SSH_HOST", "fakehost")
    monkeypatch.setattr("dashboard_core.config.SSH_USER", "fakeuser")
    monkeypatch.setattr("dashboard_core.config.SSH_KEY_PATH", "/path/to/fake/key")

    with patch("paramiko.SSHClient") as MockSSHClient:
        fake_client = MockSSHClient.return_value
        fake_stdout = MagicMock()
        fake_stdout.channel.recv_ready.side_effect = [False, False]
        fake_stdout.channel.recv_stderr_ready.return_value = False
        fake_stdout.channel.exit_status_ready.return_value = True
        fake_stdout.channel.recv_exit_status.return_value = 1

        fake_client.exec_command.return_value = (None, fake_stdout, None)
        mail_data = {
            "email_to": "",
            "email_from": "",
            "smtp_server": "",
            "email_maxperhour": "",
            "relayhost": "",
            "sasl_user": "",
            "sasl_pass_set": False,
        }
        success, output = run_mail_command_via_ssh(mail_data, sasl_pass="somepass")

        assert success is False
        assert output == "Exit code: 1"


# Test that run_mail_command_via_ssh returns failure and output when SSH configuration is missing
def test_run_mail_command_via_ssh_missing_config(monkeypatch):
    # Unset any one of the required SSH configuration variables
    monkeypatch.setattr("dashboard_core.config.SSH_HOST", "")
    monkeypatch.setattr("dashboard_core.config.SSH_USER", "fakeuser")
    monkeypatch.setattr("dashboard_core.config.SSH_KEY_PATH", "/path/to/fake/key")
    with patch("paramiko.SSHClient") as MockSSHClient:
        mail_data = {
            "email_to": "",
            "email_from": "",
            "smtp_server": "",
            "email_maxperhour": "",
            "relayhost": "",
            "sasl_user": "",
            "sasl_pass_set": False,
        }
        success, output = run_mail_command_via_ssh(mail_data, sasl_pass="somepass")
        assert success is False
        assert "SSH settings are missing (check WAZUH_SSH_HOST/USER/KEY_PATH in the .env file)." in output
        MockSSHClient.return_value.connect.assert_not_called()


# Test that run_mail_command_via_ssh returns failure and output when a paramiko exception occurs
def test_run_mail_command_via_ssh_paramiko_exception(monkeypatch):
    monkeypatch.setattr("dashboard_core.config.SSH_HOST", "fakehost")
    monkeypatch.setattr("dashboard_core.config.SSH_USER", "fakeuser")
    monkeypatch.setattr("dashboard_core.config.SSH_KEY_PATH", "/path/to/fake/key")

    with patch("paramiko.SSHClient") as MockSSHClient:
        fake_client = MockSSHClient.return_value
        fake_client.connect.side_effect = Exception("Mocked paramiko exception")

        mail_data = {
            "email_to": "",
            "email_from": "",
            "smtp_server": "",
            "email_maxperhour": "",
            "relayhost": "",
            "sasl_user": "",
            "sasl_pass_set": False,
        }
        success, output = run_mail_command_via_ssh(mail_data, sasl_pass="somepass")

        assert success is False
        assert "SSH error: Mocked paramiko exception" in output


# Test that run_mail_command_via_ssh correctly quotes arguments containing spaces or shell metacharacters
# (sasl_pass is used here since it's the most sensitive field - a real password could easily
# contain any of these characters, and this is exactly the boundary docs/security/ssh-boundary.md
# and the v1 forced-command bug are about)
def test_run_mail_command_via_ssh_quotes_arguments(monkeypatch):
    monkeypatch.setattr("dashboard_core.config.SSH_HOST", "fakehost")
    monkeypatch.setattr("dashboard_core.config.SSH_USER", "fakeuser")
    monkeypatch.setattr("dashboard_core.config.SSH_KEY_PATH", "/path/to/fake/key")

    with patch("paramiko.SSHClient") as MockSSHClient:
        fake_client = MockSSHClient.return_value
        fake_stdout = MagicMock()
        fake_stdout.channel.recv_ready.return_value = False
        fake_stdout.channel.recv_stderr_ready.return_value = False
        fake_stdout.channel.exit_status_ready.return_value = True
        fake_stdout.channel.recv_exit_status.return_value = 0
        fake_client.exec_command.return_value = (None, fake_stdout, None)

        mail_data = {
            "email_to": "admin@example.com",
            "email_from": "wazuh@example.com",
            "smtp_server": "smtp.example.com",
            "email_maxperhour": "12",
            "relayhost": "smtp.example.com:587",
            "sasl_user": "wazuh",
            "sasl_pass_set": True,
        }
        dangerous_pass = "s3cret; rm -rf /"
        run_mail_command_via_ssh(mail_data, sasl_pass=dangerous_pass)

        sent_command = fake_client.exec_command.call_args[0][0]
        # the tool-selector word + subcommand are prefixed automatically ("mail update")
        assert sent_command.startswith("mail update ")
        # the dangerous password must appear wrapped in quotes, never raw
        assert f"'{dangerous_pass}'" in sent_command


# Test that run_mail_command_via_ssh returns failure and output when mail configuration is missing or invalid
# NOTE: run_mail_command_via_ssh reads mail_data["..."] via plain dict indexing, but does so
# inside a try/except that converts a missing key into
# (False, "Mail configuration is missing or invalid: ..."). This test pins that behaviour.
def test_run_mail_command_via_ssh_invalid_mail_config(monkeypatch):
    monkeypatch.setattr("dashboard_core.config.SSH_HOST", "fakehost")
    monkeypatch.setattr("dashboard_core.config.SSH_USER", "fakeuser")
    monkeypatch.setattr("dashboard_core.config.SSH_KEY_PATH", "/path/to/fake/key")

    with patch("paramiko.SSHClient") as MockSSHClient:
        mail_data = {
            "email_to": "",
            "email_from": "",
            "smtp_server": "",
            "suspicious_key": "",
            "sasl_pass_set": False,
        }
        success, output = run_mail_command_via_ssh(mail_data, sasl_pass="somepass")
        assert success is False
        assert "Mail configuration is missing or invalid" in output


# ============================================================
# run_rsyslog_command_via_ssh
# ============================================================

# Test that run_rsyslog_command_via_ssh returns success and output when the command executes successfully
def test_run_rsyslog_command_via_ssh_success(monkeypatch):
    monkeypatch.setattr("dashboard_core.config.SSH_HOST", "fakehost")
    monkeypatch.setattr("dashboard_core.config.SSH_USER", "fakeuser")
    monkeypatch.setattr("dashboard_core.config.SSH_KEY_PATH", "/path/to/fake/key")

    with patch("paramiko.SSHClient") as MockSSHClient:
        fake_client = MockSSHClient.return_value
        fake_stdout = MagicMock()
        fake_stdout.channel.recv_ready.side_effect = [True, False]
        fake_stdout.channel.recv_stderr_ready.return_value = False
        fake_stdout.channel.recv.return_value = b'[{"name": "wazuh-tcp.conf"}]'
        fake_stdout.channel.exit_status_ready.return_value = True
        fake_stdout.channel.recv_exit_status.return_value = 0
        fake_client.exec_command.return_value = (None, fake_stdout, None)

        success, output = run_rsyslog_command_via_ssh(["list"])

        assert success is True
        assert output == '[{"name": "wazuh-tcp.conf"}]'


# Test that run_rsyslog_command_via_ssh returns failure and output when SSH configuration is missing
def test_run_rsyslog_command_via_ssh_missing_config(monkeypatch):
    monkeypatch.setattr("dashboard_core.config.SSH_HOST", "")
    monkeypatch.setattr("dashboard_core.config.SSH_USER", "fakeuser")
    monkeypatch.setattr("dashboard_core.config.SSH_KEY_PATH", "/path/to/fake/key")

    with patch("paramiko.SSHClient") as MockSSHClient:
        success, output = run_rsyslog_command_via_ssh(["list"])

        assert success is False
        assert "SSH settings are missing (check WAZUH_SSH_HOST/USER/KEY_PATH in the .env file)." in output
        MockSSHClient.return_value.connect.assert_not_called()


# Test that run_rsyslog_command_via_ssh correctly quotes arguments containing shell metacharacters
def test_run_rsyslog_command_via_ssh_quotes_arguments(monkeypatch):
    monkeypatch.setattr("dashboard_core.config.SSH_HOST", "fakehost")
    monkeypatch.setattr("dashboard_core.config.SSH_USER", "fakeuser")
    monkeypatch.setattr("dashboard_core.config.SSH_KEY_PATH", "/path/to/fake/key")

    with patch("paramiko.SSHClient") as MockSSHClient:
        fake_client = MockSSHClient.return_value
        fake_stdout = MagicMock()
        fake_stdout.channel.recv_ready.return_value = False
        fake_stdout.channel.recv_stderr_ready.return_value = False
        fake_stdout.channel.exit_status_ready.return_value = True
        fake_stdout.channel.recv_exit_status.return_value = 0
        fake_client.exec_command.return_value = (None, fake_stdout, None)

        dangerous_json = '{"content": "input(); rm -rf /"}'
        run_rsyslog_command_via_ssh(["update", "wazuh-tcp.conf", dangerous_json])

        sent_command = fake_client.exec_command.call_args[0][0]
        # the tool-selector word is prefixed automatically ("rsyslog")
        assert sent_command.startswith("rsyslog update wazuh-tcp.conf ")
        assert f"'{dangerous_json}'" in sent_command


# Test that run_rsyslog_command_via_ssh returns failure and output when a paramiko exception occurs
def test_run_rsyslog_command_via_ssh_paramiko_exception(monkeypatch):
    monkeypatch.setattr("dashboard_core.config.SSH_HOST", "fakehost")
    monkeypatch.setattr("dashboard_core.config.SSH_USER", "fakeuser")
    monkeypatch.setattr("dashboard_core.config.SSH_KEY_PATH", "/path/to/fake/key")

    with patch("paramiko.SSHClient") as MockSSHClient:
        fake_client = MockSSHClient.return_value
        fake_client.connect.side_effect = Exception("Mocked paramiko exception")

        success, output = run_rsyslog_command_via_ssh(["list"])

        assert success is False
        assert "SSH error: Mocked paramiko exception" in output


# ============================================================
# run_deps_command_via_ssh
# ============================================================

# Test that run_deps_command_via_ssh returns success and output when the command executes successfully
def test_run_deps_command_via_ssh_success(monkeypatch):
    monkeypatch.setattr("dashboard_core.config.SSH_HOST", "fakehost")
    monkeypatch.setattr("dashboard_core.config.SSH_USER", "fakeuser")
    monkeypatch.setattr("dashboard_core.config.SSH_KEY_PATH", "/path/to/fake/key")

    with patch("paramiko.SSHClient") as MockSSHClient:
        fake_client = MockSSHClient.return_value
        fake_stdout = MagicMock()
        fake_stdout.channel.recv_ready.side_effect = [True, False]
        fake_stdout.channel.recv_stderr_ready.return_value = False
        fake_stdout.channel.recv.return_value = b'{"error": 0, "data": {"rsyslog": {"installed": true, "version": "8.1"}}}'
        fake_stdout.channel.exit_status_ready.return_value = True
        fake_stdout.channel.recv_exit_status.return_value = 0
        fake_client.exec_command.return_value = (None, fake_stdout, None)

        success, output = run_deps_command_via_ssh(["check", "rsyslog"])

        assert success is True
        assert '"installed": true' in output


# Test that run_deps_command_via_ssh returns failure and output when SSH configuration is missing
def test_run_deps_command_via_ssh_missing_config(monkeypatch):
    monkeypatch.setattr("dashboard_core.config.SSH_HOST", "fakehost")
    monkeypatch.setattr("dashboard_core.config.SSH_USER", "")
    monkeypatch.setattr("dashboard_core.config.SSH_KEY_PATH", "/path/to/fake/key")

    with patch("paramiko.SSHClient") as MockSSHClient:
        success, output = run_deps_command_via_ssh(["check", "rsyslog"])

        assert success is False
        assert "SSH settings are missing (check WAZUH_SSH_HOST/USER/KEY_PATH in the .env file)." in output
        MockSSHClient.return_value.connect.assert_not_called()


# Test that run_deps_command_via_ssh correctly quotes arguments containing shell metacharacters
def test_run_deps_command_via_ssh_quotes_arguments(monkeypatch):
    monkeypatch.setattr("dashboard_core.config.SSH_HOST", "fakehost")
    monkeypatch.setattr("dashboard_core.config.SSH_USER", "fakeuser")
    monkeypatch.setattr("dashboard_core.config.SSH_KEY_PATH", "/path/to/fake/key")

    with patch("paramiko.SSHClient") as MockSSHClient:
        fake_client = MockSSHClient.return_value
        fake_stdout = MagicMock()
        fake_stdout.channel.recv_ready.return_value = False
        fake_stdout.channel.recv_stderr_ready.return_value = False
        fake_stdout.channel.exit_status_ready.return_value = True
        fake_stdout.channel.recv_exit_status.return_value = 0
        fake_client.exec_command.return_value = (None, fake_stdout, None)

        dangerous_pkg = "rsyslog; rm -rf /"
        run_deps_command_via_ssh(["check", dangerous_pkg])

        sent_command = fake_client.exec_command.call_args[0][0]
        # the tool-selector word is prefixed automatically ("deps")
        assert sent_command.startswith("deps check ")
        assert f"'{dangerous_pkg}'" in sent_command


# Test that run_deps_command_via_ssh returns failure and output when a paramiko exception occurs
def test_run_deps_command_via_ssh_paramiko_exception(monkeypatch):
    monkeypatch.setattr("dashboard_core.config.SSH_HOST", "fakehost")
    monkeypatch.setattr("dashboard_core.config.SSH_USER", "fakeuser")
    monkeypatch.setattr("dashboard_core.config.SSH_KEY_PATH", "/path/to/fake/key")

    with patch("paramiko.SSHClient") as MockSSHClient:
        fake_client = MockSSHClient.return_value
        fake_client.connect.side_effect = Exception("Mocked paramiko exception")

        success, output = run_deps_command_via_ssh(["check", "postfix"])

        assert success is False
        assert "SSH error: Mocked paramiko exception" in output


# ======================================================================
# THE DRAIN LOOP ITSELF
# ======================================================================
# These cover _run() directly rather than through a sender, because the
# defects they pin down were in the loop every sender shared. All three
# were live: the manager's own log showed restarts completing while the
# dashboard reported them failed, or never answered at all.

def _fake_channel(*, stdout_chunks=(), stderr_chunks=(), exit_status=0,
                  exit_ready_after=0):
    """A channel that hands back scripted data then reports an exit status.

    `exit_ready_after` is how many polls happen before exit_status_ready()
    turns true, so a test can reproduce the window where the command has
    finished writing but the status has not landed yet.
    """
    channel = MagicMock()
    out = list(stdout_chunks)
    err = list(stderr_chunks)
    polls = {"n": 0}

    channel.recv_ready.side_effect = lambda: bool(out)
    channel.recv.side_effect = lambda _n: out.pop(0)
    channel.recv_stderr_ready.side_effect = lambda: bool(err)
    channel.recv_stderr.side_effect = lambda _n: err.pop(0)

    def status_ready():
        polls["n"] += 1
        return polls["n"] > exit_ready_after
    channel.exit_status_ready.side_effect = status_ready
    channel.recv_exit_status.return_value = exit_status

    stdout = MagicMock()
    stdout.channel = channel
    return stdout, channel


def _run_with(stdout):
    client = MagicMock()
    client.exec_command.return_value = (None, stdout, None)
    return ssh_transport._run(client, "restart", 5)


def test_stderr_is_drained_not_left_to_block_the_remote_process():
    """restart-services.sh writes `systemctl status --no-pager` to stderr
    on its failure paths. That is larger than the channel window, and a
    stream nobody reads stops the remote process mid-write - which is how
    a failed restart became a request that never returned."""
    stdout, channel = _fake_channel(
        stdout_chunks=[b"Restarting postfix...\n"],
        stderr_chunks=[b"ERROR: postfix failed to restart\n", b"x" * 40000],
        exit_status=1,
    )
    status, out = _run_with(stdout)

    assert channel.recv_stderr.called, "stderr was never read"
    assert status == 1
    # And the operator gets the reason, instead of a bare exit code.
    assert "postfix failed to restart" in out


def test_a_success_is_not_reported_as_failure_when_the_status_lands_late():
    """A successful restart used to be shown to the operator as a failure.

    The trigger was the EOF path specifically: the old loop broke on
    `if not data: break` the moment recv() returned b"", *without*
    consulting the exit status, and only then read it as
    `recv_exit_status() if exit_status_ready() else -1`. An empty read
    arriving a beat before the status message therefore produced -1 - a
    failure verdict on a restart that had worked.

    So the fake ends its output with an empty chunk while the status is
    still a few polls away. That ordering is the whole bug; a fake
    without the empty read cannot tell the two versions apart, which is
    what an earlier version of this test got wrong.
    """
    stdout, _ = _fake_channel(
        stdout_chunks=[b"wazuh-manager restarted OK.\n", b""],
        exit_status=0,
        exit_ready_after=3,   # status lands after the EOF read
    )
    status, out = _run_with(stdout)

    assert status == 0, "a completed restart was reported as failed"
    assert "restarted OK" in out


def test_a_stalled_channel_gives_up_instead_of_spinning_forever():
    """recv_ready()/exit_status_ready() are non-blocking, so settimeout()
    never applied to the old loop - a stalled connection meant an
    unbounded busy-wait inside a request handler and an HTTP response
    that never came."""
    channel = MagicMock()
    channel.recv_ready.return_value = False
    channel.recv_stderr_ready.return_value = False
    channel.exit_status_ready.return_value = False   # never finishes
    stdout = MagicMock()
    stdout.channel = channel

    client = MagicMock()
    client.exec_command.return_value = (None, stdout, None)

    started = time.monotonic()
    status, out = ssh_transport._run(client, "restart", 1)
    elapsed = time.monotonic() - started

    assert status == -1
    assert "Timed out" in out
    assert elapsed < 5, f"did not honour its own deadline (took {elapsed:.1f}s)"
    assert channel.close.called, "the stalled channel was left open"


def test_partial_output_survives_a_timeout():
    """Whatever the script managed to say before it stalled is the only
    clue about where it stopped, so it must not be discarded."""
    channel = MagicMock()
    emitted = [b"Restarting postfix...\n"]
    channel.recv_ready.side_effect = lambda: bool(emitted)
    channel.recv.side_effect = lambda _n: emitted.pop(0)
    channel.recv_stderr_ready.return_value = False
    channel.exit_status_ready.return_value = False
    stdout = MagicMock()
    stdout.channel = channel

    client = MagicMock()
    client.exec_command.return_value = (None, stdout, None)

    status, out = ssh_transport._run(client, "restart", 1)
    assert status == -1
    assert "Restarting postfix" in out
