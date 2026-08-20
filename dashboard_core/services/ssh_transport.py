"""
The SSH channel to the Wazuh manager - now the SECOND channel, not the only one.

Everything Wazuh itself owns (ossec.conf, decoders/rules, agents, groups,
agent.conf, syscollector) moved to the Wazuh API in
``services/wazuh_api.py``. What is left here is the work the API genuinely
cannot express, because it concerns the manager's operating system rather
than Wazuh:

    mail      Postfix relay + SASL credentials (``mail_config_tool.py``)
    rsyslog   /etc/rsyslog.d/wazuh-*.conf      (``rsyslog-config-tool.py``)
    deps      allowlisted package check/install (``dependency_manager_tool.py``)

The ``ossec`` and ``agents`` selectors are no longer used from here; their
senders were removed rather than left behind as dead code, since a
plausible-looking unused sender is an invitation to route new work back
down the wrong channel.

Every function sends a flat, ``shlex.quote``-ed argument vector. The script
path and ``sudo`` are NEVER written by the dashboard - the manager's
``authorized_keys`` forced command (``config-router-wrapper.sh``) resolves
the tool from the leading selector word. That property is what bounds a
leaked key's blast radius, and it survives the migration unchanged.
See docs/security/ssh-boundary.md.

SSH settings are read as ``config.SSH_*`` at call time so tests can patch them.
"""

import shlex
import time

import paramiko

from dashboard_core import config


def _run(client: paramiko.SSHClient, command: str, timeout: int) -> tuple[int, str]:
    """Runs one command and returns ``(exit_status, combined_output)``.

    Every sender used to carry its own copy of this loop, and all four
    copies shared three defects that between them produced a restart the
    dashboard reported as failed - or never reported at all - while the
    manager's own log showed it completing:

    1. **stderr was never drained.** Paramiko buffers stdout and stderr
       separately behind one flow-control window. ``restart-services.sh``
       writes ``systemctl status --no-pager`` to stderr on its failure
       paths, which is easily larger than that window; once it filled,
       the *remote* process blocked on write and never reached its exit.
       Reading only stdout is what turned a script failure into a hang.

    2. **The poll loop had no deadline.** ``recv_ready()`` and
       ``exit_status_ready()` are non-blocking, so ``settimeout()`` - which
       only bounds a blocking ``recv()`` - never applied. A stalled or
       silently dropped connection meant an unbounded busy-wait inside a
       request handler, so the HTTP response never came.

    3. **The exit status was read with a guard that discarded it.**
       ``recv_exit_status() if exit_status_ready() else -1`` returns -1
       whenever the loop broke on EOF a moment before the exit-status
       message arrived - reporting a successful restart as a failure.
       ``recv_exit_status()`` blocks until the value exists, which is the
       behaviour that was wanted; the guard defeated it.

    Returns -1 as the status only when the deadline really was hit, and
    says so in the output so a caller can tell a timeout from a refusal.
    """
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    channel = stdout.channel
    channel.settimeout(timeout)

    deadline = time.monotonic() + timeout
    out_chunks: list[bytes] = []
    err_chunks: list[bytes] = []

    while True:
        progressed = False
        # Both streams, every pass: leaving either unread can block the
        # remote process (defect 1). Only actual bytes count as progress -
        # a ready channel that hands back b"" is at EOF, and treating that
        # as progress would keep the loop alive until the deadline.
        if channel.recv_ready():
            data = channel.recv(65536)
            if data:
                out_chunks.append(data)
                progressed = True
        if channel.recv_stderr_ready():
            data = channel.recv_stderr(65536)
            if data:
                err_chunks.append(data)
                progressed = True

        if not progressed and channel.exit_status_ready():
            break
        if time.monotonic() > deadline:
            channel.close()
            output = _decode(out_chunks, err_chunks)
            return -1, (
                f"Timed out after {timeout}s waiting for the command to finish."
                + (f" Output so far: {output}" if output else "")
            )
        if not progressed:
            time.sleep(0.1)

    # No second drain here on purpose: the loop only breaks once both
    # streams reported nothing AND the exit status had arrived, and SSH
    # delivers a channel's data before its exit-status message, so there
    # is nothing left to collect.
    #
    # recv_exit_status() is called WITHOUT an exit_status_ready() guard.
    # It blocks until the value exists, which is what the old guarded
    # version threw away when it returned -1 on a successful run.
    return channel.recv_exit_status(), _decode(out_chunks, err_chunks)


def _decode(out_chunks: list[bytes], err_chunks: list[bytes]) -> str:
    """stdout then stderr, so a script's error text reaches the operator
    instead of being dropped on the floor."""
    out = b"".join(out_chunks).decode("utf-8", errors="ignore").strip()
    err = b"".join(err_chunks).decode("utf-8", errors="ignore").strip()
    return "\n".join(part for part in (out, err) if part)


def run_mail_command_via_ssh(mail_data: dict, sasl_pass: str | None = None) -> tuple[bool, str]:
    """Triggers mail_config_tool.py on the manager.
    The SSH restricted command (the authorized_keys forced command) already
    binds the script up front - we only send "update ARG1 ARG2 ...", we do
    NOT write the script path ourselves.
    If sasl_pass is sent as an empty string the script keeps the existing
    password."""
    print(f"[DEBUG] SSH_HOST={config.SSH_HOST!r} SSH_PORT={config.SSH_PORT!r} SSH_USER={config.SSH_USER!r} SSH_KEY_PATH={config.SSH_KEY_PATH!r}")
    if not (config.SSH_HOST and config.SSH_USER and config.SSH_KEY_PATH):
        return False, "SSH settings are missing (check WAZUH_SSH_HOST/USER/KEY_PATH in the .env file)."

    try:
        args = [
        mail_data["email_to"],
        mail_data["email_from"],
        mail_data["smtp_server"],
        mail_data["email_maxperhour"],
        mail_data["relayhost"],
        mail_data["sasl_user"],
        sasl_pass or "",   # empty -> the existing password is kept
        ]
    except Exception as e:
        return False, f"Mail configuration is missing or invalid: {e}"
    args = ["mail", "update"] + args
    command = " ".join(shlex.quote(a) for a in args)

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        print("[DEBUG] attempting connect...")
        client.connect(
            hostname=config.SSH_HOST, port=config.SSH_PORT, username=config.SSH_USER,
            key_filename=config.SSH_KEY_PATH, timeout=10,
        )
        print("[DEBUG] connect succeeded, attempting exec_command...")
        exit_status, out = _run(client, command, 15)
        client.close()
        return exit_status == 0, out or f"Exit code: {exit_status}"
    except Exception as e:
        print(f"[DEBUG] SSH exception: {type(e).__name__}: {e}")
        return False, f"SSH error: {e}"


def run_rsyslog_command_via_ssh(args: list[str]) -> tuple[bool, str]:
    """Forwards arguments such as "list" or "update <name> {...}" to
    rsyslog-config-tool.py over SSH (the "rsyslog" selector) and returns
    stdout + exit code. Exactly the same pattern as the other senders."""
    if not (config.SSH_HOST and config.SSH_USER and config.SSH_KEY_PATH):
        return False, "SSH settings are missing (check WAZUH_SSH_HOST/USER/KEY_PATH in the .env file)."
    args = ["rsyslog"] + args
    command = " ".join(shlex.quote(a) for a in args)

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=config.SSH_HOST, port=config.SSH_PORT, username=config.SSH_USER,
            key_filename=config.SSH_KEY_PATH, timeout=10,
        )
        exit_status, out = _run(client, command, 15)
        client.close()
        return exit_status == 0, out or f"Exit code: {exit_status}"
    except Exception as e:
        return False, f"SSH error: {e}"


def run_deps_command_via_ssh(args: list[str]) -> tuple[bool, str]:
    """Forwards "check <pkg> ..." or "install <pkg> ..." to
    dependency_manager_tool.py over SSH (the "deps" selector) and returns
    stdout + exit code. Exactly the same pattern as the other senders."""
    if not (config.SSH_HOST and config.SSH_USER and config.SSH_KEY_PATH):
        return False, "SSH settings are missing (check WAZUH_SSH_HOST/USER/KEY_PATH in the .env file)."
    args = ["deps"] + args
    command = " ".join(shlex.quote(a) for a in args)

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=config.SSH_HOST, port=config.SSH_PORT, username=config.SSH_USER,
            key_filename=config.SSH_KEY_PATH, timeout=10,
        )
        # apt-get install can legitimately take a while - longer exec timeout
        exit_status, out = _run(client, command, 300)
        client.close()
        return exit_status == 0, out or f"Exit code: {exit_status}"
    except Exception as e:
        return False, f"SSH error: {e}"


def run_restart_command_via_ssh() -> tuple[bool, str]:
    """Restarts postfix and wazuh-manager via the "restart" selector.

    **Why this goes over SSH rather than the API's own PUT /manager/restart.**
    ``wazuh-control restart`` bounces every Wazuh daemon, ``wazuh-apid``
    included - so asking the API to restart the manager is asking it to
    kill the thing answering the request. The reply becomes unreliable by
    construction: a dropped connection looks identical to a failure, and
    on a manager that already times out regularly that ambiguity is
    exactly what you do not want from the step that confirms a config
    change went live. This channel is independent of what it restarts, and
    ``restart-services.sh`` answers synchronously, after checking that both
    services actually came back.

    Takes no arguments - the wrapper's "restart" case ignores anything
    after the selector word.

    One coupling worth knowing about: ``restart-services.sh`` runs
    ``postfix check`` first under ``set -e``, so a broken Postfix
    configuration blocks the wazuh-manager restart too.
    """
    if not (config.SSH_HOST and config.SSH_USER and config.SSH_KEY_PATH):
        return False, "SSH settings are missing (check WAZUH_SSH_HOST/USER/KEY_PATH in the .env file)."

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=config.SSH_HOST, port=config.SSH_PORT, username=config.SSH_USER,
            key_filename=config.SSH_KEY_PATH, timeout=10,
        )
        # The slowest thing this channel does: wazuh-control restart, a
        # settle delay, then a status check per service.
        exit_status, out = _run(client, "restart", 300)
        client.close()
        return exit_status == 0, out or f"Exit code: {exit_status}"
    except Exception as e:
        return False, f"SSH error: {e}"
