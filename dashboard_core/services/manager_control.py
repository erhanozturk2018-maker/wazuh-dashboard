"""
Making a written configuration change actually take effect.

Wazuh does not hot-reload `ossec.conf` or the ruleset: a change written
through the API sits on disk, correct and inert, until the manager is
restarted. Under the old SSH-only design the forced-command wrapper
handled this centrally - any mutating call restarted services on the way
out, so no caller had to remember. When `ossec.conf`, decoders and rules
moved to the Wazuh API they stopped passing through that wrapper, and the
guarantee was lost with it: saves reported success, the file was updated,
and nothing changed until something else happened to restart the manager.
That is the exact failure mode `docs/knowledge/design-decisions.md`
records as the reason the central restart exists. This module is where
that guarantee lives now.

**The restart goes over SSH, not the API.** See
`ssh_transport.run_restart_command_via_ssh` for why - briefly, the API
cannot reliably report on restarting the process that serves it.

**A failed restart never turns a successful write into a failure.** The
change IS on disk; reporting it as failed would invite the operator to
re-apply something already applied. It is reported as a success carrying
a warning, and `routes` surfaces a retry control for it - the same
split the wrapper made with its own exit code.
"""

from dashboard_core.services.ssh_transport import run_restart_command_via_ssh

# Shown when the write landed but the manager did not come back. Phrased
# so the operator knows the change is safe, what is not true yet, and
# what to do - a bare "restart failed" leaves all three unanswered.
RESTART_FAILED_HINT = (
    "The change was saved, but the Wazuh manager could not be restarted, "
    "so it is not live yet. Use Apply changes to retry."
)


def apply_changes() -> tuple[bool, str]:
    """Restarts the manager so configuration on disk becomes active.

    Returns ``(ok, message)``. Callers that have just written something
    should keep their own success even when this fails - see the module
    docstring.
    """
    ok, output = run_restart_command_via_ssh()
    if not ok:
        return False, str(output)
    return True, "Manager restarted."


def needs_restart_retry(message: str) -> bool:
    """Did this save land on disk without going live?

    Routes redirect after a successful save, which would otherwise drop
    the warning `restart_warning()` returned. They use this to flag the
    redirect instead, so the page can render a retry control.
    """
    return RESTART_FAILED_HINT in str(message or "")


def restart_warning() -> str:
    """Restart the manager and return an empty string on success, or an
    operator-facing warning to append to a save confirmation.

    The shape callers want: they already know their write succeeded and
    only need to know whether to say anything extra about it.
    """
    ok, message = apply_changes()
    if ok:
        return ""
    return f"{RESTART_FAILED_HINT} ({message})"
