"""
Project-owned rsyslog rule files (/etc/rsyslog.d/wazuh-*.conf) on the
manager, via ``rsyslog-config-tool.py`` behind the "rsyslog" selector.

**This is still SSH, deliberately.** rsyslog belongs to the manager's
operating system, not to Wazuh, so the Wazuh API has no way to express it
- the same reason Postfix and package installation stayed on this channel
while everything Wazuh owns moved to the API
(docs/architecture/system-overview.md).

Build the argument vector, hand the tool's JSON back as Python values,
translate its {"error": "..."} payloads into readable messages.
"""

import json

from dashboard_core.services.ssh_transport import run_rsyslog_command_via_ssh


def _friendly_error(raw_output: str) -> str:
    """The manager-side tools report failure as a {"error": "..."} JSON
    payload on stdout; this turns that into a readable line instead of
    surfacing the raw output.

    Lived in services/manager.py until the ossec.conf work moved to the
    API and left that module with nothing else in it.
    """
    try:
        parsed = json.loads(raw_output)
        if isinstance(parsed, dict) and "error" in parsed:
            return parsed["error"]
    except (json.JSONDecodeError, TypeError):
        pass
    return raw_output


def rsyslog_files_list() -> tuple[list[dict] | None, str | None]:
    ok, out = run_rsyslog_command_via_ssh(["list"])
    if not ok:
        return None, _friendly_error(out)
    try:
        return json.loads(out), None
    except json.JSONDecodeError:
        return None, out


def rsyslog_file_save(name: str, content: str, *, overwrite: bool) -> tuple[bool, str]:
    """add = create only (manager rejects an existing name);
    update = create-or-overwrite."""
    if overwrite:
        ok, out = run_rsyslog_command_via_ssh(
            ["update", name, json.dumps({"content": content}, ensure_ascii=False)]
        )
    else:
        ok, out = run_rsyslog_command_via_ssh(
            ["add", json.dumps({"name": name, "content": content}, ensure_ascii=False)]
        )
    return ok, (out if ok else _friendly_error(out))


def rsyslog_file_delete(name: str) -> tuple[bool, str]:
    ok, out = run_rsyslog_command_via_ssh(["delete", name])
    return ok, (out if ok else _friendly_error(out))
