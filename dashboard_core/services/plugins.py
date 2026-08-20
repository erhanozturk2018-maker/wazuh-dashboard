"""
Plugin (system dependency) verification on the manager:
dependency_manager_tool.py via the "deps" selector.

Results are persisted per-package under settings.json's "plugins" key as
{"verified": bool, "version": str|null, "checked_at": ISO-8601}.

``checked_at`` changes in EXACTLY two situations:
1. the operator explicitly confirms the Manage Plugins dialog
   (``verify_and_record_plugins``), or
2. a Postfix-dependent operation fails at runtime, which triggers a
   scoped re-check of postfix only (``recheck_postfix``).
Every other read of the state goes through
``storage.load_plugin_status()`` and is strictly read-only.
"""

import json
from datetime import datetime, timezone

from dashboard_core.services.ssh_transport import run_deps_command_via_ssh
from dashboard_core.storage import save_plugin_entries

KNOWN_PLUGINS = ("rsyslog", "postfix")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_deps_envelope(raw_output: str) -> dict | None:
    """dependency_manager_tool.py prints one JSON object with a numeric
    "error" field - the same envelope convention every SSH-dispatched
    tool in wazuh-integration/ uses."""
    for line in raw_output.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and "error" in parsed:
            return parsed
    return None


def _deps_command(args: list[str]) -> tuple[dict | None, str | None]:
    """Returns (data, error): the envelope's per-package "data" dict on
    success, otherwise a readable message."""
    ok, out = run_deps_command_via_ssh(args)
    envelope = _parse_deps_envelope(out)
    if envelope is None:
        return None, out.strip() or "Manager did not return a JSON response."
    if not ok or envelope.get("error") != 0:
        return None, str(envelope.get("message") or envelope)
    data = envelope.get("data")
    if not isinstance(data, dict):
        return None, f"Manager returned an unexpected data shape: {envelope}"
    return data, None


def _entries_from(data: dict, packages: list[str]) -> dict:
    checked_at = _now_iso()
    return {
        name: {
            "verified": bool(data.get(name, {}).get("installed")),
            "version": data.get(name, {}).get("version"),
            "checked_at": checked_at,
        }
        for name in packages
    }


def verify_and_record_plugins(packages: list[str]) -> tuple[dict | None, str | None]:
    """The Manage Plugins confirm flow: check -> install anything missing
    -> re-check -> persist the per-package result. Returns (entries,
    error); on error nothing is persisted."""
    data, err = _deps_command(["check", *packages])
    if err:
        return None, err

    missing = [p for p in packages if not data.get(p, {}).get("installed")]
    if missing:
        _, err = _deps_command(["install", *missing])
        if err:
            return None, err
        data, err = _deps_command(["check", *packages])
        if err:
            return None, err

    entries = _entries_from(data, packages)
    save_plugin_entries(entries)
    return entries, None


def recheck_postfix() -> dict | None:
    """Scoped re-check after a Postfix-dependent operation failed at
    runtime: checks postfix ONLY (never the whole plugin list) and
    updates only its settings.json entry. Returns postfix's fresh entry,
    or None when even the re-check could not reach the manager."""
    data, err = _deps_command(["check", "postfix"])
    if err:
        return None
    entries = _entries_from(data, ["postfix"])
    save_plugin_entries(entries)
    return entries["postfix"]
