#!/usr/bin/env python3
"""
~/usr/local/bin/rsyslog-config-tool.py

Manages the PROJECT'S OWN rsyslog rule files under /etc/rsyslog.d/ - the
`wazuh-*.conf` files (e.g. wazuh-tcp.conf) that feed logs toward the
Wazuh manager. This is deliberately NOT a general rsyslog wrapper: only
file names matching `wazuh-*.conf` are ever listed, written, or deleted,
so distro-owned files (50-default.conf etc.) are unreachable through the
SSH channel.

Usage:
    rsyslog-config-tool.py list
    rsyslog-config-tool.py get <name>
    rsyslog-config-tool.py add <json>            {"name": ..., "content": ...}  (fails if exists)
    rsyslog-config-tool.py update <name> <json>  {"content": ...}               (create-or-overwrite)
    rsyslog-config-tool.py delete <name>

Dispatched by config-router-wrapper.sh via the "rsyslog" selector; the
wrapper restarts rsyslog (not wazuh-manager/postfix) after a successful
mutating action. Same conventions as the other tools: plain functions,
one JSON object on stdout, non-zero exit + {"error": ...} on failure.
Every mutation of an existing file backs it up first (same
.bak.<timestamp> naming + 5-backup rotation as ossec-config-tool.py).
"""

import importlib.util
import json
import os
import re
import sys

RSYSLOG_DIR = "/etc/rsyslog.d"

# project-owned files only - the "wazuh-" prefix IS the ownership marker
FILE_NAME_RE = re.compile(r"^wazuh-[A-Za-z0-9._-]+\.conf$")

# Reuse the backup + rotation helpers from ossec-config-tool.py (hyphenated
# filename -> load by path; same directory in-repo and at /usr/local/bin).
_TOOL_DIR = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "ossec_config_tool", os.path.join(_TOOL_DIR, "ossec-config-tool.py")
)
_ossec_config_tool = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_ossec_config_tool)

backup_file = _ossec_config_tool.backup_config  # copy2 + 5-backup rotation


def fail(msg):
    print(json.dumps({"error": msg}, ensure_ascii=False))
    sys.exit(1)


def validate_file_name(name):
    if not FILE_NAME_RE.match(name) or ".." in name:
        return (
            "invalid file name: must match wazuh-*.conf "
            "(letters/digits/dot/dash/underscore, no path components)"
        )
    return None


def _file_path(name):
    return os.path.join(RSYSLOG_DIR, name)


# ----------------------------------------------------------------------
# COMMANDS
# ----------------------------------------------------------------------

def cmd_list():
    entries = []
    if os.path.isdir(RSYSLOG_DIR):
        for name in sorted(os.listdir(RSYSLOG_DIR)):
            path = _file_path(name)
            if not FILE_NAME_RE.match(name) or not os.path.isfile(path):
                continue
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            entries.append({"_id": name, "name": name, "content": content})
    print(json.dumps(entries, ensure_ascii=False, indent=2))


def cmd_get(name):
    err = validate_file_name(name)
    if err:
        fail(err)
    path = _file_path(name)
    if not os.path.isfile(path):
        fail(f"id not found: {name}")
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    print(json.dumps({"_id": name, "name": name, "content": content},
                     ensure_ascii=False, indent=2))


def _write_file(name, content):
    """Create-or-overwrite; backs an existing file up first. Returns the
    backup path or None for a brand-new file."""
    os.makedirs(RSYSLOG_DIR, exist_ok=True)
    path = _file_path(name)
    backup_path = backup_file(path) if os.path.exists(path) else None
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    try:
        os.chmod(path, 0o644)
    except OSError:
        pass
    return backup_path


def cmd_add(json_str):
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        fail(f"invalid json: {e}")
    name = data.get("name") or ""
    content = data.get("content") or ""
    err = validate_file_name(name)
    if err:
        fail(err)
    if not content.strip():
        fail("content cannot be empty")
    if os.path.exists(_file_path(name)):
        fail(f"an rsyslog file named '{name}' already exists - use update to overwrite it")
    _write_file(name, content)
    print(json.dumps({
        "status": "added", "_id": name, "backup": None,
    }, ensure_ascii=False, indent=2))


def cmd_update(name, json_str):
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        fail(f"invalid json: {e}")
    content = data.get("content") or ""
    err = validate_file_name(name)
    if err:
        fail(err)
    if not content.strip():
        fail("content cannot be empty")
    backup_path = _write_file(name, content)
    print(json.dumps({
        "status": "updated", "_id": name, "backup": backup_path,
    }, ensure_ascii=False, indent=2))


def cmd_delete(name):
    err = validate_file_name(name)
    if err:
        fail(err)
    path = _file_path(name)
    if not os.path.isfile(path):
        fail(f"id not found: {name}")
    backup_path = backup_file(path)
    os.remove(path)
    print(json.dumps({
        "status": "deleted", "_id": name, "backup": backup_path,
    }, ensure_ascii=False, indent=2))


# ----------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        fail("no command specified (list/get/add/update/delete)")

    command = sys.argv[1]
    args = sys.argv[2:]

    if command == "list" and len(args) == 0:
        cmd_list()
    elif command == "get" and len(args) == 1:
        cmd_get(args[0])
    elif command == "add" and len(args) == 1:
        cmd_add(args[0])
    elif command == "update" and len(args) == 2:
        cmd_update(args[0], args[1])
    elif command == "delete" and len(args) == 1:
        cmd_delete(args[0])
    else:
        fail(f"unrecognized command: {command} {args}")


if __name__ == "__main__":
    main()
