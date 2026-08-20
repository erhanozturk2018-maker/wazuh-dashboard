#!/usr/bin/env python3
"""
~/usr/local/bin/dependency_manager_tool.py

Generic system-dependency ("plugin") checker/installer for the dashboard's
Manage Plugins flow. Deliberately its own tool - NOT folded into
rsyslog-config-tool.py or mail_config_tool.py - because it covers
dependencies for multiple, unrelated features (rsyslog for log
forwarding, postfix for mail relay).

Usage:
    dependency_manager_tool.py check <package> [<package> ...]
    dependency_manager_tool.py install <package> [<package> ...]

`check` uses `dpkg -s <package>` (install status + the Version: line);
`install` runs `apt-get install -y` for whatever is missing, then
re-checks. Both print:

    {"error": 0, "data": {"<package>": {"installed": bool, "version": str|null}}}

and exit non-zero with {"error": 1, "message": ...} on failure (the
same numeric-envelope convention every tool this wrapper dispatches to
uses).

SECURITY NOTE: package names are restricted to ALLOWED_PACKAGES. This
tool is reachable through the SSH forced command with root sudo - an
open-ended `apt-get install <anything>` would widen the blast radius far
beyond what the dashboard needs. Extending the list is a deliberate,
reviewed change (docs/security/ssh-boundary.md).

Dispatched by config-router-wrapper.sh via the "deps" selector; neither
subcommand triggers the wrapper's service restart (check/install are not
add/update/delete).
"""

import json
import os
import subprocess
import sys

ALLOWED_PACKAGES = ("rsyslog", "postfix")


def _run(cmd, env=None):
    """Runs a command, returns (exit_code, stdout, stderr)."""
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300, env=env)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def fail(message, code=1):
    print(json.dumps({"error": code, "message": message}))
    sys.exit(code)


def _validate_packages(packages):
    if not packages:
        fail("no package names given")
    for name in packages:
        if name not in ALLOWED_PACKAGES:
            fail(
                f"package '{name}' is not in the allowed list "
                f"({', '.join(ALLOWED_PACKAGES)})"
            )


def check_package(name):
    """{"installed": bool, "version": str|None} from `dpkg -s`."""
    code, out, err = _run(["dpkg", "-s", name])
    if code != 0:
        # dpkg -s exits non-zero for a package it has never seen
        return {"installed": False, "version": None}

    installed = False
    version = None
    for line in out.splitlines():
        if line.startswith("Status:"):
            # "Status: install ok installed" vs "deinstall ok config-files"
            installed = line.strip().endswith("installed")
        elif line.startswith("Version:"):
            version = line.split(":", 1)[1].strip()
    return {"installed": installed, "version": version if installed else None}


def cmd_check(packages):
    _validate_packages(packages)
    data = {name: check_package(name) for name in packages}
    print(json.dumps({"error": 0, "data": data}, ensure_ascii=False))


def cmd_install(packages):
    _validate_packages(packages)

    missing = [name for name in packages if not check_package(name)["installed"]]
    if missing:
        env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
        code, out, err = _run(["apt-get", "install", "-y", *missing], env=env)
        if code != 0:
            fail(f"apt-get install failed for {' '.join(missing)} (exit {code}): {err or out}")

    data = {name: check_package(name) for name in packages}
    print(json.dumps({"error": 0, "data": data}, ensure_ascii=False))


def main():
    if len(sys.argv) < 3:
        fail("usage: check <package> [...] | install <package> [...]")

    command = sys.argv[1]
    packages = sys.argv[2:]

    if command == "check":
        cmd_check(packages)
    elif command == "install":
        cmd_install(packages)
    else:
        fail(f"unknown command: {command} (use 'check' or 'install')")


if __name__ == "__main__":
    main()
