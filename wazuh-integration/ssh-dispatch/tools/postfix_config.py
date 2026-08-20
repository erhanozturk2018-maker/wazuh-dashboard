#!/usr/bin/env python3
"""
~/usr/local/bin/postfix_config.py

Owns the two Postfix-side files behind the dashboard's mail settings:

    /etc/postfix/main.cf      Postfix's own "key = value" text format;
                              only the `relayhost` line is managed here.
    /etc/postfix/sasl_passwd  one "relayhost  username:password" line.
                              This file does NOT ship with Postfix - and
                              it MUST be recompiled with `postmap` after
                              every write, or Postfix keeps reading the
                              old, stale sasl_passwd.db.

This module is NOT an SSH dispatch target: it is only ever imported by
mail_config_tool.py, never invoked directly (no sudoers entry, no
config-router-wrapper.sh selector). Plain functions, matching the style
of the other tools/ scripts.

Every write backs up both files first (same `.bak.<timestamp>` naming and
5-backup rotation as ossec-config-tool.py - reused from there, not
duplicated) and, if `postmap` or `postfix check` then fails, restores
both files from those fresh backups so no half-applied state survives.
"""

import importlib.util
import os
import re
import shutil
import subprocess

MAIN_CF = "/etc/postfix/main.cf"
SASL_PASSWD = "/etc/postfix/sasl_passwd"

RELAYHOST_RE = re.compile(r"^relayhost\s*=\s*(.*)$")

# Reuse the backup + rotation helpers from ossec-config-tool.py. The file
# name is hyphenated so a normal import is impossible; it sits in the same
# directory as this module both in-repo (tools/) and deployed
# (/usr/local/bin), so load it by path.
_TOOL_DIR = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "ossec_config_tool", os.path.join(_TOOL_DIR, "ossec-config-tool.py")
)
_ossec_config_tool = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_ossec_config_tool)

backup_file = _ossec_config_tool.backup_config  # copy2 + 5-backup rotation


def _run(cmd):
    """Runs a command, returns (exit_code, stdout, stderr). Split out so
    tests can stub the postmap/postfix binaries."""
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


# ----------------------------------------------------------------------
# READ
# ----------------------------------------------------------------------

def read_relayhost(path=None):
    """Current `relayhost` value from main.cf ("" when the line is absent)."""
    path = path or MAIN_CF
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            m = RELAYHOST_RE.match(line.strip())
            if m:
                return m.group(1).strip()
    return ""


def _first_sasl_line(path):
    """First non-comment, non-blank line of sasl_passwd ("" if none)."""
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                return stripped
    return ""


def read_sasl_user(path=None):
    """The username half of sasl_passwd's "relayhost  user:pass" line."""
    line = _first_sasl_line(path or SASL_PASSWD)
    parts = line.split()
    if len(parts) < 2:
        return ""
    return parts[1].split(":", 1)[0]


def read_sasl_password(path=None):
    """The password half of sasl_passwd's "relayhost  user:pass" line.
    Used to preserve the existing password when an update supplies none."""
    line = _first_sasl_line(path or SASL_PASSWD)
    parts = line.split()
    if len(parts) < 2:
        return ""
    cred = parts[1]
    return cred.split(":", 1)[1] if ":" in cred else ""


# ----------------------------------------------------------------------
# WRITE
# ----------------------------------------------------------------------

def _write_relayhost(relayhost, path):
    """Replaces every existing `relayhost = ...` line, or appends one."""
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    replaced = False
    for i, line in enumerate(lines):
        if RELAYHOST_RE.match(line.strip()):
            lines[i] = f"relayhost = {relayhost}\n"
            replaced = True
    if not replaced:
        if lines and not lines[-1].endswith("\n"):
            lines[-1] += "\n"
        lines.append(f"relayhost = {relayhost}\n")

    with open(path, "w", encoding="utf-8") as f:
        f.writelines(lines)


def update_postfix_settings(relayhost, sasl_user, sasl_pass=None,
                            main_cf_path=None, sasl_passwd_path=None):
    """Applies the Postfix half of a mail-settings update.

    Backs up both files, rewrites main.cf's relayhost and the sasl_passwd
    line, recompiles the map (`postmap`) and sanity-checks the whole
    Postfix config (`postfix check`). If sasl_pass is empty/None the
    current password is read out of sasl_passwd first and preserved. On
    any failure after the backups, both files are restored from them and
    RuntimeError is raised - the caller (mail_config_tool.py) turns that
    into the JSON error convention.
    """
    main_cf_path = main_cf_path or MAIN_CF
    sasl_passwd_path = sasl_passwd_path or SASL_PASSWD

    password = sasl_pass if sasl_pass else read_sasl_password(sasl_passwd_path)

    main_cf_backup = backup_file(main_cf_path)
    sasl_backup = backup_file(sasl_passwd_path)

    try:
        _write_relayhost(relayhost, main_cf_path)

        with open(sasl_passwd_path, "w", encoding="utf-8") as f:
            f.write(f"{relayhost}  {sasl_user}:{password}\n")
        os.chmod(sasl_passwd_path, 0o600)

        code, out, err = _run(["postmap", sasl_passwd_path])
        if code != 0:
            raise RuntimeError(f"postmap failed (exit {code}): {err or out}")

        code, out, err = _run(["postfix", "check"])
        if code != 0:
            raise RuntimeError(f"postfix check failed (exit {code}): {err or out}")
    except Exception:
        # roll both files back to their just-taken backups - never leave a
        # rewritten sasl_passwd next to a stale .db, or a half-updated pair
        shutil.copy2(main_cf_backup, main_cf_path)
        shutil.copy2(sasl_backup, sasl_passwd_path)
        raise

    return {"main_cf_backup": main_cf_backup, "sasl_passwd_backup": sasl_backup}
