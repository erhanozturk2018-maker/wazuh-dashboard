#!/usr/bin/env python3
"""
~/usr/local/bin/mail_config_tool.py

Python replacement for the old mail-config-tool.sh - same CLI contract:

    mail_config_tool.py read
    mail_config_tool.py update EMAIL_TO EMAIL_FROM SMTP_SERVER MAXPERHOUR RELAYHOST SASL_USER SASL_PASS

Dispatched by config-router-wrapper.sh via the "mail" selector (the
wrapper's central restart still fires after a successful "update", exactly
as before). Prints a single JSON object to stdout and exits non-zero with
{"error": "..."} on failure, like the other tools.

The ossec.conf mail fields (email_to / email_from / smtp_server /
email_maxperhour, all inside the <global> block) are edited through
ossec-config-tool.py's lxml wrap/unwrap helpers - never sed/regex; the
file has multiple <ossec_config> roots. NOTE: unlike the old bash sed
(which replaced *every* <email_to> line in the file, including the ones
inside unrelated <email_alerts> blocks), this tool only touches the
fields inside <global> - that sed behavior was a defect, not a contract.

The Postfix half (/etc/postfix/main.cf + sasl_passwd, postmap, postfix
check) is owned by postfix_config.py; this script is the only caller and
the only SSH-facing entry point of the pair.

All inputs are validated up front, BEFORE any file is touched; the
Postfix side additionally rolls itself back if postmap/postfix check
fail, so no partial write is ever left behind.
"""

import importlib.util
import json
import os
import re
import sys

OSSEC_CONF = "/var/ossec/etc/ossec.conf"

# same validation the bash version had
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

OSSEC_MAIL_FIELDS = ("email_to", "email_from", "smtp_server", "email_maxperhour")

# ossec-config-tool.py has a hyphenated filename, so load it by path; it
# sits next to this script both in-repo (tools/) and deployed
# (/usr/local/bin). postfix_config.py is loaded the same way for symmetry.
_TOOL_DIR = os.path.dirname(os.path.abspath(__file__))


def _load_sibling(filename, module_name):
    spec = importlib.util.spec_from_file_location(
        module_name, os.path.join(_TOOL_DIR, filename)
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ossec_config_tool = _load_sibling("ossec-config-tool.py", "ossec_config_tool")
postfix_config = _load_sibling("postfix_config.py", "postfix_config")


def fail(msg):
    print(json.dumps({"error": msg}, ensure_ascii=False))
    sys.exit(1)


def _first_global_field(root, tag):
    """First <tag> element inside any <global> block, or None."""
    for g in root.iter("global"):
        el = g.find(tag)
        if el is not None:
            return el
    return None


# ----------------------------------------------------------------------
# COMMAND: read
# ----------------------------------------------------------------------

def cmd_read():
    try:
        root = ossec_config_tool.load_wrapped_tree(path=OSSEC_CONF)
    except Exception as e:
        fail(f"could not parse {OSSEC_CONF}: {e}")

    def global_text(tag):
        el = _first_global_field(root, tag)
        return (el.text or "").strip() if el is not None else ""

    try:
        relayhost = postfix_config.read_relayhost()
        sasl_user = postfix_config.read_sasl_user()
        sasl_pass_set = bool(postfix_config.read_sasl_password())
    except OSError as e:
        fail(f"could not read Postfix config: {e}")

    print(json.dumps({
        "email_to": global_text("email_to"),
        "email_from": global_text("email_from"),
        "smtp_server": global_text("smtp_server"),
        "email_maxperhour": global_text("email_maxperhour"),
        "relayhost": relayhost,
        "sasl_user": sasl_user,
        "sasl_pass_set": sasl_pass_set,
        "ossec_conf_path": OSSEC_CONF,
        "main_cf_path": postfix_config.MAIN_CF,
        "sasl_passwd_path": postfix_config.SASL_PASSWD,
    }, ensure_ascii=False, indent=2))


# ----------------------------------------------------------------------
# COMMAND: update
# ----------------------------------------------------------------------

def cmd_update(email_to, email_from, smtp_server, maxperhour,
               relayhost, sasl_user, sasl_pass):
    # ---- validate EVERYTHING before writing anything (same rules as the
    # bash version) ----
    if not EMAIL_RE.match(email_to):
        fail("invalid email_to")
    if not EMAIL_RE.match(email_from):
        fail("invalid email_from")
    if not maxperhour.isdigit():
        fail("maxperhour must be a number")
    if not smtp_server:
        fail("smtp_server cannot be empty")
    if not relayhost:
        fail("relayhost cannot be empty")
    if not sasl_user:
        fail("sasl username cannot be empty")

    # parse ossec.conf up front too - if it is unreadable/corrupt we must
    # find out before the Postfix files are touched
    try:
        root = ossec_config_tool.load_wrapped_tree(path=OSSEC_CONF)
    except Exception as e:
        fail(f"could not parse {OSSEC_CONF}: {e}")
    if not list(root.iter("global")):
        fail(f"no <global> block found in {OSSEC_CONF} - file structure is different than expected")

    # ---- Postfix side first (it can roll itself back on failure) ----
    try:
        postfix_result = postfix_config.update_postfix_settings(
            relayhost, sasl_user, sasl_pass or None,
        )
    except RuntimeError as e:
        fail(str(e))
    except OSError as e:
        fail(f"could not update Postfix config: {e}")

    # ---- then the ossec.conf <global> mail fields ----
    values = {
        "email_to": email_to,
        "email_from": email_from,
        "smtp_server": smtp_server,
        "email_maxperhour": maxperhour,
    }
    first_global = next(root.iter("global"))
    for tag in OSSEC_MAIL_FIELDS:
        el = _first_global_field(root, tag)
        if el is None:
            el = ossec_config_tool.etree.SubElement(first_global, tag)
            el.tail = "\n    "
        el.text = values[tag]

    backup_path = ossec_config_tool.save_wrapped_tree(root, path=OSSEC_CONF)

    print(json.dumps({
        "status": "updated",
        "ossec_conf_backup": backup_path,
        "main_cf_backup": postfix_result["main_cf_backup"],
        "sasl_passwd_backup": postfix_result["sasl_passwd_backup"],
    }, ensure_ascii=False, indent=2))


# ----------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        fail("invalid mode. Use 'read' or 'update'")

    mode = sys.argv[1]

    if mode == "read":
        if len(sys.argv) != 2:
            fail("usage: read")
        cmd_read()
    elif mode == "update":
        if len(sys.argv) != 9:
            fail("usage: update EMAIL_TO EMAIL_FROM SMTP_SERVER MAXPERHOUR RELAYHOST SASL_USER SASL_PASS")
        cmd_update(*sys.argv[2:9])
    else:
        fail("invalid mode. Use 'read' or 'update'")


if __name__ == "__main__":
    main()
