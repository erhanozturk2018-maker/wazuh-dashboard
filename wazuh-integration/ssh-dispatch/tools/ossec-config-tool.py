#!/usr/bin/env python3
"""
~/usr/local/bin/ossec-config-tool.py

Tool to programmatically list / read / edit / add / delete
<email_alerts> and <integration> blocks in the Wazuh manager's
/var/ossec/etc/ossec.conf file.

Usage:
    ossec-config-tool.py list <block_type>
    ossec-config-tool.py get <block_type> <id>
    ossec-config-tool.py add <block_type> <json>
    ossec-config-tool.py update <block_type> <id> <json>
    ossec-config-tool.py delete integration <name>
    ossec-config-tool.py delete email_alerts <id> <confirm_email_to>
    ossec-config-tool.py delete decoder_file|rule_file <name>

block_type: "email_alerts" | "integration" | "localfile"
            | "decoder_file" | "rule_file"   (custom XML files, see below)

localfile: the Logcollector's <localfile> entries (standard layout: the
SECOND <ossec_config> block). Keyed by "location"; update cannot change
it (delete + add instead).

FILE-BACKED KINDS (decoder_file / rule_file): these are NOT ossec.conf
blocks - they are the individually-named XML files under
/var/ossec/etc/decoders/ and /var/ossec/etc/rules/. They reuse the same
verbs so the wrapper's mutating-action restart and the dashboard's
existing senders apply unchanged:
    list  decoder_file                       -> [{"_id": name, "name", "content"}]
    get   decoder_file <name>
    add   decoder_file {"name": ..., "content": "<xml>"}   (fails if exists)
    update decoder_file <name> {"content": "<xml>"}        (create-or-overwrite)
    delete decoder_file <name>
Submitted content is validated for XML WELL-FORMEDNESS only (wrapped in a
fake <root>, since these files hold multiple top-level <decoder>/<rule>
elements with no shared root) - Wazuh rule/decoder semantics are not
checked here.

IMPORTANT: ossec.conf has more than one <ossec_config> root element
(it does not follow the single-root XML rule). Because of this we
first wrap the file in a fake <root> element before handing it to
lxml. On write, this wrapper is stripped and the original
<ossec_config> blocks (along with the comments/whitespace between
them) are written back out unchanged.

SECURITY NOTES:
- An integration block is uniquely identified by its "name" field.
  add/update/delete use this field as the key. update CANNOT change
  "name" (use delete + add to rename).
- An email_alerts block has no natural unique field, so when "list"
  is called, a zero-based SEQUENCE NUMBER (index) is used as the
  identifier. This ID is TEMPORARY - it depends on the file's current
  ordering. Because of this, confirm the current ID with "list" right
  before running update/delete, AND you must also supply the block's
  current email_to value ("_confirm_email_to") to the update/delete
  command - if it doesn't match, the operation is REJECTED FOR SAFETY.
- Before every write operation, a backup of the original file is
  taken as /var/ossec/etc/ossec.conf.bak.<timestamp>.
"""

import sys
import os
import json
import re
import shutil
import time
from lxml import etree

CONFIG_PATH = "/var/ossec/etc/ossec.conf"
DECODERS_DIR = "/var/ossec/etc/decoders"
RULES_DIR = "/var/ossec/etc/rules"

# Defines which sub-elements are read/written for each block_type.
# "key_field": what we naturally identify this block type by.
#   email_alerts -> no natural unique field, index/order will be used (key_field=None)
#   integration  -> the name field is already unique, key_field="name"
BLOCK_SPECS = {
    "email_alerts": {
        "fields": [
            "email_to", "level", "rules_group", "rule_id",
            "event_location", "do_not_delay", "do_not_group",
        ],
        "key_field": None,
        "required": ["email_to"],
    },
    "integration": {
        "fields": [
            "name", "hook_url", "api_key", "alert_format",
            "rule_id", "level", "group", "event_location", "options",
        ],
        "key_field": "name",
        "required": ["name", "alert_format"],
    },
    # <localfile> entries in the SECOND <ossec_config> block (the one
    # Logcollector reads). Keyed by "location" - update cannot change it
    # (delete + add instead), same rule as integration's "name".
    "localfile": {
        "fields": [
            "location", "log_format", "command", "alias",
            "frequency", "only-future-events",
        ],
        "key_field": "location",
        "required": ["location", "log_format"],
    },
}

# Self-closing empty tags (they indicate PRESENCE/ABSENCE, not a value)
SELF_CLOSING_FIELDS = {"do_not_delay", "do_not_group"}

# For integration, extra required fields depending on name (from BOLUM 4 / SECTION 4 notes)
INTEGRATION_REQUIRES_HOOK_URL = {"slack", "shuffle", "maltiverse"}
INTEGRATION_REQUIRES_API_KEY = {"pagerduty", "virustotal", "maltiverse"}


# ----------------------------------------------------------------------
# FILE READING / WRITING
# ----------------------------------------------------------------------

def load_wrapped_tree(path=CONFIG_PATH):
    """
    Reads the file and returns it as an Element tree wrapped in a fake
    <root> and parsed with lxml. Parser settings are set up to preserve
    comments and formatting as much as possible.
    """
    with open(path, "rb") as f:
        raw = f.read()

    wrapped = b"<root>" + raw + b"</root>"

    parser = etree.XMLParser(
        remove_blank_text=False,
        strip_cdata=False,
        resolve_entities=False,
    )
    root = etree.fromstring(wrapped, parser=parser)
    return root


# How many .bak.<timestamp> files to keep per base path. Older ones are
# deleted after every new backup so the config directory never accumulates
# an unbounded backup history.
MAX_BACKUPS = 5


def rotate_backups(path, keep=MAX_BACKUPS):
    """Deletes all but the `keep` most recent `<path>.bak.<timestamp>`
    files. Sorted by the timestamp embedded in the filename (already
    lexicographically ordered), not filesystem mtime."""
    directory = os.path.dirname(path) or "."
    prefix = os.path.basename(path) + ".bak."
    names = [n for n in os.listdir(directory) if n.startswith(prefix)]
    names.sort(key=lambda n: n[len(prefix):])
    for name in names[:-keep] if keep else names:
        try:
            os.remove(os.path.join(directory, name))
        except OSError:
            pass


def backup_config(path=CONFIG_PATH):
    """Takes a timestamped backup of the original file before writing,
    then drops backups beyond the MAX_BACKUPS most recent."""
    ts = time.strftime("%Y%m%d-%H%M%S")
    backup_path = f"{path}.bak.{ts}"
    shutil.copy2(path, backup_path)
    rotate_backups(path)
    return backup_path


def save_wrapped_tree(root, path=CONFIG_PATH):
    """
    Strips the fake <root> wrapper and writes the original <ossec_config>
    blocks it contains back to the file, IN ORDER (including the
    comments/whitespace between them). A backup is taken before writing.
    """
    backup_path = backup_config(path)

    parts = [root.text or ""]
    for node in root:
        parts.append(etree.tostring(node, encoding="unicode"))
    content = "".join(parts)

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

    return backup_path


# ----------------------------------------------------------------------
# SHARED HELPER FUNCTIONS
# ----------------------------------------------------------------------

def element_to_dict(el, fields):
    """
    Converts an <email_alerts> or <integration> element, along with the
    sub-fields we care about, into a flat dict.
    """
    result = {}
    for field in fields:
        child = el.find(field)
        if child is None:
            continue
        if field in SELF_CLOSING_FIELDS:
            result[field] = True
        else:
            result[field] = (child.text or "").strip()
    return result


def get_global_email_alert_level(root):
    """
    Reads the <alerts><email_alert_level> value (if present). Used to
    warn the user when adding/updating email_alerts blocks if a block's
    own level is below this global floor.
    """
    for alerts_el in root.iter("alerts"):
        lvl_el = alerts_el.find("email_alert_level")
        if lvl_el is not None and (lvl_el.text or "").strip():
            try:
                return int(lvl_el.text.strip())
            except ValueError:
                continue
    return None


def fail(msg):
    print(json.dumps({"error": msg}, ensure_ascii=False))
    sys.exit(1)


def warn(msg):
    print(f"WARNING: {msg}", file=sys.stderr)


# ----------------------------------------------------------------------
# INTEGRATION - helpers
# ----------------------------------------------------------------------

def integration_find_by_name(root, name):
    for el in root.iter("integration"):
        name_el = el.find("name")
        if name_el is not None and (name_el.text or "").strip() == name:
            return el
    return None


def integration_build_element(data):
    new_el = etree.Element("integration")
    new_el.text = "\n    "
    fields = BLOCK_SPECS["integration"]["fields"]
    for field in fields:
        if field in data and data[field] not in (None, ""):
            child = etree.SubElement(new_el, field)
            child.text = str(data[field])
            child.tail = "\n    "
    if len(new_el):
        new_el[-1].tail = "\n  "
    new_el.tail = "\n\n"
    return new_el


def integration_validate(data, *, is_new):
    name = data.get("name")
    if is_new and not name:
        return "name field is required"
    if is_new and not data.get("alert_format"):
        return "alert_format field is required"
    if name in INTEGRATION_REQUIRES_HOOK_URL and not data.get("hook_url"):
        return f"hook_url is required for the '{name}' integration"
    if name in INTEGRATION_REQUIRES_API_KEY and not data.get("api_key"):
        return f"api_key is required for the '{name}' integration"
    return None


def integration_insertion_parent(root):
    """The most sensible place to insert a new integration block."""
    existing = list(root.iter("integration"))
    if existing:
        last = existing[-1]
        parent = last.getparent()
        idx = list(parent).index(last)
        return parent, idx + 1
    ossec_configs = root.findall("ossec_config")
    if not ossec_configs:
        return None, None
    parent = ossec_configs[-1]
    return parent, len(parent)


# ----------------------------------------------------------------------
# LOCALFILE - helpers (Logcollector entries, keyed by location)
# ----------------------------------------------------------------------

def localfile_find_by_location(root, location):
    for el in root.iter("localfile"):
        loc_el = el.find("location")
        if loc_el is not None and (loc_el.text or "").strip() == location:
            return el
    return None


def localfile_build_element(data):
    new_el = etree.Element("localfile")
    new_el.text = "\n    "
    for field in BLOCK_SPECS["localfile"]["fields"]:
        if field in data and data[field] not in (None, ""):
            child = etree.SubElement(new_el, field)
            child.text = str(data[field])
            child.tail = "\n    "
    if len(new_el):
        new_el[-1].tail = "\n  "
    new_el.tail = "\n\n"
    return new_el


def localfile_insertion_parent(root):
    """Where to insert a new localfile block:
    1) next to the last existing <localfile>, if any exist
    2) otherwise, into the SECOND <ossec_config> root - the standard
       layout puts Logcollector's config there
    3) with a single-root file, fall back to that root."""
    existing = list(root.iter("localfile"))
    if existing:
        last = existing[-1]
        parent = last.getparent()
        idx = list(parent).index(last)
        return parent, idx + 1
    ossec_configs = root.findall("ossec_config")
    if not ossec_configs:
        return None, None
    parent = ossec_configs[1] if len(ossec_configs) >= 2 else ossec_configs[-1]
    return parent, len(parent)


# ----------------------------------------------------------------------
# EMAIL_ALERTS - helpers
# ----------------------------------------------------------------------

def email_alerts_all(root):
    return list(root.iter("email_alerts"))


def email_alerts_by_index(root, idx):
    blocks = email_alerts_all(root)
    if idx < 0 or idx >= len(blocks):
        return None
    return blocks[idx]


def email_alerts_build_element(data):
    new_el = etree.Element("email_alerts")
    new_el.text = "\n    "
    fields = BLOCK_SPECS["email_alerts"]["fields"]
    for field in fields:
        if field in SELF_CLOSING_FIELDS:
            if data.get(field):
                child = etree.SubElement(new_el, field)
                child.tail = "\n    "
        elif field in data and data[field] not in (None, ""):
            child = etree.SubElement(new_el, field)
            child.text = str(data[field])
            child.tail = "\n    "
    if len(new_el):
        new_el[-1].tail = "\n  "
    new_el.tail = "\n\n"
    return new_el


def email_alerts_insertion_parent(root):
    """
    Where to insert a new email_alerts block:
    1) next to the last existing email_alerts block, if any exist
    2) otherwise, next to the <global> block that holds the mail settings
    3) otherwise, at the end of the first <ossec_config> root
    """
    existing = email_alerts_all(root)
    if existing:
        last = existing[-1]
        parent = last.getparent()
        idx = list(parent).index(last)
        return parent, idx + 1

    for g in root.iter("global"):
        if g.find("email_notification") is not None:
            parent = g.getparent()
            idx = list(parent).index(g)
            return parent, idx + 1

    ossec_configs = root.findall("ossec_config")
    if not ossec_configs:
        return None, None
    parent = ossec_configs[0]
    return parent, len(parent)


def email_alerts_check_confirm(el, confirm_value, idx):
    current_to_el = el.find("email_to")
    current_to = (current_to_el.text or "").strip() if current_to_el is not None else ""
    if not confirm_value:
        return (
            "for safety, the '_confirm_email_to' (update) or confirm_email_to "
            "(delete) field is required - it confirms which email_to this ID belongs to"
        )
    if confirm_value != current_to:
        return (
            f"safety confirmation failed: for id {idx} the current email_to='{current_to}' "
            f"but the given value was='{confirm_value}' - the ID may have shifted, "
            f"re-check the current state with 'list' first"
        )
    return None


# ----------------------------------------------------------------------
# CUSTOM DECODER/RULE FILES (/var/ossec/etc/decoders|rules/*.xml)
# ----------------------------------------------------------------------

FILE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.xml$")


def file_kind_dir(kind):
    """Directory owning a file-backed kind, or None for ossec.conf block
    types. Reads the module globals at call time so tests can redirect
    DECODERS_DIR/RULES_DIR."""
    if kind == "decoder_file":
        return DECODERS_DIR
    if kind == "rule_file":
        return RULES_DIR
    return None


def validate_custom_file_name(name):
    """Bare .xml file name only - no path separators, no traversal."""
    if not FILE_NAME_RE.match(name) or ".." in name:
        return (
            "invalid file name: letters/digits/dot/dash/underscore only, "
            "must end with .xml, no path components"
        )
    return None


def validate_custom_xml(content):
    """WELL-FORMEDNESS check only. These files hold multiple top-level
    <decoder>/<rule> elements with no shared root (same 'invalid but
    tolerated' style as ossec.conf), so they are wrapped in a fake <root>
    before parsing. Wazuh semantics are deliberately not validated."""
    if not content.strip():
        return "content cannot be empty"
    parser = etree.XMLParser(
        remove_blank_text=False, strip_cdata=False, resolve_entities=False,
    )
    try:
        etree.fromstring(b"<root>" + content.encode("utf-8") + b"</root>", parser=parser)
    except etree.XMLSyntaxError as e:
        return f"content is not well-formed XML: {e}"
    return None


def custom_file_write(kind, name, content):
    """Writes (create-or-overwrite) one custom file. An existing file is
    backed up first (same .bak.<timestamp> + rotation as ossec.conf);
    returns the backup path or None for a brand-new file."""
    directory = file_kind_dir(kind)
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, name)
    backup_path = backup_config(path) if os.path.exists(path) else None
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    try:
        # match Wazuh's own custom-file conventions; harmless where the
        # wazuh group doesn't exist (dev machines)
        shutil.chown(path, group="wazuh")
        os.chmod(path, 0o640)
    except (LookupError, OSError, NotImplementedError):
        pass
    return backup_path


def cmd_list_files(kind):
    directory = file_kind_dir(kind)
    entries = []
    if os.path.isdir(directory):
        for name in sorted(os.listdir(directory)):
            path = os.path.join(directory, name)
            if not name.endswith(".xml") or not os.path.isfile(path):
                continue
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            entries.append({"_id": name, "name": name, "content": content})
    print(json.dumps(entries, ensure_ascii=False, indent=2))


def cmd_get_file(kind, name):
    err = validate_custom_file_name(name)
    if err:
        fail(err)
    path = os.path.join(file_kind_dir(kind), name)
    if not os.path.isfile(path):
        fail(f"id not found: {name}")
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    print(json.dumps({"_id": name, "name": name, "content": content},
                     ensure_ascii=False, indent=2))


def cmd_add_file(kind, json_str):
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        fail(f"invalid json: {e}")
    name = data.get("name") or ""
    content = data.get("content") or ""
    err = validate_custom_file_name(name) or validate_custom_xml(content)
    if err:
        fail(err)
    if os.path.exists(os.path.join(file_kind_dir(kind), name)):
        fail(f"a {kind} named '{name}' already exists - use update to overwrite it")
    custom_file_write(kind, name, content)
    print(json.dumps({
        "status": "added", "block_type": kind, "_id": name, "backup": None,
    }, ensure_ascii=False, indent=2))


def cmd_update_file(kind, name, json_str):
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        fail(f"invalid json: {e}")
    content = data.get("content") or ""
    err = validate_custom_file_name(name) or validate_custom_xml(content)
    if err:
        fail(err)
    backup_path = custom_file_write(kind, name, content)
    print(json.dumps({
        "status": "updated", "block_type": kind, "_id": name, "backup": backup_path,
    }, ensure_ascii=False, indent=2))


def cmd_delete_file(kind, name):
    err = validate_custom_file_name(name)
    if err:
        fail(err)
    path = os.path.join(file_kind_dir(kind), name)
    if not os.path.isfile(path):
        fail(f"id not found: {name}")
    backup_path = backup_config(path)
    os.remove(path)
    print(json.dumps({
        "status": "deleted", "block_type": kind, "_id": name, "backup": backup_path,
    }, ensure_ascii=False, indent=2))


# ----------------------------------------------------------------------
# COMMANDS: list / get  (unchanged)
# ----------------------------------------------------------------------

def cmd_list(block_type):
    if file_kind_dir(block_type):
        return cmd_list_files(block_type)
    spec = BLOCK_SPECS.get(block_type)
    if spec is None:
        fail(f"unknown block_type: {block_type}")

    root = load_wrapped_tree()
    blocks = root.iter(block_type)

    output = []
    for idx, el in enumerate(blocks):
        entry = element_to_dict(el, spec["fields"])
        if spec["key_field"] is None:
            entry["_id"] = idx
        else:
            entry["_id"] = entry.get(spec["key_field"])
        output.append(entry)

    print(json.dumps(output, ensure_ascii=False, indent=2))


def cmd_get(block_type, block_id):
    if file_kind_dir(block_type):
        return cmd_get_file(block_type, block_id)
    spec = BLOCK_SPECS.get(block_type)
    if spec is None:
        fail(f"unknown block_type: {block_type}")

    root = load_wrapped_tree()
    blocks = list(root.iter(block_type))

    if spec["key_field"] is None:
        try:
            idx = int(block_id)
            el = blocks[idx]
        except (ValueError, IndexError):
            fail(f"id not found: {block_id}")
        entry = element_to_dict(el, spec["fields"])
        entry["_id"] = idx
    else:
        el = None
        for candidate in blocks:
            name_el = candidate.find(spec["key_field"])
            if name_el is not None and (name_el.text or "").strip() == block_id:
                el = candidate
                break
        if el is None:
            fail(f"id not found: {block_id}")
        entry = element_to_dict(el, spec["fields"])
        entry["_id"] = block_id

    print(json.dumps(entry, ensure_ascii=False, indent=2))


# ----------------------------------------------------------------------
# COMMAND: add
# ----------------------------------------------------------------------

def cmd_add(block_type, json_str):
    if file_kind_dir(block_type):
        return cmd_add_file(block_type, json_str)
    if block_type not in BLOCK_SPECS:
        fail(f"unknown block_type: {block_type}")

    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        fail(f"invalid json: {e}")

    root = load_wrapped_tree()

    if block_type == "integration":
        err = integration_validate(data, is_new=True)
        if err:
            fail(err)
        if integration_find_by_name(root, data["name"]) is not None:
            fail(f"an integration named '{data['name']}' already exists, names must be unique")

        new_el = integration_build_element(data)
        parent, pos = integration_insertion_parent(root)
        if parent is None:
            fail("ossec_config root element not found, file structure is different than expected")
        parent.insert(pos, new_el)

    elif block_type == "localfile":
        for field in BLOCK_SPECS["localfile"]["required"]:
            if not data.get(field):
                fail(f"{field} field is required")
        if localfile_find_by_location(root, data["location"]) is not None:
            fail(f"a localfile with location '{data['location']}' already exists")

        new_el = localfile_build_element(data)
        parent, pos = localfile_insertion_parent(root)
        if parent is None:
            fail("ossec_config root element not found, file structure is different than expected")
        parent.insert(pos, new_el)

    else:  # email_alerts
        if not data.get("email_to"):
            fail("email_to field is required")

        global_level = get_global_email_alert_level(root)
        if global_level is not None and "level" in data:
            try:
                if int(data["level"]) < global_level:
                    warn(
                        f"level={data['level']} is lower than the global email_alert_level={global_level} "
                        f"- this block will never trigger"
                    )
            except (TypeError, ValueError):
                pass

        new_el = email_alerts_build_element(data)
        parent, pos = email_alerts_insertion_parent(root)
        if parent is None:
            fail("ossec_config root element not found, file structure is different than expected")
        parent.insert(pos, new_el)

    backup_path = save_wrapped_tree(root)
    print(json.dumps({
        "status": "added",
        "block_type": block_type,
        "backup": backup_path,
    }, ensure_ascii=False, indent=2))


# ----------------------------------------------------------------------
# COMMAND: update
# ----------------------------------------------------------------------

def cmd_update(block_type, block_id, json_str):
    if file_kind_dir(block_type):
        return cmd_update_file(block_type, block_id, json_str)
    if block_type not in BLOCK_SPECS:
        fail(f"unknown block_type: {block_type}")

    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as e:
        fail(f"invalid json: {e}")

    root = load_wrapped_tree()

    if block_type == "integration":
        el = integration_find_by_name(root, block_id)
        if el is None:
            fail(f"id not found: {block_id}")
        if "name" in data and data["name"] != block_id:
            fail("the integration 'name' field cannot be changed via update; use delete + add")

        err = integration_validate({**{"name": block_id}, **data}, is_new=False)
        if err:
            fail(err)

        for field in BLOCK_SPECS["integration"]["fields"]:
            if field == "name" or field not in data:
                continue
            value = data[field]
            child = el.find(field)
            if value in (None, ""):
                if child is not None:
                    el.remove(child)
            else:
                if child is None:
                    child = etree.SubElement(el, field)
                    child.tail = "\n    "
                child.text = str(value)

    elif block_type == "localfile":
        el = localfile_find_by_location(root, block_id)
        if el is None:
            fail(f"id not found: {block_id}")
        if "location" in data and data["location"] != block_id:
            fail("the localfile 'location' field cannot be changed via update; use delete + add")

        for field in BLOCK_SPECS["localfile"]["fields"]:
            if field == "location" or field not in data:
                continue
            value = data[field]
            child = el.find(field)
            if value in (None, ""):
                if child is not None:
                    el.remove(child)
            else:
                if child is None:
                    child = etree.SubElement(el, field)
                    child.tail = "\n    "
                child.text = str(value)

    else:  # email_alerts
        try:
            idx = int(block_id)
        except ValueError:
            fail(f"id must be numeric: {block_id}")

        el = email_alerts_by_index(root, idx)
        if el is None:
            fail(f"id not found: {idx}")

        confirm_err = email_alerts_check_confirm(el, data.get("_confirm_email_to"), idx)
        if confirm_err:
            fail(confirm_err)

        global_level = get_global_email_alert_level(root)
        if global_level is not None and "level" in data:
            try:
                if int(data["level"]) < global_level:
                    warn(
                        f"level={data['level']} is lower than the global email_alert_level={global_level} "
                        f"- this block will never trigger"
                    )
            except (TypeError, ValueError):
                pass

        for field in BLOCK_SPECS["email_alerts"]["fields"]:
            if field not in data:
                continue
            value = data[field]
            child = el.find(field)
            if field in SELF_CLOSING_FIELDS:
                if value and child is None:
                    etree.SubElement(el, field).tail = "\n    "
                elif not value and child is not None:
                    el.remove(child)
            else:
                if value in (None, ""):
                    if child is not None:
                        el.remove(child)
                else:
                    if child is None:
                        child = etree.SubElement(el, field)
                        child.tail = "\n    "
                    child.text = str(value)

    backup_path = save_wrapped_tree(root)
    print(json.dumps({
        "status": "updated",
        "block_type": block_type,
        "_id": block_id,
        "backup": backup_path,
    }, ensure_ascii=False, indent=2))


# ----------------------------------------------------------------------
# COMMAND: delete
# ----------------------------------------------------------------------

def cmd_delete(block_type, args):
    if file_kind_dir(block_type):
        if len(args) != 1:
            fail(f"usage: delete {block_type} <name>")
        return cmd_delete_file(block_type, args[0])
    root = load_wrapped_tree()

    if block_type == "integration":
        if len(args) != 1:
            fail("usage: delete integration <name>")
        name = args[0]
        el = integration_find_by_name(root, name)
        if el is None:
            fail(f"id not found: {name}")
        el.getparent().remove(el)
        block_id = name

    elif block_type == "localfile":
        if len(args) != 1:
            fail("usage: delete localfile <location>")
        location = args[0]
        el = localfile_find_by_location(root, location)
        if el is None:
            fail(f"id not found: {location}")
        el.getparent().remove(el)
        block_id = location

    elif block_type == "email_alerts":
        if len(args) != 2:
            fail("usage: delete email_alerts <id> <confirm_email_to>")
        try:
            idx = int(args[0])
        except ValueError:
            fail(f"id must be numeric: {args[0]}")
        confirm_email_to = args[1]

        el = email_alerts_by_index(root, idx)
        if el is None:
            fail(f"id not found: {idx}")

        confirm_err = email_alerts_check_confirm(el, confirm_email_to, idx)
        if confirm_err:
            fail(confirm_err)

        el.getparent().remove(el)
        block_id = idx

    else:
        fail(f"unknown block_type: {block_type}")

    backup_path = save_wrapped_tree(root)
    print(json.dumps({
        "status": "deleted",
        "block_type": block_type,
        "_id": block_id,
        "backup": backup_path,
    }, ensure_ascii=False, indent=2))


# ----------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        fail("no command specified (list/get/add/update/delete)")

    command = sys.argv[1]

    if command == "list":
        if len(sys.argv) != 3:
            fail("usage: list <block_type>")
        cmd_list(sys.argv[2])

    elif command == "get":
        if len(sys.argv) != 4:
            fail("usage: get <block_type> <id>")
        cmd_get(sys.argv[2], sys.argv[3])

    elif command == "add":
        if len(sys.argv) != 4:
            fail("usage: add <block_type> <json>")
        cmd_add(sys.argv[2], sys.argv[3])

    elif command == "update":
        if len(sys.argv) != 5:
            fail("usage: update <block_type> <id> <json>")
        cmd_update(sys.argv[2], sys.argv[3], sys.argv[4])

    elif command == "delete":
        if len(sys.argv) < 4:
            fail("usage: delete integration <name> | delete email_alerts <id> <confirm_email_to>")
        cmd_delete(sys.argv[2], sys.argv[3:])

    else:
        fail(f"unknown command: {command}")


if __name__ == "__main__":
    main()