"""
Reading and editing the manager's ``ossec.conf`` through the Wazuh API.

This is the dashboard-side home of logic that used to live in
``wazuh-integration/ssh-dispatch/tools/ossec-config-tool.py``. It moved
here because the API hands us the file as raw XML and takes raw XML back
(``GET|PUT /manager/configuration``), so the parse/edit/serialize step now
belongs to whoever is holding the bytes - the dashboard.

**XML goes through lxml, never regex.** ``ossec.conf`` is not well-formed
single-root XML: it has several ``<ossec_config>`` roots and repeated
``<global>`` blocks. Everything here therefore wraps the document in a
fake ``<root>`` before parsing and strips that wrapper on the way out,
preserving the original blocks and the comments/whitespace between them.

**Backups moved, they did not disappear.** The manager-side tool wrote
``ossec.conf.bak.<timestamp>`` next to the file before every mutation. The
API offers no way to write an arbitrary file on the manager, so the same
guarantee is kept on this side instead: the pre-change document is written
under ``data/config_backups/`` before any PUT, with the same
keep-the-5-most-recent rotation. The location changed; the ability to undo
the last few changes did not.

Every public function returns ``(ok, result)`` - the same shape the SSH
senders used - so callers do not need to care which channel is underneath.
"""

import time
from pathlib import Path

from lxml import etree

from dashboard_core import config
from dashboard_core.services import manager_control, wazuh_api

CONFIG_PATH = "/manager/configuration"
VALIDATION_PATH = "/manager/configuration/validation"

# Keep the 5 most recent backups per base name - enough to undo the last
# few changes, which is the only recovery scenario these exist for.
MAX_BACKUPS = 5

# Which sub-elements are read/written per block type, and what identifies
# a block. Ported verbatim from the manager-side tool - changing these
# changes what the dashboard can express about ossec.conf.
BLOCK_SPECS = {
    "email_alerts": {
        "fields": [
            "email_to", "level", "rules_group", "rule_id",
            "event_location", "do_not_delay", "do_not_group",
        ],
        # No naturally unique field: blocks are addressed by their
        # zero-based position, which is why every mutation also demands a
        # confirmation value. See _check_email_alerts_confirm.
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
    # NOTE: a localfile has no single key field. File-based entries are
    # identified by <location>, but command/full_command entries have no
    # <location> at all - Wazuh does not require one - and are identified
    # by <alias>, or failing that by the command itself. Keying this block
    # type on "location" alone (as the previous manager-side tool did)
    # leaves every command entry unaddressable: listable, but impossible
    # to edit or delete. See localfile_key().
    "localfile": {
        "fields": [
            "location", "log_format", "command", "alias",
            "frequency", "only-future-events",
        ],
        "key_field": None,
        "required": ["log_format"],
    },
}

# log_format values whose entries describe a COMMAND to run rather than a
# file to read, and therefore carry no <location>.
COMMAND_LOG_FORMATS = {"command", "full_command"}

# Tags whose PRESENCE is the value - they carry no text.
SELF_CLOSING_FIELDS = {"do_not_delay", "do_not_group"}

INTEGRATION_REQUIRES_HOOK_URL = {"slack", "shuffle", "maltiverse"}
INTEGRATION_REQUIRES_API_KEY = {"pagerduty", "virustotal", "maltiverse"}


# ----------------------------------------------------------------------
# PARSE / SERIALIZE
# ----------------------------------------------------------------------

def parse_config(raw: str):
    """Raw ossec.conf text -> an lxml element wrapped in a fake <root>."""
    parser = etree.XMLParser(
        remove_blank_text=False, strip_cdata=False, resolve_entities=False,
    )
    return etree.fromstring(
        b"<root>" + raw.encode("utf-8") + b"</root>", parser=parser
    )


def serialize_config(root) -> str:
    """Strips the fake <root> and returns the original <ossec_config>
    blocks in order, including the text between them."""
    parts = [root.text or ""]
    for node in root:
        parts.append(etree.tostring(node, encoding="unicode"))
    return "".join(parts)


# ----------------------------------------------------------------------
# BACKUPS (dashboard-side - see the module docstring)
# ----------------------------------------------------------------------

def backup_dir() -> Path:
    directory = Path(config.DATA_DIR) / "config_backups"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def rotate_backups(prefix: str, keep: int = MAX_BACKUPS) -> None:
    """Drops all but the `keep` most recent backups for one base name.

    Sorted by the timestamp embedded in the filename rather than by
    filesystem mtime - the name is already the authoritative ordering and
    cannot be perturbed by a copy or a touch.
    """
    directory = backup_dir()
    names = sorted(
        (p for p in directory.iterdir() if p.name.startswith(prefix)),
        key=lambda p: p.name[len(prefix):],
    )
    for stale in names[:-keep] if keep else names:
        try:
            stale.unlink()
        except OSError:
            pass


def write_backup(raw: str, base_name: str = "ossec.conf") -> str:
    """Stores the pre-change document and returns the backup's path."""
    prefix = f"{base_name}.bak."
    path = backup_dir() / f"{prefix}{time.strftime('%Y%m%d-%H%M%S')}"
    path.write_text(raw, encoding="utf-8")
    rotate_backups(prefix)
    return str(path)


# ----------------------------------------------------------------------
# FETCH / PUSH
# ----------------------------------------------------------------------

def fetch_raw() -> tuple[bool, str]:
    """The manager's current ossec.conf, verbatim."""
    ok, result = wazuh_api.request("GET", f"{CONFIG_PATH}?raw=true")
    if not ok:
        return False, str(result)
    if not isinstance(result, str) or "<ossec_config>" not in result:
        return False, "The manager returned an unexpected ossec.conf payload."
    return True, result


def fetch_tree():
    """The current ossec.conf as (ok, parsed_root_or_message, raw)."""
    ok, raw = fetch_raw()
    if not ok:
        return False, raw, ""
    try:
        return True, parse_config(raw), raw
    except etree.XMLSyntaxError as e:
        return False, f"The manager's ossec.conf could not be parsed: {e}", ""


def push_tree(root, original_raw: str, *, apply_changes: bool = True) -> tuple[bool, str]:
    """Backs up, writes the edited document, asks the manager to confirm
    the result is still valid, then restarts it so the change takes effect.

    The validation call is a deliberate extra round trip: a malformed
    ossec.conf stops the manager from starting, and one slow request is a
    cheap price for catching that while the backup is still the most
    recent thing on disk.

    On success the returned message is a **warning string, or empty** -
    Wazuh does not hot-reload this file, so a write with no restart is a
    change that silently never takes effect (`services/manager_control.py`).
    A failed restart still reports success, because the write itself did
    land; the warning is what tells the operator it is not live yet.

    ``apply_changes=False`` skips the restart for a caller doing several
    writes in a row that should end in a single restart.
    """
    backup_path = write_backup(original_raw)
    content = serialize_config(root)

    ok, result = wazuh_api.request(
        "PUT", CONFIG_PATH, raw_body=content,
        content_type="application/octet-stream",
    )
    if not ok:
        return False, (
            f"The manager rejected the configuration: {result} "
            f"(nothing was changed; a copy of the previous file is at {backup_path})"
        )

    valid_ok, valid_result = wazuh_api.request("GET", VALIDATION_PATH)
    if valid_ok:
        items = (
            valid_result.get("data", {}).get("affected_items", [])
            if isinstance(valid_result, dict) else []
        )
        bad = [i for i in items if i.get("status") != "OK"]
        if bad:
            return False, (
                "The configuration was written but the manager reports it as "
                f"invalid: {bad}. Restore from {backup_path}."
            )

    return True, manager_control.restart_warning() if apply_changes else ""


# ----------------------------------------------------------------------
# SHARED HELPERS
# ----------------------------------------------------------------------

def element_to_dict(el, fields: list[str]) -> dict:
    result = {}
    for field in fields:
        child = el.find(field)
        if child is None:
            continue
        result[field] = True if field in SELF_CLOSING_FIELDS else (child.text or "").strip()
    return result


def build_element(block_type: str, data: dict):
    """Creates one block element with the indentation the file uses."""
    el = etree.Element(block_type)
    el.text = "\n    "
    for field in BLOCK_SPECS[block_type]["fields"]:
        if field in SELF_CLOSING_FIELDS:
            if data.get(field):
                etree.SubElement(el, field).tail = "\n    "
        elif field in data and data[field] not in (None, ""):
            child = etree.SubElement(el, field)
            child.text = str(data[field])
            child.tail = "\n    "
    if len(el):
        el[-1].tail = "\n  "
    el.tail = "\n\n"
    return el


def apply_fields(el, block_type: str, data: dict, *, skip: str | None = None) -> None:
    """Merges submitted values into an existing block. A field present but
    empty removes its tag; a field absent from `data` is left untouched."""
    for field in BLOCK_SPECS[block_type]["fields"]:
        if field == skip or field not in data:
            continue
        value = data[field]
        child = el.find(field)
        if field in SELF_CLOSING_FIELDS:
            if value and child is None:
                etree.SubElement(el, field).tail = "\n    "
            elif not value and child is not None:
                el.remove(child)
        elif value in (None, ""):
            if child is not None:
                el.remove(child)
        else:
            if child is None:
                child = etree.SubElement(el, field)
                child.tail = "\n    "
            child.text = str(value)


def global_email_alert_level(root) -> int | None:
    """The <alerts><email_alert_level> floor, if set. A block whose own
    level is below this never fires, which is worth telling the operator
    rather than letting them wonder why nothing arrives."""
    for alerts_el in root.iter("alerts"):
        level_el = alerts_el.find("email_alert_level")
        if level_el is not None and (level_el.text or "").strip():
            try:
                return int(level_el.text.strip())
            except ValueError:
                continue
    return None


def _level_warning(root, data: dict) -> str | None:
    floor = global_email_alert_level(root)
    if floor is None or "level" not in data:
        return None
    try:
        if int(data["level"]) < floor:
            return (
                f"Level {data['level']} is below the manager's global "
                f"email_alert_level of {floor} - this block will never trigger."
            )
    except (TypeError, ValueError):
        return None
    return None


def _find_by_field(root, tag: str, field: str, value: str):
    for el in root.iter(tag):
        child = el.find(field)
        if child is not None and (child.text or "").strip() == value:
            return el
    return None


def _text(el, field: str) -> str:
    child = el.find(field)
    return (child.text or "").strip() if child is not None else ""


def localfile_key(source) -> str:
    """The identifier for one <localfile>, from an element or a dict.

    Falls back through <location> -> <alias> -> <command> because the
    three describe mutually exclusive shapes of the same block: a file to
    read has a location, a command to run may have a friendly alias, and
    anything else has only the command text to go on. Without this
    fallback, command entries are unaddressable - which is what the
    previous location-only key produced.
    """
    get = (lambda f: (source.get(f) or "").strip()) if isinstance(source, dict) \
        else (lambda f: _text(source, f))
    return get("location") or get("alias") or get("command")


def _find_localfile(root, key: str):
    for el in root.iter("localfile"):
        if localfile_key(el) == key:
            return el
    return None


def _duplicate_localfile_keys(root) -> set[str]:
    """Keys shared by more than one entry. Two blocks with the same key
    cannot be told apart, so mutating either is unsafe."""
    seen, duplicates = set(), set()
    for el in root.iter("localfile"):
        key = localfile_key(el)
        if key in seen:
            duplicates.add(key)
        seen.add(key)
    return duplicates


def _check_email_alerts_confirm(el, confirm_value: str | None, idx: int) -> str | None:
    """email_alerts blocks are addressed by position, and positions shift
    whenever any block is added or removed. The caller must therefore also
    send the email_to it believes lives at that index; a mismatch means the
    operator is looking at a stale page and the edit would hit the wrong
    block."""
    current_el = el.find("email_to")
    current = (current_el.text or "").strip() if current_el is not None else ""
    if not confirm_value:
        return (
            "A confirmation value is required - it proves which recipient "
            "this entry belongs to."
        )
    if confirm_value != current:
        return (
            f"Safety check failed: entry {idx} currently has email_to "
            f"'{current}', not '{confirm_value}'. The list shifted - reload "
            "and try again."
        )
    return None


# ----------------------------------------------------------------------
# INSERTION POINTS
# ----------------------------------------------------------------------

def _insertion_point(root, block_type: str):
    """Where a new block of this type should go.

    Preference in all cases is to sit beside the last existing block of
    the same kind, so related configuration stays together. The fallbacks
    differ because the standard ossec.conf layout puts different concerns
    in different <ossec_config> roots.
    """
    existing = list(root.iter(block_type))
    if existing:
        last = existing[-1]
        parent = last.getparent()
        return parent, list(parent).index(last) + 1

    roots = root.findall("ossec_config")
    if not roots:
        return None, None

    if block_type == "localfile":
        # Logcollector's entries live in the SECOND root in the standard
        # layout; single-root files fall back to the only one there is.
        target = roots[1] if len(roots) >= 2 else roots[-1]
        return target, len(target)

    if block_type == "email_alerts":
        # Failing an existing block, sit next to the <global> that carries
        # the mail settings - that is where a reader expects to find it.
        for global_el in root.iter("global"):
            if global_el.find("email_notification") is not None:
                parent = global_el.getparent()
                return parent, list(parent).index(global_el) + 1
        return roots[0], len(roots[0])

    return roots[-1], len(roots[-1])


# ----------------------------------------------------------------------
# PUBLIC OPERATIONS
# ----------------------------------------------------------------------

def list_blocks(block_type: str) -> tuple[bool, list | str]:
    """Every block of one type, each as a flat dict plus an ``_id``.

    ``_id`` is the block's name/location where one exists, and its
    zero-based index for email_alerts - the same identifier the mutating
    calls expect back.
    """
    if block_type not in BLOCK_SPECS:
        return False, f"Unknown block type: {block_type}"

    ok, root, _ = fetch_tree()
    if not ok:
        return False, root

    spec = BLOCK_SPECS[block_type]
    duplicates = _duplicate_localfile_keys(root) if block_type == "localfile" else set()

    blocks = []
    for idx, el in enumerate(root.iter(block_type)):
        item = element_to_dict(el, spec["fields"])
        if block_type == "localfile":
            item["_id"] = localfile_key(el)
            # Surfaced so the UI can disable editing rather than silently
            # letting an edit land on the wrong one of two identical keys.
            item["_ambiguous"] = item["_id"] in duplicates
        elif spec["key_field"]:
            item["_id"] = item.get(spec["key_field"], "")
        else:
            item["_id"] = idx
        blocks.append(item)
    return True, blocks


def add_block(block_type: str, data: dict) -> tuple[bool, str]:
    if block_type not in BLOCK_SPECS:
        return False, f"Unknown block type: {block_type}"

    ok, root, raw = fetch_tree()
    if not ok:
        return False, root

    notice = None
    if block_type == "integration":
        error = _validate_integration(data, is_new=True)
        if error:
            return False, error
        if _find_by_field(root, "integration", "name", data["name"]) is not None:
            return False, f"An integration named '{data['name']}' already exists."

    elif block_type == "localfile":
        error = _validate_localfile(data)
        if error:
            return False, error
        key = localfile_key(data)
        if _find_localfile(root, key) is not None:
            return False, f"A log source identified by '{key}' already exists."

    else:  # email_alerts
        if not data.get("email_to"):
            return False, "The recipient (email_to) is required."
        notice = _level_warning(root, data)

    parent, position = _insertion_point(root, block_type)
    if parent is None:
        return False, "No <ossec_config> root found - the file is not shaped as expected."
    parent.insert(position, build_element(block_type, data))

    ok, result = push_tree(root, raw)
    if not ok:
        return False, result
    # `result` is the restart warning (empty when the manager came back).
    return True, " ".join(p for p in (notice or "Added.", result) if p)


def update_block(block_type: str, block_id, data: dict) -> tuple[bool, str]:
    if block_type not in BLOCK_SPECS:
        return False, f"Unknown block type: {block_type}"

    ok, root, raw = fetch_tree()
    if not ok:
        return False, root

    notice = None
    if block_type == "integration":
        el = _find_by_field(root, "integration", "name", block_id)
        if el is None:
            return False, f"No integration named '{block_id}'."
        if "name" in data and data["name"] != block_id:
            return False, "An integration's name cannot be changed - delete and re-add it."
        error = _validate_integration({"name": block_id, **data}, is_new=False)
        if error:
            return False, error
        apply_fields(el, "integration", data, skip="name")

    elif block_type == "localfile":
        if block_id in _duplicate_localfile_keys(root):
            return False, (
                f"More than one log source is identified by '{block_id}', so "
                "this edit cannot be aimed safely. Give them distinct aliases "
                "on the manager first."
            )
        el = _find_localfile(root, block_id)
        if el is None:
            return False, f"No log source identified by '{block_id}'."
        # The identifying field is immutable for the same reason an
        # integration's name is: changing it would relocate the block's
        # identity mid-edit. Renaming is delete + add.
        identifying = "location" if _text(el, "location") else (
            "alias" if _text(el, "alias") else "command"
        )
        if identifying in data and data[identifying] != block_id:
            return False, (
                f"The '{identifying}' identifies this log source and cannot be "
                "changed here - delete it and add a new one."
            )
        apply_fields(el, "localfile", data, skip=identifying)

    else:  # email_alerts
        ok_index, index_or_error = _email_alerts_index(block_id)
        if not ok_index:
            return False, index_or_error
        blocks = list(root.iter("email_alerts"))
        if index_or_error >= len(blocks):
            return False, f"No email alert entry at position {index_or_error}."
        el = blocks[index_or_error]
        error = _check_email_alerts_confirm(
            el, data.get("_confirm_email_to"), index_or_error
        )
        if error:
            return False, error
        notice = _level_warning(root, data)
        apply_fields(el, "email_alerts", data)

    ok, result = push_tree(root, raw)
    if not ok:
        return False, result
    return True, " ".join(p for p in (notice or "Saved.", result) if p)


def delete_block(block_type: str, block_id, confirm: str | None = None) -> tuple[bool, str]:
    if block_type not in BLOCK_SPECS:
        return False, f"Unknown block type: {block_type}"

    ok, root, raw = fetch_tree()
    if not ok:
        return False, root

    if block_type == "integration":
        el = _find_by_field(root, "integration", "name", block_id)
        if el is None:
            return False, f"No integration named '{block_id}'."

    elif block_type == "localfile":
        if block_id in _duplicate_localfile_keys(root):
            return False, (
                f"More than one log source is identified by '{block_id}', so "
                "this delete cannot be aimed safely. Give them distinct "
                "aliases on the manager first."
            )
        el = _find_localfile(root, block_id)
        if el is None:
            return False, f"No log source identified by '{block_id}'."

    else:  # email_alerts
        ok_index, index_or_error = _email_alerts_index(block_id)
        if not ok_index:
            return False, index_or_error
        blocks = list(root.iter("email_alerts"))
        if index_or_error >= len(blocks):
            return False, f"No email alert entry at position {index_or_error}."
        el = blocks[index_or_error]
        error = _check_email_alerts_confirm(el, confirm, index_or_error)
        if error:
            return False, error

    el.getparent().remove(el)
    ok, result = push_tree(root, raw)
    if not ok:
        return False, result
    return True, " ".join(p for p in ("Deleted.", result) if p)


# ----------------------------------------------------------------------
# INTERNALS
# ----------------------------------------------------------------------

def _email_alerts_index(block_id) -> tuple[bool, int | str]:
    try:
        index = int(block_id)
    except (TypeError, ValueError):
        return False, f"The entry id must be a number, got '{block_id}'."
    if index < 0:
        return False, f"The entry id must not be negative, got {index}."
    return True, index


def _validate_localfile(data: dict) -> str | None:
    """A log source is either a file to read or a command to run, and the
    two have different requirements - which is why one flat "required"
    list cannot express this block type."""
    log_format = (data.get("log_format") or "").strip()
    if not log_format:
        return "The log format is required."

    if log_format in COMMAND_LOG_FORMATS:
        if not (data.get("command") or "").strip():
            return f"A command is required for log format '{log_format}'."
        # An alias is what makes a command entry addressable later, and
        # it is also what a decoder matches on via <program_name>, so the
        # dashboard insists on one even though Wazuh tolerates its absence.
        if not (data.get("alias") or "").strip():
            return (
                "An alias is required for a command log source - it names the "
                "entry and is what a decoder matches on."
            )
        return None

    if not (data.get("location") or "").strip():
        return f"A location is required for log format '{log_format}'."
    return None


def _validate_integration(data: dict, *, is_new: bool) -> str | None:
    name = data.get("name")
    if is_new and not name:
        return "The integration name is required."
    if is_new and not data.get("alert_format"):
        return "The alert format is required."
    if name in INTEGRATION_REQUIRES_HOOK_URL and not data.get("hook_url"):
        return f"A hook URL is required for the '{name}' integration."
    if name in INTEGRATION_REQUIRES_API_KEY and not data.get("api_key"):
        return f"An API key is required for the '{name}' integration."
    return None
