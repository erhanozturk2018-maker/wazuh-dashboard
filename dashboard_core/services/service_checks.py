"""
Targeted service-status checks: the three pieces, generated together.

Watching a service means three things must exist and agree, all tied
together by one `alias`:

1. a ``<localfile log_format="full_command">`` in a GROUP's agent.conf —
   the agents in that group run the command on a schedule and ship the
   output;
2. a **decoder** that turns that raw output line into a ``status`` field —
   without it Wazuh receives the text and silently discards it;
3. a **rule** that fires an alert when ``status`` reads as stopped.

Writing those by hand for every service is repetitive and easy to get
subtly wrong (a mismatched alias produces no error anywhere — the check
simply never fires). This module generates all three from one description
and keeps them consistent.

**Why group-scoped rather than sent to every agent.** A check for a
service a host does not run produces meaningless output, which the decoder
then reads as "not running". That is a false alert manufactured by
configuration. Targeting by group is what prevents it, and is why
``create_check`` insists on a group rather than offering an "all agents"
shortcut.

**Why one file per check.** Each check's decoder and rule live in their own
``service_check_<alias>.xml``. Appending to a shared ``local_rules.xml``
would mean parsing and surgically editing a file on every create and
delete; a dedicated file makes creation a write and removal a delete, which
is far harder to get wrong.
"""

import re

from lxml import etree

from dashboard_core.services import agents as agents_service
from dashboard_core.services import custom_files, manager_control

# The alias becomes an XML attribute value, a decoder's <program_name>,
# and part of a filename, so it is kept deliberately narrow.
ALIAS_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{2,63}$")

# Wazuh reserves rule ids below 100000 for its own ruleset; user rules
# live at or above it. Staying inside this range is what keeps a generated
# rule from colliding with a product update.
USER_RULE_ID_MIN = 100000
USER_RULE_ID_MAX = 120000

FILE_PREFIX = "service_check_"

# What each platform's status command prints, and which of those outputs
# mean "not running". Taken from the commands below, NOT from syscollector
# — the two vocabularies differ and mixing them silently breaks matching.
PLATFORMS = {
    "linux": {
        "label": "Linux (systemd)",
        "command": "systemctl is-active {service}",
        # `systemctl is-active` prints exactly one word.
        "stopped": ["inactive", "failed", "deactivating", "unknown"],
    },
    "windows": {
        "label": "Windows",
        "command": "powershell -NoProfile -Command \"(Get-Service -Name '{service}').Status\"",
        "stopped": ["Stopped", "Paused", "StopPending"],
    },
}

DEFAULT_LEVEL = 12
DEFAULT_FREQUENCY = 60


class ServiceCheckError(Exception):
    """A check could not be described or applied. Carries an operator-
    readable message; never a traceback for the browser."""


# ----------------------------------------------------------------------
# DESCRIBING A CHECK
# ----------------------------------------------------------------------

def platform_for(os_platform: str) -> str:
    """Maps an agent's reported OS to one of our command templates."""
    return "windows" if "windows" in (os_platform or "").lower() else "linux"


def suggest_command(platform: str, service: str) -> str:
    spec = PLATFORMS.get(platform) or PLATFORMS["linux"]
    return spec["command"].format(service=service)


def validate(alias: str, command: str, frequency: str, level: str) -> str | None:
    """Everything the operator can get wrong, checked before anything is
    written. Returns a message, or None when the description is usable."""
    if not ALIAS_RE.match(alias or ""):
        return (
            "The alias must start with a letter and contain only letters, "
            "digits, underscore or hyphen (3-64 characters)."
        )
    if not (command or "").strip():
        return "The command cannot be empty."
    if not str(frequency).isdigit() or int(frequency) < 10:
        return "The frequency must be a whole number of seconds, at least 10."
    if not str(level).isdigit() or not (1 <= int(level) <= 15):
        return "The alert level must be a number between 1 and 15."
    return None


# ----------------------------------------------------------------------
# GENERATING THE XML
# ----------------------------------------------------------------------

def render_decoder(alias: str) -> str:
    """Turns the command's single-word output into a `status` field.

    Two decoders are needed, not one: the parent matches the alias (which
    Wazuh reports as the program name for a full_command entry), and the
    child extracts the value. A single decoder cannot do both.
    """
    return (
        f'<decoder name="{alias}">\n'
        f'  <program_name>{alias}</program_name>\n'
        f'</decoder>\n\n'
        f'<decoder name="{alias}-status">\n'
        f'  <parent>{alias}</parent>\n'
        f'  <regex>^(\\S+)$</regex>\n'
        f'  <order>status</order>\n'
        f'</decoder>\n'
    )


def render_rule(alias: str, service: str, platform: str, rule_id: int, level: int) -> str:
    stopped = PLATFORMS.get(platform, PLATFORMS["linux"])["stopped"]
    pattern = "|".join(re.escape(value) for value in stopped)
    return (
        f'<group name="service_monitoring,">\n'
        f'  <rule id="{rule_id}" level="{level}">\n'
        f'    <decoded_as>{alias}</decoded_as>\n'
        f'    <field name="status">^({pattern})$</field>\n'
        f'    <description>Service stopped: {service}</description>\n'
        f'  </rule>\n'
        f'</group>\n'
    )


def next_rule_id(used: set[int]) -> int:
    """The lowest free id in the user range.

    Reusing an id that another rule already holds makes Wazuh refuse to
    load the ruleset, which takes the whole analysis engine down — so this
    scans what exists rather than counting checks.
    """
    for candidate in range(USER_RULE_ID_MIN, USER_RULE_ID_MAX):
        if candidate not in used:
            return candidate
    raise ServiceCheckError(
        f"No free rule id left between {USER_RULE_ID_MIN} and {USER_RULE_ID_MAX}."
    )


def used_rule_ids(rule_files: list[dict], read) -> set[int]:
    """Every rule id currently defined in the custom rule files.

    `read` is injected so this stays testable without a manager; in
    production it is ``custom_files.read_file``.
    """
    used: set[int] = set()
    for entry in rule_files:
        ok, content = read("rule", entry["name"])
        if not ok:
            # A file we cannot read might hold any id, so refusing is safer
            # than allocating one that turns out to collide.
            raise ServiceCheckError(
                f"Could not read {entry['name']} to check for rule-id "
                f"collisions: {content}"
            )
        used.update(int(m) for m in re.findall(r'<rule\s+id="(\d+)"', content))
    return used


# ----------------------------------------------------------------------
# agent.conf EDITING
#
# agent.conf may hold several <agent_config> roots (os= / name= filters),
# so it gets the same fake-<root> wrapper as ossec.conf rather than being
# assumed single-root.
# ----------------------------------------------------------------------

def _parse_agent_config(raw: str):
    parser = etree.XMLParser(remove_blank_text=False, strip_cdata=False,
                             resolve_entities=False)
    return etree.fromstring(b"<root>" + (raw or "").encode("utf-8") + b"</root>",
                            parser=parser)


def _serialize_agent_config(root) -> str:
    parts = [root.text or ""]
    for node in root:
        parts.append(etree.tostring(node, encoding="unicode"))
    return "".join(parts)


def _localfile_for(alias: str, command: str, frequency: int):
    el = etree.Element("localfile")
    el.text = "\n    "
    for tag, value in (
        ("log_format", "full_command"),
        ("command", command),
        ("alias", alias),
        ("frequency", str(frequency)),
    ):
        child = etree.SubElement(el, tag)
        child.text = value
        child.tail = "\n    "
    el[-1].tail = "\n  "
    el.tail = "\n\n"
    return el


def add_collector(raw: str, alias: str, command: str, frequency: int) -> str:
    """Adds one full_command block to a group's agent.conf."""
    root = _parse_agent_config(raw)
    for existing in root.iter("localfile"):
        current = existing.find("alias")
        if current is not None and (current.text or "").strip() == alias:
            raise ServiceCheckError(
                f"This group already has a check with the alias '{alias}'."
            )

    configs = root.findall("agent_config")
    if not configs:
        # A brand-new group's file may be empty or comment-only.
        config = etree.SubElement(root, "agent_config")
        config.text = "\n  "
        config.tail = "\n"
    else:
        config = configs[0]
    config.append(_localfile_for(alias, command, frequency))
    return _serialize_agent_config(root)


def remove_collector(raw: str, alias: str) -> str:
    root = _parse_agent_config(raw)
    removed = False
    for el in list(root.iter("localfile")):
        current = el.find("alias")
        if current is not None and (current.text or "").strip() == alias:
            el.getparent().remove(el)
            removed = True
    if not removed:
        raise ServiceCheckError(f"No check with the alias '{alias}' in this group.")
    return _serialize_agent_config(root)


def collectors_in(raw: str) -> list[dict]:
    """The full_command entries a group's agent.conf defines."""
    try:
        root = _parse_agent_config(raw)
    except etree.XMLSyntaxError:
        return []
    found = []
    for el in root.iter("localfile"):
        text = lambda tag: (el.findtext(tag) or "").strip()
        if text("log_format") != "full_command" or not text("alias"):
            continue
        found.append({
            "alias": text("alias"),
            "command": text("command"),
            "frequency": text("frequency"),
        })
    return found


# ----------------------------------------------------------------------
# THE WHOLE OPERATION
# ----------------------------------------------------------------------

def list_watched() -> tuple[bool, list[dict] | str]:
    """Every service check currently configured, across all groups.

    Costs one call for the group list plus one per group. Groups are few
    and this backs a summary card the operator asked for, so the N is
    bounded and visible — unlike a per-row fetch in a table.
    """
    ok, groups = agents_service.list_groups()
    if not ok:
        return False, str(groups)

    watched = []
    for group in groups:
        ok, raw = agents_service.read_group_config(group["name"])
        if not ok:
            continue  # a group whose config cannot be read simply reports none
        for collector in collectors_in(raw):
            watched.append({**collector, "group": group["name"],
                            "agents": group.get("count", 0)})
    return True, watched


def create_check(*, alias: str, service: str, group: str, command: str,
                 platform: str, frequency: int = DEFAULT_FREQUENCY,
                 level: int = DEFAULT_LEVEL) -> tuple[bool, str]:
    """Writes the collector, the decoder and the rule as one operation.

    Three separate writes cannot be made atomic against this API, so a
    failure part-way **rolls back what already landed** rather than leaving
    a half-configured check — a collector without a decoder produces silent
    dead traffic, and a rule without a collector never fires.
    """
    error = validate(alias, command, frequency, level)
    if error:
        return False, error

    ok, rule_files = custom_files.list_files("rule")
    if not ok:
        return False, f"Could not read the existing rules: {rule_files}"
    try:
        rule_id = next_rule_id(used_rule_ids(rule_files, custom_files.read_file))
    except ServiceCheckError as e:
        return False, str(e)

    ok, original = agents_service.read_group_config(group)
    if not ok:
        return False, f"Could not read the group's configuration: {original}"
    try:
        updated = add_collector(original, alias, command, frequency)
    except ServiceCheckError as e:
        return False, str(e)

    filename = f"{FILE_PREFIX}{alias}.xml"
    done: list[str] = []

    def rollback():
        """Undo whatever may have landed.

        The file deletes are attempted **unconditionally**, not only for
        writes that reported success. Measured behaviour: the API can
        reject a rule upload with an error and still leave the file on
        disk. Rolling back only the writes we believe succeeded therefore
        leaves an orphan behind — which is exactly what happened before
        this was unconditional. Deleting a file that was never created is
        harmless, so the safe direction is to always try.
        """
        custom_files.delete_file("rule", filename, apply_changes=False)
        custom_files.delete_file("decoder", filename, apply_changes=False)
        if "collector" in done:
            agents_service.write_group_config(group, original)

    ok, message = agents_service.write_group_config(group, updated)
    if not ok:
        return False, f"Could not update the group's configuration: {message}"
    done.append("collector")

    # Neither file restarts on its own: a check needs both to exist
    # before a restart is worth paying for, so one happens at the end.
    ok, message = custom_files.save_file(
        "decoder", filename, render_decoder(alias), overwrite=True,
        apply_changes=False)
    if not ok:
        rollback()
        return False, f"Could not write the decoder (nothing was left behind): {message}"
    done.append("decoder")

    ok, message = custom_files.save_file(
        "rule", filename,
        render_rule(alias, service, platform, rule_id, level), overwrite=True,
        apply_changes=False)
    if not ok:
        rollback()
        return False, f"Could not write the rule (nothing was left behind): {message}"
    done.append("rule")

    warning = manager_control.restart_warning()
    return True, " ".join(p for p in (
        f"Watching '{service}' on group '{group}' as {alias} "
        f"(rule {rule_id}). Agents apply it on their next sync.",
        warning,
    ) if p)


def remove_check(*, alias: str, group: str) -> tuple[bool, str]:
    """Removes all three pieces. Continues past individual failures and
    reports what could not be removed, because a partial cleanup that stops
    at the first error leaves the operator with no way to finish it from
    the UI."""
    if not ALIAS_RE.match(alias or ""):
        return False, "Invalid alias."

    problems = []

    ok, raw = agents_service.read_group_config(group)
    if ok:
        try:
            ok, message = agents_service.write_group_config(
                group, remove_collector(raw, alias))
            if not ok:
                problems.append(f"collector: {message}")
        except ServiceCheckError as e:
            problems.append(f"collector: {e}")
    else:
        problems.append(f"collector: {raw}")

    filename = f"{FILE_PREFIX}{alias}.xml"
    for kind in ("decoder", "rule"):
        # One restart at the end covers both deletions.
        ok, message = custom_files.delete_file(kind, filename, apply_changes=False)
        if not ok:
            problems.append(f"{kind}: {message}")

    if problems:
        return False, "Partially removed — " + "; ".join(problems)

    warning = manager_control.restart_warning()
    return True, " ".join(p for p in (
        f"Stopped watching '{alias}' on group '{group}'.", warning) if p)
