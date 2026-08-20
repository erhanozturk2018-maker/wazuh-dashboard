"""
ossec.conf editing, now on the dashboard side.

This replaces the old tests/services/test_manager_service.py, which
covered `services/manager.py` - a thin wrapper that built SSH argument
vectors and parsed the manager-side tool's JSON. That tool is gone: the
API hands us raw XML and takes raw XML back, so the parse/edit/serialize
work moved here and so did the tests.

Two of the old file's concerns disappeared with it rather than moving:
`_parse_agent_envelope` (the API returns JSON directly, so there is no
stdout to scan past a restart banner) and `_agent_key_from` (the API
returns a dict entry, not the bare string `manage_agents -j -e` gave).
"""

import pytest
from lxml import etree

from dashboard_core import config
from dashboard_core.services import ossec_config


@pytest.fixture(autouse=True)
def isolated_backups(tmp_path, monkeypatch):
    """Backups are real file writes; keep them out of the repo's data/."""
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)


# ======================================================================
# PARSE / SERIALIZE
# ======================================================================

def test_round_trip_is_byte_identical(ossec_conf):
    """The wrapper must survive a full parse/serialize cycle untouched.

    ossec.conf has multiple <ossec_config> roots, so it is wrapped in a
    fake <root> to be parseable at all. If stripping that wrapper is not
    exact, every save silently rewrites parts of the operator's file that
    nobody asked to change.
    """
    root = ossec_config.parse_config(ossec_conf)
    assert ossec_config.serialize_config(root) == ossec_conf


def test_parse_handles_multiple_roots(ossec_conf):
    root = ossec_config.parse_config(ossec_conf)
    assert len(root.findall("ossec_config")) == 2


def test_comments_between_blocks_are_preserved():
    raw = "<!-- keep me -->\n<ossec_config>\n  <global/>\n</ossec_config>\n"
    root = ossec_config.parse_config(raw)
    assert ossec_config.serialize_config(root) == raw


# ======================================================================
# LOCALFILE IDENTITY
#
# The previous implementation keyed localfile on <location> alone. Wazuh
# does not require a location for command entries, so those were listed
# with an empty id and could never be edited or deleted - and they are
# exactly the entries the service-monitoring feature creates.
# ======================================================================

def test_command_entries_get_an_identity_from_their_alias(ossec_conf):
    root = ossec_config.parse_config(ossec_conf)
    keys = [ossec_config.localfile_key(el) for el in root.iter("localfile")]
    assert "/var/log/auth.log" in keys
    assert "cron_check" in keys
    assert "" not in keys


def test_localfile_key_falls_back_through_location_alias_command():
    assert ossec_config.localfile_key({"location": "/var/log/x", "alias": "a"}) == "/var/log/x"
    assert ossec_config.localfile_key({"alias": "a", "command": "c"}) == "a"
    assert ossec_config.localfile_key({"command": "df -P"}) == "df -P"


def test_every_localfile_is_findable_by_its_own_key(ossec_conf):
    root = ossec_config.parse_config(ossec_conf)
    for el in list(root.iter("localfile")):
        key = ossec_config.localfile_key(el)
        assert ossec_config._find_localfile(root, key) is not None, key


def test_duplicate_keys_are_reported_not_silently_shadowed():
    raw = (
        "<ossec_config>\n"
        "  <localfile><log_format>command</log_format><command>df -P</command></localfile>\n"
        "  <localfile><log_format>command</log_format><command>df -P</command></localfile>\n"
        "</ossec_config>\n"
    )
    root = ossec_config.parse_config(raw)
    assert ossec_config._duplicate_localfile_keys(root) == {"df -P"}


def test_update_refuses_an_ambiguous_localfile(api_with_config):
    raw = (
        "<ossec_config>\n"
        "  <localfile><log_format>command</log_format><command>df -P</command></localfile>\n"
        "  <localfile><log_format>command</log_format><command>df -P</command></localfile>\n"
        "</ossec_config>\n"
    )
    api_with_config.set("/manager/configuration?raw=true", raw)
    ok, message = ossec_config.update_block("localfile", "df -P", {"frequency": "60"})
    assert ok is False
    assert "more than one" in message.lower()


# ======================================================================
# LOCALFILE VALIDATION - a file to read and a command to run have
# different requirements, which one flat "required" list cannot express.
# ======================================================================

@pytest.mark.parametrize("data,expected_ok", [
    ({"log_format": "full_command", "command": "systemctl is-active cron", "alias": "c"}, True),
    ({"log_format": "syslog", "location": "/var/log/x.log"}, True),
    ({"log_format": "full_command", "command": "x"}, False),          # no alias
    ({"log_format": "full_command", "alias": "x"}, False),            # no command
    ({"log_format": "syslog"}, False),                                # no location
    ({"location": "/var/log/x.log"}, False),                          # no log_format
])
def test_localfile_validation(data, expected_ok):
    assert (ossec_config._validate_localfile(data) is None) is expected_ok


# ======================================================================
# LIST
# ======================================================================

def test_list_blocks_reads_each_type(api_with_config):
    ok, integrations = ossec_config.list_blocks("integration")
    assert ok and [i["_id"] for i in integrations] == ["custom-webhook"]

    ok, alerts = ossec_config.list_blocks("email_alerts")
    assert ok and alerts[0]["_id"] == 0 and alerts[0]["email_to"] == "first@example.com"

    ok, localfiles = ossec_config.list_blocks("localfile")
    assert ok and len(localfiles) == 2


def test_list_blocks_rejects_unknown_type():
    ok, message = ossec_config.list_blocks("nonsense")
    assert ok is False and "unknown block type" in message.lower()


def test_list_blocks_surfaces_a_read_failure(api_stub):
    api_stub.fail("/manager/configuration", "manager unreachable")
    ok, message = ossec_config.list_blocks("integration")
    assert ok is False and "manager unreachable" in message


# ======================================================================
# ADD / UPDATE / DELETE
# ======================================================================

def _written(stub):
    """The XML body of the PUT this test caused."""
    for method, path, kwargs in stub.calls:
        if method == "PUT" and "/manager/configuration" in path:
            return kwargs["raw_body"]
    raise AssertionError(f"no configuration PUT was made; calls: {stub.paths()}")


def test_add_integration_writes_the_block(api_with_config):
    ok, _ = ossec_config.add_block("integration", {
        "name": "slack", "alert_format": "json", "hook_url": "https://hooks.slack.com/x",
    })
    assert ok
    root = ossec_config.parse_config(_written(api_with_config))
    names = [(el.findtext("name") or "") for el in root.iter("integration")]
    assert names == ["custom-webhook", "slack"]


def test_add_integration_rejects_a_duplicate_name(api_with_config):
    ok, message = ossec_config.add_block("integration", {
        "name": "custom-webhook", "alert_format": "json",
    })
    assert ok is False and "already exists" in message


def test_add_integration_enforces_name_specific_requirements(api_with_config):
    ok, message = ossec_config.add_block("integration", {"name": "slack", "alert_format": "json"})
    assert ok is False and "hook url" in message.lower()


def test_update_integration_refuses_a_rename(api_with_config):
    ok, message = ossec_config.update_block(
        "integration", "custom-webhook", {"name": "renamed"}
    )
    assert ok is False and "cannot be changed" in message


def test_update_clears_a_field_submitted_empty(api_with_config):
    ok, _ = ossec_config.update_block("integration", "custom-webhook", {"hook_url": ""})
    assert ok
    root = ossec_config.parse_config(_written(api_with_config))
    block = next(el for el in root.iter("integration"))
    assert block.find("hook_url") is None


def test_delete_integration_removes_only_that_block(api_with_config):
    ok, _ = ossec_config.delete_block("integration", "custom-webhook")
    assert ok
    root = ossec_config.parse_config(_written(api_with_config))
    assert list(root.iter("integration")) == []
    # Neighbours must be untouched.
    assert len(list(root.iter("localfile"))) == 2


def test_delete_reports_a_missing_target(api_with_config):
    ok, message = ossec_config.delete_block("integration", "not-there")
    assert ok is False and "no integration named" in message.lower()


# ======================================================================
# EMAIL_ALERTS POSITIONAL SAFETY
#
# These blocks have no unique field, so they are addressed by position.
# Positions shift whenever any block is added or removed, so a mutation
# must also state which recipient it believes is at that position.
# ======================================================================

def test_email_alerts_update_requires_a_confirmation(api_with_config):
    ok, message = ossec_config.update_block("email_alerts", 0, {"level": "5"})
    assert ok is False and "confirmation" in message.lower()


def test_email_alerts_update_rejects_a_stale_confirmation(api_with_config):
    ok, message = ossec_config.update_block(
        "email_alerts", 0, {"level": "5", "_confirm_email_to": "someone-else@example.com"}
    )
    assert ok is False and "shifted" in message.lower()


def test_email_alerts_update_accepts_a_matching_confirmation(api_with_config):
    ok, _ = ossec_config.update_block(
        "email_alerts", 0, {"level": "5", "_confirm_email_to": "first@example.com"}
    )
    assert ok
    root = ossec_config.parse_config(_written(api_with_config))
    assert next(root.iter("email_alerts")).findtext("level") == "5"


def test_email_alerts_delete_rejects_a_stale_confirmation(api_with_config):
    ok, message = ossec_config.delete_block("email_alerts", 0, "wrong@example.com")
    assert ok is False and "shifted" in message.lower()


def test_email_alerts_id_must_be_numeric(api_with_config):
    ok, message = ossec_config.delete_block("email_alerts", "abc", "x@example.com")
    assert ok is False and "must be a number" in message


def test_add_warns_when_level_is_below_the_global_floor(api_with_config):
    """The sample config sets email_alert_level to 10; a block below that
    never fires, and silently doing nothing is worse than saying so."""
    ok, message = ossec_config.add_block(
        "email_alerts", {"email_to": "x@example.com", "level": "3"}
    )
    assert ok
    assert "never trigger" in message


# ======================================================================
# SELF-CLOSING FIELDS - presence is the value
# ======================================================================

def test_self_closing_fields_are_written_without_text(api_with_config):
    ok, _ = ossec_config.add_block("email_alerts", {
        "email_to": "x@example.com", "do_not_delay": True, "do_not_group": False,
    })
    assert ok
    root = ossec_config.parse_config(_written(api_with_config))
    added = list(root.iter("email_alerts"))[-1]
    assert added.find("do_not_delay") is not None
    assert (added.find("do_not_delay").text or "") == ""
    assert added.find("do_not_group") is None


# ======================================================================
# WRITE SAFETY
# ======================================================================

def test_a_backup_is_written_before_every_push(api_with_config, tmp_path):
    ossec_config.add_block("integration", {"name": "slack", "alert_format": "json",
                                           "hook_url": "https://x"})
    backups = list((tmp_path / "config_backups").iterdir())
    assert len(backups) == 1
    # The backup holds the PREVIOUS content, which is what makes it useful.
    assert "custom-webhook" in backups[0].read_text(encoding="utf-8")
    assert "slack" not in backups[0].read_text(encoding="utf-8")


def test_backups_rotate_to_the_five_most_recent(tmp_path):
    for i in range(8):
        ossec_config.write_backup(f"content {i}", base_name="ossec.conf")
        # The name carries the timestamp, so distinct names need distinct
        # seconds; write directly instead of sleeping through eight of them.
        stamped = tmp_path / "config_backups" / f"ossec.conf.bak.2026010100000{i}"
        stamped.write_text(f"content {i}", encoding="utf-8")
    ossec_config.rotate_backups("ossec.conf.bak.")
    kept = sorted(p.name for p in (tmp_path / "config_backups").iterdir())
    assert len(kept) == 5


def test_a_rejected_write_reports_the_backup_location(api_stub):
    api_stub.set("/manager/configuration?raw=true", "<ossec_config>\n</ossec_config>\n")
    api_stub.fail("/manager/configuration", "invalid configuration")
    ok, message = ossec_config.add_block(
        "integration", {"name": "slack", "alert_format": "json", "hook_url": "https://x"}
    )
    assert ok is False
    assert "invalid configuration" in message
    assert "config_backups" in message


def test_an_invalid_result_is_reported_even_though_the_put_succeeded(api_stub):
    """The PUT can succeed while the resulting file is unusable - a
    manager that will not start on its next restart is worth catching
    while the backup is still the newest thing on disk."""
    api_stub.set("/manager/configuration?raw=true", "<ossec_config>\n</ossec_config>\n")
    api_stub.set("/manager/configuration/validation", {
        "data": {"affected_items": [{"name": "manager", "status": "ERROR"}],
                 "failed_items": []},
        "error": 0,
    })
    api_stub.set("/manager/configuration", {"data": {"affected_items": ["manager"],
                                                     "failed_items": []}, "error": 0})
    ok, message = ossec_config.add_block(
        "integration", {"name": "slack", "alert_format": "json", "hook_url": "https://x"}
    )
    assert ok is False
    assert "invalid" in message.lower() and "Restore from" in message


def test_unparseable_config_from_the_manager_is_reported_not_raised(api_stub):
    api_stub.set("/manager/configuration?raw=true", "<ossec_config><unclosed>")
    ok, message = ossec_config.list_blocks("integration")
    assert ok is False
    assert "could not be parsed" in message
