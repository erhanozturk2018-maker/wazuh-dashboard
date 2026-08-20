"""
Service checks: the three-piece generator.

A check is a collector (in a group's agent.conf), a decoder, and a rule,
all tied together by one alias. The pieces are individually unremarkable;
what needs protecting is that they stay CONSISTENT, because every way they
can disagree fails silently:

  - collector without decoder → Wazuh receives text and discards it
  - decoder without rule      → a field is extracted, nothing alerts
  - rule without collector    → a rule that can never match
  - a colliding rule id       → the whole ruleset refuses to load

So the tests here lean on the failure paths, and especially on rollback.
"""

import pytest

from dashboard_core.services import service_checks as sc


# ======================================================================
# DESCRIBING
# ======================================================================

@pytest.mark.parametrize("alias,ok", [
    ("sshd_status_check", True),
    ("ldap-check", True),
    ("a" * 64, True),
    ("ab", False),                 # too short
    ("a" * 65, False),             # too long
    ("9starts_with_digit", False),
    ("has space", False),
    ("has/slash", False),          # would escape the filename
    ("../traversal", False),
    ("", False),
])
def test_alias_validation(alias, ok):
    result = sc.validate(alias, "systemctl is-active x", "60", "12")
    assert (result is None) is ok


@pytest.mark.parametrize("frequency,level,ok", [
    ("60", "12", True),
    ("10", "1", True),
    ("9", "12", False),            # too frequent
    ("abc", "12", False),
    ("60", "0", False),
    ("60", "16", False),
])
def test_frequency_and_level_bounds(frequency, level, ok):
    result = sc.validate("valid_alias", "cmd", frequency, level)
    assert (result is None) is ok


def test_platform_detection_and_command_suggestion():
    assert sc.platform_for("ubuntu") == "linux"
    assert sc.platform_for("Microsoft Windows 11 Pro") == "windows"
    assert sc.platform_for(None) == "linux"

    assert "systemctl is-active sshd" == sc.suggest_command("linux", "sshd")
    assert "Get-Service" in sc.suggest_command("windows", "Spooler")


# ======================================================================
# GENERATING
# ======================================================================

def test_decoder_ties_to_the_alias_twice():
    """The parent matches the program name; the child extracts the value.
    One decoder cannot do both, and a mismatch between them means nothing
    is ever decoded."""
    xml = sc.render_decoder("sshd_check")
    assert "<program_name>sshd_check</program_name>" in xml
    assert "<parent>sshd_check</parent>" in xml
    assert "<order>status</order>" in xml


def test_rule_matches_the_platforms_own_stopped_words():
    """The command's vocabulary, not syscollector's — `systemctl
    is-active` prints "inactive", never "STOPPED"."""
    linux = sc.render_rule("a", "cron", "linux", 100000, 12)
    assert "inactive" in linux and "STOPPED" not in linux

    windows = sc.render_rule("a", "Spooler", "windows", 100001, 12)
    assert "Stopped" in windows and "inactive" not in windows


def test_rule_carries_the_id_level_and_decoded_as():
    xml = sc.render_rule("sshd_check", "sshd", "linux", 100042, 7)
    assert 'id="100042"' in xml
    assert 'level="7"' in xml
    assert "<decoded_as>sshd_check</decoded_as>" in xml
    assert "sshd" in xml


def test_generated_xml_is_well_formed():
    from lxml import etree
    for xml in (sc.render_decoder("x_check"),
                sc.render_rule("x_check", "svc", "linux", 100000, 12)):
        etree.fromstring(b"<root>" + xml.encode() + b"</root>")


# ======================================================================
# RULE ID ALLOCATION
# ======================================================================

def test_ids_start_at_the_user_range():
    assert sc.next_rule_id(set()) == sc.USER_RULE_ID_MIN


def test_ids_skip_what_is_already_taken():
    used = {100000, 100001, 100003}
    assert sc.next_rule_id(used) == 100002


def test_running_out_of_ids_is_an_error_not_a_collision():
    used = set(range(sc.USER_RULE_ID_MIN, sc.USER_RULE_ID_MAX))
    with pytest.raises(sc.ServiceCheckError):
        sc.next_rule_id(used)


def test_used_ids_are_scanned_from_the_actual_files():
    files = [{"name": "local_rules.xml"}, {"name": "other.xml"}]
    contents = {
        "local_rules.xml": '<group><rule id="100000" level="5"></rule>\n'
                           '<rule id="100007" level="5"></rule></group>',
        "other.xml": '<rule id="100003" level="5"></rule>',
    }
    used = sc.used_rule_ids(files, lambda kind, name: (True, contents[name]))
    assert used == {100000, 100007, 100003}
    assert sc.next_rule_id(used) == 100001


def test_an_unreadable_rule_file_refuses_rather_than_guessing():
    """Allocating an id while blind to an existing file risks a collision
    that stops the whole ruleset loading."""
    files = [{"name": "unreadable.xml"}]
    with pytest.raises(sc.ServiceCheckError):
        sc.used_rule_ids(files, lambda kind, name: (False, "permission denied"))


# ======================================================================
# agent.conf EDITING
# ======================================================================

EMPTY_CONF = "<agent_config>\n\n  <!-- Shared agent configuration here -->\n\n</agent_config>\n"


def test_add_collector_into_an_empty_group_config():
    result = sc.add_collector(EMPTY_CONF, "sshd_check", "systemctl is-active sshd", 60)
    assert "<log_format>full_command</log_format>" in result
    assert "<alias>sshd_check</alias>" in result
    assert "<frequency>60</frequency>" in result
    # The original comment survives.
    assert "Shared agent configuration here" in result


def test_add_collector_into_a_file_with_no_agent_config_root():
    """A brand-new group's file can be empty; the block still has to land
    somewhere valid."""
    result = sc.add_collector("", "x_check", "uptime", 60)
    assert "<agent_config>" in result and "<alias>x_check</alias>" in result


def test_add_collector_refuses_a_duplicate_alias():
    once = sc.add_collector(EMPTY_CONF, "sshd_check", "cmd", 60)
    with pytest.raises(sc.ServiceCheckError, match="already has a check"):
        sc.add_collector(once, "sshd_check", "other cmd", 30)


def test_remove_collector_takes_only_its_own():
    conf = sc.add_collector(EMPTY_CONF, "a_check", "cmd a", 60)
    conf = sc.add_collector(conf, "b_check", "cmd b", 60)
    result = sc.remove_collector(conf, "a_check")
    assert "a_check" not in result
    assert "b_check" in result and "cmd b" in result


def test_remove_collector_reports_a_missing_alias():
    with pytest.raises(sc.ServiceCheckError, match="No check with the alias"):
        sc.remove_collector(EMPTY_CONF, "not_there")


def test_collectors_in_lists_only_full_command_entries():
    conf = (
        "<agent_config>\n"
        "  <localfile><log_format>syslog</log_format>"
        "<location>/var/log/x</location></localfile>\n"
        "  <localfile><log_format>full_command</log_format>"
        "<command>uptime</command><alias>up_check</alias>"
        "<frequency>60</frequency></localfile>\n"
        "</agent_config>\n"
    )
    found = sc.collectors_in(conf)
    assert len(found) == 1
    assert found[0] == {"alias": "up_check", "command": "uptime", "frequency": "60"}


def test_collectors_in_survives_malformed_xml():
    """A group whose config someone hand-broke must not take down the
    summary card for every other group."""
    assert sc.collectors_in("<agent_config><unclosed>") == []


def test_multiple_agent_config_roots_are_preserved():
    """agent.conf may carry os=/name= filtered blocks; adding a collector
    must not silently drop the others."""
    conf = ('<agent_config os="Linux">\n</agent_config>\n'
            '<agent_config os="Windows">\n</agent_config>\n')
    result = sc.add_collector(conf, "x_check", "cmd", 60)
    assert result.count("<agent_config") == 2


# ======================================================================
# THE WHOLE OPERATION - especially what happens when it fails
# ======================================================================

@pytest.fixture
def fake_manager(monkeypatch):
    """A stand-in for the two service modules, recording what was written
    and able to fail on demand."""
    state = {
        "group_config": EMPTY_CONF,
        "files": {},
        "fail_on": None,        # "decoder" | "rule" | "collector"
        "writes": [],
        "restarts_requested": [],
    }

    def read_group_config(group):
        return True, state["group_config"]

    def write_group_config(group, content):
        if state["fail_on"] == "collector":
            return False, "manager refused"
        state["group_config"] = content
        state["writes"].append(("group", group))
        return True, "ok"

    def list_files(kind):
        return True, [{"name": n} for n, k in state["files"].items() if k[0] == kind]

    def read_file(kind, name):
        entry = state["files"].get(name)
        return (True, entry[1]) if entry else (False, "missing")

    def save_file(kind, name, content, *, overwrite, apply_changes=True):
        if state["fail_on"] == kind:
            return False, f"manager refused the {kind}"
        state["files"][name] = (kind, content)
        state["writes"].append((kind, name))
        # Recorded so a test can assert the intermediate writes do NOT
        # restart - a check is only worth a restart once all three pieces
        # are in place.
        state["restarts_requested"].append((kind, name, apply_changes))
        return True, "ok"

    def delete_file(kind, name, apply_changes=True):
        state["files"].pop(name, None)
        state["writes"].append(("delete-" + kind, name))
        state["restarts_requested"].append(("delete-" + kind, name, apply_changes))
        return True, "ok"

    monkeypatch.setattr(sc.agents_service, "read_group_config", read_group_config)
    monkeypatch.setattr(sc.agents_service, "write_group_config", write_group_config)
    monkeypatch.setattr(sc.custom_files, "list_files", list_files)
    monkeypatch.setattr(sc.custom_files, "read_file", read_file)
    monkeypatch.setattr(sc.custom_files, "save_file", save_file)
    monkeypatch.setattr(sc.custom_files, "delete_file", delete_file)

    # The restart itself is recorded by the autouse `restarts` fixture in
    # tests/conftest.py - one seam for the whole suite, not a second one
    # here.
    return state


def make(**overrides):
    args = dict(alias="sshd_check", service="sshd", group="linux_servers",
                command="systemctl is-active sshd", platform="linux")
    args.update(overrides)
    return args


def test_create_writes_all_three_pieces(fake_manager):
    ok, message = sc.create_check(**make())
    assert ok, message

    assert "<alias>sshd_check</alias>" in fake_manager["group_config"]
    assert "service_check_sshd_check.xml" in fake_manager["files"]
    kinds = {k for k, _ in fake_manager["files"].values()}
    assert kinds == {"decoder", "rule"} or len(fake_manager["files"]) == 1
    assert "100000" in message   # the allocated rule id is reported


def test_create_reports_the_rule_id_and_the_sync_delay(fake_manager):
    ok, message = sc.create_check(**make())
    assert ok
    assert "next sync" in message


def test_a_failing_decoder_rolls_back_the_collector(fake_manager):
    """Otherwise the group ships command output that nothing decodes —
    dead traffic with no sign anything is wrong."""
    fake_manager["fail_on"] = "decoder"
    ok, message = sc.create_check(**make())

    assert ok is False
    assert "nothing was left behind" in message
    assert "sshd_check" not in fake_manager["group_config"]


def test_a_failing_rule_rolls_back_the_collector_and_decoder(fake_manager):
    fake_manager["fail_on"] = "rule"
    ok, message = sc.create_check(**make())

    assert ok is False
    assert "sshd_check" not in fake_manager["group_config"]
    assert fake_manager["files"] == {}


def test_a_failing_collector_writes_nothing_at_all(fake_manager):
    fake_manager["fail_on"] = "collector"
    ok, message = sc.create_check(**make())

    assert ok is False
    assert fake_manager["files"] == {}


def test_create_validates_before_touching_the_manager(fake_manager):
    ok, message = sc.create_check(**make(alias="bad alias"))
    assert ok is False
    assert fake_manager["writes"] == []


def test_create_refuses_a_duplicate_alias_in_the_same_group(fake_manager):
    assert sc.create_check(**make())[0]
    ok, message = sc.create_check(**make())
    assert ok is False
    assert "already has a check" in message


def test_a_second_check_gets_a_different_rule_id(fake_manager):
    sc.create_check(**make(alias="first_check"))
    ok, message = sc.create_check(**make(alias="second_check"))
    assert ok, message
    assert "100001" in message


def test_remove_takes_all_three_pieces(fake_manager):
    sc.create_check(**make())
    ok, message = sc.remove_check(alias="sshd_check", group="linux_servers")

    assert ok, message
    assert "sshd_check" not in fake_manager["group_config"]
    assert fake_manager["files"] == {}


def test_remove_reports_what_it_could_not_clean_up(fake_manager, monkeypatch):
    """Stopping at the first failure would leave the operator with pieces
    they cannot reach from the UI, so removal continues and reports."""
    sc.create_check(**make())
    monkeypatch.setattr(sc.custom_files, "delete_file",
                        lambda kind, name, apply_changes=True: (False, f"{kind} is read-only"))

    ok, message = sc.remove_check(alias="sshd_check", group="linux_servers")
    assert ok is False
    assert "Partially removed" in message
    assert "decoder" in message and "rule" in message
    # The collector still came out, even though the files did not.
    assert "sshd_check" not in fake_manager["group_config"]


def test_list_watched_spans_groups(monkeypatch):
    configs = {
        "linux_servers": sc.add_collector(EMPTY_CONF, "sshd_check", "cmd", 60),
        "default": EMPTY_CONF,
    }
    monkeypatch.setattr(sc.agents_service, "list_groups", lambda: (True, [
        {"name": "linux_servers", "count": 3}, {"name": "default", "count": 2},
    ]))
    monkeypatch.setattr(sc.agents_service, "read_group_config",
                        lambda g: (True, configs[g]))

    ok, watched = sc.list_watched()
    assert ok
    assert len(watched) == 1
    assert watched[0]["alias"] == "sshd_check"
    assert watched[0]["group"] == "linux_servers"
    assert watched[0]["agents"] == 3


def test_list_watched_skips_a_group_it_cannot_read(monkeypatch):
    monkeypatch.setattr(sc.agents_service, "list_groups", lambda: (True, [
        {"name": "broken", "count": 1}, {"name": "fine", "count": 1},
    ]))
    monkeypatch.setattr(
        sc.agents_service, "read_group_config",
        lambda g: (False, "unreachable") if g == "broken"
        else (True, sc.add_collector(EMPTY_CONF, "ok_check", "cmd", 60)),
    )

    ok, watched = sc.list_watched()
    assert ok
    assert [w["alias"] for w in watched] == ["ok_check"]


# ======================================================================
# RESTART BATCHING
# ======================================================================
# A check is three writes, and each one restarts the manager by default.
# On this deployment a restart is measured in tens of seconds, so paying
# three times would make creating a check absurdly slow - and the two
# intermediate states are not worth making live anyway: a collector with
# no decoder discards its output, a decoder with no rule alerts on
# nothing.

def test_creating_a_check_restarts_the_manager_exactly_once(fake_manager, restarts):
    sc.create_check(**make())
    assert restarts.count == 1

    # ...and it is the intermediate writes that were told to hold off,
    # not the restart being skipped somewhere unrelated.
    held = [kind for kind, _, apply_changes in fake_manager["restarts_requested"]
            if not apply_changes]
    assert set(held) == {"decoder", "rule"}


def test_removing_a_check_restarts_the_manager_exactly_once(fake_manager, restarts):
    sc.create_check(**make())
    before = restarts.count
    sc.remove_check(alias="sshd_check", group="linux_servers")
    assert restarts.count == before + 1


def test_a_rolled_back_creation_does_not_leave_a_restart_behind(fake_manager, restarts):
    """Nothing survived the rollback, so there is nothing to make live."""
    fake_manager["fail_on"] = "rule"
    ok, _ = sc.create_check(**make())
    assert ok is False
    assert restarts.count == 0
