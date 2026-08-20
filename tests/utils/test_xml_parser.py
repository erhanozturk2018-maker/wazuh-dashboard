"""
================================================================================
Purpose
================================================================================
This module protects the `lxml`-based `ossec.conf` parsing/writing logic
in `wazuh-integration/ssh-dispatch/tools/ossec-config-tool.py`.

**This script is no longer dispatched** - editing `<email_alerts>` and
`<integration>` blocks in production now happens on the dashboard side,
in `dashboard_core/services/ossec_config.py` (covered by
`tests/services/test_ossec_config.py`), which ported this same
wrap-in-a-fake-`<root>` trick when the manager channel became the Wazuh
API. `ossec-config-tool.py` survives on the manager only because
`postfix_config.py` and `rsyslog-config-tool.py` import its helpers
(`load_wrapped_tree`, `backup_config`, `rotate_backups`); this module's
remaining value is protecting *that* shared logic, not a live editing
path of its own. `ossec.conf` is not well-formed single-root XML (it has
multiple `<ossec_config>` root elements), and the wrap/parse/edit/strip
trick is a documented, deliberate design decision
(`docs/knowledge/design-decisions.md`) specifically chosen over
regex/text-based editing, which was evaluated and rejected as unsafe for
this file's shape. This module exists to prove that trick is correct in
isolation, using synthetic in-memory XML fixtures, without requiring a
live manager or a real `/var/ossec/etc/ossec.conf`.

================================================================================
Responsibilities
================================================================================
- Verify `load_wrapped_tree()` correctly wraps arbitrary multi-root XML
  bytes in a fake `<root>` and parses them without raising, including
  files containing comments and blank-line formatting between blocks.
- Verify `save_wrapped_tree()` strips the fake `<root>` wrapper on write
  and reproduces the original blocks, in order, including preserved
  comments/whitespace between them, plus any edits made to the in-memory
  tree.
- Verify `save_wrapped_tree()` calls `backup_config()` before writing, and
  that the backup file is a byte-for-byte copy of the file's prior
  contents.
- Verify `element_to_dict()` correctly extracts each field named in a
  block's spec, strips whitespace from text values, treats
  `SELF_CLOSING_FIELDS` (`do_not_delay`, `do_not_group`) as boolean
  presence flags rather than text values, and silently omits fields whose
  child element is absent (rather than raising `KeyError`/`AttributeError`).
- Verify `get_global_email_alert_level()` correctly locates
  `<alerts><email_alert_level>` when present, handles multiple `<alerts>`
  blocks (first match), and returns `None` when absent or non-numeric.
- Verify `integration_find_by_name()`, `integration_build_element()`, and
  `integration_insertion_parent()` correctly locate an existing
  `<integration>` by its `<name>` child, build a new element containing
  only the non-empty fields provided, and choose a sensible insertion
  point (after the last existing `<integration>`, or at the end of the
  last `<ossec_config>` root if none exist).
- Verify `email_alerts_all()`, `email_alerts_by_index()`,
  `email_alerts_build_element()`, and `email_alerts_insertion_parent()`
  correctly enumerate blocks by document order (the basis of the
  temporary, file-order-dependent ID scheme), bounds-check an out-of-range
  index (returns `None`, does not raise `IndexError`), build a new
  element with self-closing flags correctly represented, and choose the
  documented three-tier insertion point (next to last existing block →
  next to the `<global>`/`email_notification` block → end of first
  `<ossec_config>` root).

================================================================================
System Boundaries
================================================================================
In scope: the pure XML tree manipulation functions in
`ossec-config-tool.py` listed above — everything from `load_wrapped_tree`
through the `email_alerts_*`/`integration_*` helper functions, exclusive
of the `cmd_*`/`main()` CLI dispatch layer.

Out of scope, and covered elsewhere:
- Field-level validation (`integration_validate()`,
  `email_alerts_check_confirm()`, `BLOCK_SPECS[...]["required"]`) — this
  is validation logic, not XML parsing/writing; if the team decides to
  test it directly, it belongs in a separately-scoped module (see the
  Assumptions section of `tests/utils/test_validation.py`), not here.
- The `cmd_list/get/add/update/delete`/`main()` CLI layer — argument
  parsing, stdout JSON formatting, and exit codes for this script are a
  distinct concern from whether the underlying tree edit is correct, and
  exercising them would require simulating `sys.argv`/subprocess
  invocation rather than testing pure functions.
- Anything about how the dashboard reaches the manager for this kind of
  edit — it no longer goes through this script at all; that path is the
  Wazuh API, covered by `tests/services/test_ossec_config.py`. This
  module never imports or references dashboard code.
- Real filesystem interaction with `/var/ossec/etc/ossec.conf` — this
  module must never assume that path exists or is writable.

================================================================================
Why These Tests Matter
================================================================================
This is the only code in the repository that directly mutates the Wazuh
manager's authoritative configuration file, and it does so around a
structural workaround (the fake-`<root>` wrapper) for a file format that
violates ordinary XML's single-root assumption. A bug in the wrap/strip
logic could corrupt `ossec.conf` in a way that isn't caught until the
`wazuh-manager` service fails to restart or fails to parse its own config
— a failure mode that surfaces far from its cause and is expensive to
diagnose on a real manager. `docs/knowledge/design-decisions.md` records
that regex-based editing of this file was *specifically evaluated and
rejected* because of exactly this risk ("safely locating and replacing a
specific block by text pattern-matching risks... corrupting adjacent
blocks"); this module's coverage of the `lxml`-based alternative is what
makes that design decision trustworthy rather than merely documented.
The insertion-point and index-bounds logic additionally guards the
documented stale-ID race condition
(`docs/security/manager-side.md`) at its structural root — if
`email_alerts_by_index()` mishandled bounds, the confirmation check built
on top of it couldn't do its job correctly.

================================================================================
Production Files to Understand First
================================================================================
- `wazuh-integration/ssh-dispatch/tools/ossec-config-tool.py` — the
  entire file, but especially the module docstring (explains the
  multi-root/wrapper problem directly), `BLOCK_SPECS`,
  `SELF_CLOSING_FIELDS`, and every function from `load_wrapped_tree`
  through `email_alerts_insertion_parent`.
- `docs/development/coding-standards.md` — "XML editing: `lxml`, never
  regex or plain text munging," for the authoritative statement that any
  future `ossec.conf`-editing code must reuse these functions rather than
  reimplement parsing.
- `docs/knowledge/design-decisions.md` — "`ossec.conf` editing: `lxml`
  over regex/text munging," for why this approach was chosen.
- `docs/security/manager-side.md` — "`email_alerts` blocks: the
  ID-confirmation pattern is a race-condition guard" and "Backup-before-write
  is universal, not per-feature," for the guarantees this module's
  index/backup tests exist to uphold.

================================================================================
Testing Strategy
================================================================================
This is a Unit test module operating entirely on synthetic, in-memory
`ossec.conf`-shaped fixtures — small, hand-authored multi-root XML
strings/bytes covering the realistic shapes this file takes (multiple
`<ossec_config>` roots, comments between blocks, existing `<email_alerts>`
and `<integration>` blocks, a `<global><email_notification/></global>`
block, an `<alerts><email_alert_level>` block) — never the real
`/var/ossec/etc/ossec.conf`. Functions that take a `path` parameter with
a `CONFIG_PATH` default (`load_wrapped_tree`, `backup_config`,
`save_wrapped_tree`) should be called with an explicit `tmp_path`-based
path in every test, never the default, so no test can accidentally touch
a real file on the machine running the suite.

================================================================================
Expected Test Scenarios
================================================================================
- Round-trip: writing a fixture through `load_wrapped_tree` →
  (no edits) → `save_wrapped_tree` reproduces the original file content
  byte-for-byte (proving the wrapper adds no artifacts).
- Round-trip with an edit: adding/removing/modifying an element between
  load and save preserves all *other* blocks' formatting/comments
  unchanged.
- `element_to_dict` against a block with all fields present, a block
  missing some optional fields, and a block using both self-closing flags.
- `get_global_email_alert_level` with zero, one, and multiple `<alerts>`
  blocks, and with a non-numeric value present.
- `integration_find_by_name` finding an existing block, and returning
  `None` for a name that doesn't exist.
- `integration_build_element` including only non-empty provided fields,
  and confirming `name` is never silently dropped when present.
- `integration_insertion_parent` with zero, one, and multiple existing
  `<integration>` blocks, and with a fixture that has no `<integration>`
  blocks and no `<ossec_config>` root at all (returns `(None, None)`).
- `email_alerts_by_index` with a valid index, a negative index, and an
  index past the end of the list — the latter two return `None`, not an
  exception.
- `email_alerts_insertion_parent`'s three-tier fallback, exercised with
  three separate fixtures each satisfying only one tier.
- `backup_config`/`save_wrapped_tree` produce a `.bak.<timestamp>` file
  whose contents match the pre-write file exactly, using a `tmp_path`
  fixture file, before any edit is applied.

================================================================================
Out of Scope
================================================================================
- Testing against the real, live `/var/ossec/etc/ossec.conf` file format
  from an actual Wazuh installation beyond what can be reasonably
  synthesized as a fixture — if a real anonymized sample becomes
  available, it may be added as an additional fixture, but this module
  must not require one to run.
- `sudo`/permission/ownership concerns around the real file path — those
  are deployment concerns (`docs/development/deployment.md`), not parsing
  logic.
- Validation logic (see System Boundaries) and the CLI/`main()` dispatch
  layer.
- Concurrent-write safety (e.g. two simultaneous manager-side tool
  invocations racing on the same file) — not implemented in the current
  code, so not something to test as if it were a guarantee.

================================================================================
Mocking Strategy
================================================================================
Minimal mocking. `shutil.copy2` (used by `backup_config`) and file
`open()` calls should operate on real, temporary files (via pytest's
`tmp_path`) rather than being mocked — the whole point of this module is
verifying real file I/O and real `lxml` parsing behavior, so mocking the
filesystem away would defeat its purpose. The only thing worth
controlling is `time.strftime()` (used to timestamp backup filenames) if
a test needs a deterministic backup filename to assert against; even
then, asserting the backup file *exists and matches content* without
pinning the exact timestamp string is usually sufficient and less brittle.

================================================================================
Assumptions
================================================================================
- Assumption: this module tests `ossec-config-tool.py` as an importable
  pure-Python module (`from ossec_config_tool import load_wrapped_tree,
  ...` or equivalent, depending on how the test suite's `sys.path`/import
  mechanism is set up), even though the script is deployed separately via
  `scp` and never imported by `main.py` in production
  (`docs/architecture/system-overview.md`). Import-for-testing is judged
  compatible with that architectural note, which concerns production
  execution coupling, not test-time code reuse — but this is inferred,
  not stated explicitly anywhere in the docs, and should be confirmed
  with the team if the module's file naming (hyphens vs. underscores)
  makes a direct import awkward.
- Assumption: fixture XML strings are hand-authored to be *representative*
  of real `ossec.conf` shapes (based on reading the script's own comments
  and the example in `wazuh-integration/webhook/ossec-conf-example.xml`),
  not derived from a real captured file, since no live manager is
  available per `docs/development/testing.md`.

================================================================================
Success Criteria
================================================================================
A fully passing suite in this module guarantees that the fake-`<root>`
wrapper technique correctly round-trips `ossec.conf`'s multi-root,
comment-bearing structure without data loss or corruption; that every
block-location/insertion helper behaves correctly at its documented
boundary conditions (empty file, no matching block, out-of-range index);
and that every mutation is preceded by a verifiable backup — independent
of whether the surrounding CLI/validation logic is also correct.

================================================================================
Maintenance Notes
================================================================================
If a new block type is ever added to `BLOCK_SPECS`, add a symmetric set
of fixture-based scenarios here (find/build-element/insertion-point) for
it, following the existing `email_alerts`/`integration` pattern, before
wiring it into the CLI layer. If the wrap/strip technique in
`load_wrapped_tree`/`save_wrapped_tree` is ever changed (e.g. to handle a
new edge case in real-world `ossec.conf` formatting), add the triggering
fixture here first as a regression test, then fix the implementation —
this file format has no schema to validate against, so this module's
fixtures are the closest thing to one.
"""

import importlib.util
from pathlib import Path

TOOL_PATH = Path(__file__).parent.parent.parent / "wazuh-integration" / "ssh-dispatch" / "tools" / "ossec-config-tool.py"

spec = importlib.util.spec_from_file_location("ossec_config_tool", TOOL_PATH)
ossec_config_tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ossec_config_tool)


# ============================================================
# load_wrapped_tree / save_wrapped_tree - wrap/unwrap + backup
# ============================================================

def test_load_wrapped_tree_parses_multi_root_file(tmp_path):
  fake_conf = tmp_path / "ossec.conf"
  fake_conf.write_text(
      "<ossec_config><a>1</a></ossec_config>\n"
      "<ossec_config><b>2</b></ossec_config>"
  )

  root = ossec_config_tool.load_wrapped_tree(path=str(fake_conf))

  children = list(root)
  assert len(children) == 2
  assert children[0].tag == "ossec_config"
  assert children[1].tag == "ossec_config"


def test_save_wrapped_tree_roundtrip_unchanged(tmp_path):
  original = (
      "<ossec_config><a>1</a></ossec_config>\n"
      "<ossec_config><b>2</b></ossec_config>"
  )
  fake_conf = tmp_path / "ossec.conf"
  fake_conf.write_text(original)

  root = ossec_config_tool.load_wrapped_tree(path=str(fake_conf))
  ossec_config_tool.save_wrapped_tree(root, path=str(fake_conf))

  # we made no changes - the file must come out byte-identical to the original
  assert fake_conf.read_text() == original


def test_save_wrapped_tree_creates_backup_with_original_content(tmp_path):
  original = "<ossec_config><a>1</a></ossec_config>"
  fake_conf = tmp_path / "ossec.conf"
  fake_conf.write_text(original)

  root = ossec_config_tool.load_wrapped_tree(path=str(fake_conf))
  backup_path = ossec_config_tool.save_wrapped_tree(root, path=str(fake_conf))

  backup_file = Path(backup_path)
  assert backup_file.exists()
  assert backup_file.name.startswith("ossec.conf.bak.")
  assert backup_file.read_text() == original


def test_save_wrapped_tree_persists_edits(tmp_path):
  fake_conf = tmp_path / "ossec.conf"
  fake_conf.write_text("<ossec_config><a>1</a></ossec_config>")

  root = ossec_config_tool.load_wrapped_tree(path=str(fake_conf))
  # make one real edit: change the first child's text
  root[0].find("a").text = "999"
  ossec_config_tool.save_wrapped_tree(root, path=str(fake_conf))

  assert "999" in fake_conf.read_text()
  assert "<a>1</a>" not in fake_conf.read_text()


# ============================================================
# backup_config / rotate_backups - 5-backup rotation
# ============================================================

def test_backup_rotation_deletes_oldest_keeps_five(tmp_path):
  fake_conf = tmp_path / "ossec.conf"
  fake_conf.write_text("<ossec_config><a>1</a></ossec_config>")

  # pre-seed 7 older backups with distinct embedded timestamps
  old_names = [f"ossec.conf.bak.20250101-0000{i:02d}" for i in range(7)]
  for name in old_names:
    (tmp_path / name).write_text("old backup")

  backup_path = ossec_config_tool.backup_config(path=str(fake_conf))

  remaining = sorted(p.name for p in tmp_path.glob("ossec.conf.bak.*"))
  assert len(remaining) == 5
  # the newly created backup must survive rotation
  assert Path(backup_path).name in remaining
  # survivors are the 4 NEWEST old ones + the new one; the 3 oldest are gone
  for name in old_names[:3]:
    assert name not in remaining
  for name in old_names[3:]:
    assert name in remaining


def test_backup_rotation_sorts_by_filename_timestamp_not_mtime(tmp_path):
  import os
  fake_conf = tmp_path / "ossec.conf"
  fake_conf.write_text("<ossec_config><a>1</a></ossec_config>")

  oldest_ts = tmp_path / "ossec.conf.bak.20200101-000000"
  newer_ts = [tmp_path / f"ossec.conf.bak.20250101-00000{i}" for i in range(5)]
  for p in [oldest_ts] + newer_ts:
    p.write_text("backup")
  # give the OLDEST-timestamped file the NEWEST mtime - if rotation sorted
  # by mtime instead of the filename timestamp, it would wrongly survive
  os.utime(oldest_ts, (9999999999, 9999999999))

  ossec_config_tool.backup_config(path=str(fake_conf))

  remaining = {p.name for p in tmp_path.glob("ossec.conf.bak.*")}
  assert len(remaining) == 5
  assert oldest_ts.name not in remaining


def test_backup_rotation_only_touches_matching_base_path(tmp_path):
  fake_conf = tmp_path / "ossec.conf"
  fake_conf.write_text("<ossec_config><a>1</a></ossec_config>")
  # backups of a DIFFERENT base file must never be counted or deleted
  other_backups = [tmp_path / f"main.cf.bak.20250101-00000{i}" for i in range(7)]
  for p in other_backups:
    p.write_text("someone else's backup")

  ossec_config_tool.backup_config(path=str(fake_conf))

  for p in other_backups:
    assert p.exists()


def test_backup_config_returns_new_backup_path_unchanged(tmp_path):
  original = "<ossec_config><a>1</a></ossec_config>"
  fake_conf = tmp_path / "ossec.conf"
  fake_conf.write_text(original)

  backup_path = ossec_config_tool.backup_config(path=str(fake_conf))

  backup_file = Path(backup_path)
  assert backup_file.exists()
  assert backup_file.name.startswith("ossec.conf.bak.")
  assert backup_file.read_text() == original


# ============================================================
# element_to_dict
# ============================================================

def test_element_to_dict_extracts_present_fields(tmp_path):
  fake_conf = tmp_path / "ossec.conf"
  fake_conf.write_text(
      "<ossec_config><integration>"
      "<name>slack</name><alert_format>json</alert_format>"
      "</integration></ossec_config>"
  )
  root = ossec_config_tool.load_wrapped_tree(path=str(fake_conf))
  integration_el = root[0].find("integration")

  result = ossec_config_tool.element_to_dict(
      integration_el, ossec_config_tool.BLOCK_SPECS["integration"]["fields"]
  )

  assert result["name"] == "slack"
  assert result["alert_format"] == "json"


def test_element_to_dict_omits_missing_fields(tmp_path):
  fake_conf = tmp_path / "ossec.conf"
  fake_conf.write_text(
      "<ossec_config><integration>"
      "<name>slack</name>"
      "</integration></ossec_config>"
  )
  root = ossec_config_tool.load_wrapped_tree(path=str(fake_conf))
  integration_el = root[0].find("integration")

  result = ossec_config_tool.element_to_dict(
      integration_el, ossec_config_tool.BLOCK_SPECS["integration"]["fields"]
  )

  assert "hook_url" not in result
  assert "api_key" not in result


def test_element_to_dict_self_closing_field_present_means_true(tmp_path):
  fake_conf = tmp_path / "ossec.conf"
  fake_conf.write_text(
      "<ossec_config><email_alerts>"
      "<email_to>a@b.com</email_to><do_not_delay /><do_not_group />"
      "</email_alerts></ossec_config>"
  )
  root = ossec_config_tool.load_wrapped_tree(path=str(fake_conf))
  email_alerts_el = root[0].find("email_alerts")

  result = ossec_config_tool.element_to_dict(
      email_alerts_el, ossec_config_tool.BLOCK_SPECS["email_alerts"]["fields"]
  )

  assert result["do_not_delay"] is True
  assert result["do_not_group"] is True


def test_element_to_dict_self_closing_field_absent_is_omitted(tmp_path):
  fake_conf = tmp_path / "ossec.conf"
  fake_conf.write_text(
      "<ossec_config><email_alerts>"
      "<email_to>a@b.com</email_to>"
      "</email_alerts></ossec_config>"
  )
  root = ossec_config_tool.load_wrapped_tree(path=str(fake_conf))
  email_alerts_el = root[0].find("email_alerts")

  result = ossec_config_tool.element_to_dict(
      email_alerts_el, ossec_config_tool.BLOCK_SPECS["email_alerts"]["fields"]
  )

  # CAREFUL: an absent self-closing field is NOT False, it is simply not in the dict
  assert "do_not_delay" not in result


# ============================================================
# get_global_email_alert_level
# ============================================================

def test_get_global_email_alert_level_present(tmp_path):
  fake_conf = tmp_path / "ossec.conf"
  fake_conf.write_text(
      "<ossec_config><alerts><email_alert_level>7</email_alert_level></alerts></ossec_config>"
  )
  root = ossec_config_tool.load_wrapped_tree(path=str(fake_conf))

  assert ossec_config_tool.get_global_email_alert_level(root) == 7


def test_get_global_email_alert_level_absent(tmp_path):
  fake_conf = tmp_path / "ossec.conf"
  fake_conf.write_text("<ossec_config><global>yes</global></ossec_config>")
  root = ossec_config_tool.load_wrapped_tree(path=str(fake_conf))

  assert ossec_config_tool.get_global_email_alert_level(root) is None


def test_get_global_email_alert_level_non_numeric(tmp_path):
  fake_conf = tmp_path / "ossec.conf"
  fake_conf.write_text(
      "<ossec_config><alerts><email_alert_level>not-a-number</email_alert_level></alerts></ossec_config>"
  )
  root = ossec_config_tool.load_wrapped_tree(path=str(fake_conf))

  assert ossec_config_tool.get_global_email_alert_level(root) is None


# ============================================================
# email_alerts_by_index
# ============================================================

def test_email_alerts_by_index_valid(tmp_path):
  fake_conf = tmp_path / "ossec.conf"
  fake_conf.write_text(
      "<ossec_config>"
      "<email_alerts><email_to>first@b.com</email_to></email_alerts>"
      "<email_alerts><email_to>second@b.com</email_to></email_alerts>"
      "</ossec_config>"
  )
  root = ossec_config_tool.load_wrapped_tree(path=str(fake_conf))

  block = ossec_config_tool.email_alerts_by_index(root, 1)

  assert block is not None
  assert block.find("email_to").text == "second@b.com"


def test_email_alerts_by_index_negative_returns_none(tmp_path):
  fake_conf = tmp_path / "ossec.conf"
  fake_conf.write_text(
      "<ossec_config><email_alerts><email_to>a@b.com</email_to></email_alerts></ossec_config>"
  )
  root = ossec_config_tool.load_wrapped_tree(path=str(fake_conf))

  assert ossec_config_tool.email_alerts_by_index(root, -1) is None


def test_email_alerts_by_index_out_of_range_returns_none(tmp_path):
  fake_conf = tmp_path / "ossec.conf"
  fake_conf.write_text(
      "<ossec_config><email_alerts><email_to>a@b.com</email_to></email_alerts></ossec_config>"
  )
  root = ossec_config_tool.load_wrapped_tree(path=str(fake_conf))

  # there is only 1 block (index 0) - index 5 is out of range
  assert ossec_config_tool.email_alerts_by_index(root, 5) is None

# ============================================================
# email_alerts_check_confirm - stale-ID (id drift) protection
# ============================================================

def _make_email_alerts_element(tmp_path, email_to):
  fake_conf = tmp_path / "ossec.conf"
  fake_conf.write_text(
      f"<ossec_config><email_alerts><email_to>{email_to}</email_to></email_alerts></ossec_config>"
  )
  root = ossec_config_tool.load_wrapped_tree(path=str(fake_conf))
  return root[0].find("email_alerts")


def test_email_alerts_check_confirm_matching_value_allows(tmp_path):
  el = _make_email_alerts_element(tmp_path, "ops@example.com")

  result = ossec_config_tool.email_alerts_check_confirm(el, "ops@example.com", 0)

  assert result is None


def test_email_alerts_check_confirm_empty_value_rejected(tmp_path):
  el = _make_email_alerts_element(tmp_path, "ops@example.com")

  result = ossec_config_tool.email_alerts_check_confirm(el, "", 0)

  assert result is not None
  assert "confirm_email_to" in result


def test_email_alerts_check_confirm_mismatched_value_rejected(tmp_path):
  el = _make_email_alerts_element(tmp_path, "ops@example.com")

  result = ossec_config_tool.email_alerts_check_confirm(el, "wrong@example.com", 3)

  assert result is not None
  # prove the message contains both the idx and both values
  assert "3" in result
  assert "ops@example.com" in result
  assert "wrong@example.com" in result


# ============================================================
# localfile - Logcollector entries (keyed by location)
# ============================================================

TWO_ROOT_CONF = (
    "<ossec_config>\n"
    "  <global><email_notification>yes</email_notification></global>\n"
    "</ossec_config>\n"
    "<ossec_config>\n"
    "  <localfile>\n"
    "    <log_format>syslog</log_format>\n"
    "    <location>/var/log/auth.log</location>\n"
    "  </localfile>\n"
    "</ossec_config>"
)


def _load_fixture(tmp_path, content):
  fake_conf = tmp_path / "ossec.conf"
  fake_conf.write_text(content)
  return ossec_config_tool.load_wrapped_tree(path=str(fake_conf))


def test_localfile_block_spec_registered():
  spec = ossec_config_tool.BLOCK_SPECS["localfile"]
  assert spec["key_field"] == "location"
  assert "log_format" in spec["required"]


def test_localfile_find_by_location(tmp_path):
  root = _load_fixture(tmp_path, TWO_ROOT_CONF)

  el = ossec_config_tool.localfile_find_by_location(root, "/var/log/auth.log")
  assert el is not None
  assert el.find("log_format").text == "syslog"

  assert ossec_config_tool.localfile_find_by_location(root, "/nope") is None


def test_localfile_build_element_includes_only_provided_fields():
  el = ossec_config_tool.localfile_build_element({
      "location": "/var/log/app.log", "log_format": "syslog",
  })

  assert el.tag == "localfile"
  assert el.find("location").text == "/var/log/app.log"
  assert el.find("log_format").text == "syslog"
  assert el.find("command") is None


def test_localfile_insertion_next_to_existing_block(tmp_path):
  root = _load_fixture(tmp_path, TWO_ROOT_CONF)

  parent, pos = ossec_config_tool.localfile_insertion_parent(root)

  existing = list(root.iter("localfile"))[-1]
  assert parent is existing.getparent()
  assert pos == list(parent).index(existing) + 1


def test_localfile_insertion_targets_second_ossec_config_when_none_exist(tmp_path):
  root = _load_fixture(
      tmp_path,
      "<ossec_config><global>x</global></ossec_config>\n"
      "<ossec_config><ruleset>y</ruleset></ossec_config>",
  )

  parent, pos = ossec_config_tool.localfile_insertion_parent(root)

  # the SECOND <ossec_config> (Logcollector's) is the target
  assert parent is root.findall("ossec_config")[1]


def test_localfile_insertion_single_root_falls_back(tmp_path):
  root = _load_fixture(tmp_path, "<ossec_config><global>x</global></ossec_config>")

  parent, pos = ossec_config_tool.localfile_insertion_parent(root)

  assert parent is root.findall("ossec_config")[0]


def test_localfile_roundtrip_add_and_delete(tmp_path):
  fake_conf = tmp_path / "ossec.conf"
  fake_conf.write_text(TWO_ROOT_CONF)
  root = ossec_config_tool.load_wrapped_tree(path=str(fake_conf))

  new_el = ossec_config_tool.localfile_build_element({
      "location": "/var/log/custom.log", "log_format": "json",
  })
  parent, pos = ossec_config_tool.localfile_insertion_parent(root)
  parent.insert(pos, new_el)
  ossec_config_tool.save_wrapped_tree(root, path=str(fake_conf))

  text = fake_conf.read_text()
  assert "<location>/var/log/custom.log</location>" in text
  # the pre-existing entry is untouched
  assert "<location>/var/log/auth.log</location>" in text

  # delete it again through the same helpers
  root2 = ossec_config_tool.load_wrapped_tree(path=str(fake_conf))
  el = ossec_config_tool.localfile_find_by_location(root2, "/var/log/custom.log")
  el.getparent().remove(el)
  ossec_config_tool.save_wrapped_tree(root2, path=str(fake_conf))

  assert "/var/log/custom.log" not in fake_conf.read_text()


# ============================================================
# integration_validate - required fields + name-based special rules
# ============================================================

def test_integration_validate_new_requires_name():
  result = ossec_config_tool.integration_validate({}, is_new=True)

  assert result == "name field is required"


def test_integration_validate_new_requires_alert_format():
  result = ossec_config_tool.integration_validate({"name": "custom-hook"}, is_new=True)

  assert result == "alert_format field is required"


def test_integration_validate_new_with_required_fields_passes():
  result = ossec_config_tool.integration_validate(
      {"name": "custom-hook", "alert_format": "json"}, is_new=True
  )

  assert result is None


def test_integration_validate_slack_requires_hook_url():
  result = ossec_config_tool.integration_validate(
      {"name": "slack", "alert_format": "json"}, is_new=True
  )

  assert result is not None
  assert "hook_url" in result
  assert "slack" in result


def test_integration_validate_slack_with_hook_url_passes():
  result = ossec_config_tool.integration_validate(
      {"name": "slack", "alert_format": "json", "hook_url": "https://hooks.slack.com/x"},
      is_new=True,
  )

  assert result is None


def test_integration_validate_pagerduty_requires_api_key():
  result = ossec_config_tool.integration_validate(
      {"name": "pagerduty", "alert_format": "json"}, is_new=True
  )

  assert result is not None
  assert "api_key" in result
  assert "pagerduty" in result


def test_integration_validate_update_does_not_require_name_or_alert_format():
  # is_new=False -> the name/alert_format requirement is disabled
  result = ossec_config_tool.integration_validate({}, is_new=False)

  assert result is None


def test_integration_validate_hook_url_rule_applies_even_on_update():
  # CAREFUL: the hook_url/api_key special rules do not look at is_new - if
  # a name was given they still apply (even during an update)
  result = ossec_config_tool.integration_validate({"name": "slack"}, is_new=False)

  assert result is not None
  assert "hook_url" in result