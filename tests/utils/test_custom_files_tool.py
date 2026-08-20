"""
Manager-side custom decoder/rule file management (ISP feature) in
ossec-config-tool.py: the `decoder_file` / `rule_file` kinds behind the
standard list/get/add/update/delete verbs.

These are file-backed kinds - NOT ossec.conf blocks: each file under
/var/ossec/etc/decoders|rules/ holds multiple top-level <decoder>/<rule>
elements with no shared root. Covered here: name validation (no path
traversal), XML well-formedness gating (well-formed accepted, malformed
rejected before any write), create-vs-overwrite semantics, and
backup-before-mutation with the 5-backup rotation.

DECODERS_DIR / RULES_DIR are monkeypatched to tmp_path (the tool reads
them at call time via file_kind_dir()).
"""

import importlib.util
import json
from pathlib import Path

import pytest

TOOL_PATH = Path(__file__).parent.parent.parent / "wazuh-integration" / "ssh-dispatch" / "tools" / "ossec-config-tool.py"

spec = importlib.util.spec_from_file_location("ossec_config_tool_files", TOOL_PATH)
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

WELL_FORMED = '<decoder name="custom-app">\n  <prematch>^custom</prematch>\n</decoder>\n<decoder name="custom-app-2">\n  <parent>custom-app</parent>\n</decoder>'
MALFORMED = '<decoder name="broken">\n  <prematch>^oops</decoder>'


@pytest.fixture
def dirs(tmp_path, monkeypatch):
    decoders = tmp_path / "decoders"
    rules = tmp_path / "rules"
    decoders.mkdir()
    rules.mkdir()
    monkeypatch.setattr(tool, "DECODERS_DIR", str(decoders))
    monkeypatch.setattr(tool, "RULES_DIR", str(rules))
    return {"decoders": decoders, "rules": rules}


# ============================================================
# list / get
# ============================================================

def test_list_files_empty(dirs, capsys):
    tool.cmd_list("decoder_file")
    assert json.loads(capsys.readouterr().out) == []


def test_list_files_returns_names_and_contents(dirs, capsys):
    (dirs["decoders"] / "b.xml").write_text("<decoder name=\"b\"/>")
    (dirs["decoders"] / "a.xml").write_text("<decoder name=\"a\"/>")
    (dirs["decoders"] / "notes.txt").write_text("not xml, must be ignored")

    tool.cmd_list("decoder_file")

    out = json.loads(capsys.readouterr().out)
    assert [e["name"] for e in out] == ["a.xml", "b.xml"]
    assert out[0]["content"] == "<decoder name=\"a\"/>"
    assert out[0]["_id"] == "a.xml"


def test_get_file_found_and_missing(dirs, capsys):
    (dirs["rules"] / "local.xml").write_text("<group name=\"g\"/>")

    tool.cmd_get("rule_file", "local.xml")
    assert json.loads(capsys.readouterr().out)["content"] == "<group name=\"g\"/>"

    with pytest.raises(SystemExit):
        tool.cmd_get("rule_file", "missing.xml")
    assert "id not found" in json.loads(capsys.readouterr().out)["error"]


# ============================================================
# add - create only, well-formedness gate
# ============================================================

def test_add_file_writes_well_formed_multiroot_xml(dirs, capsys):
    tool.cmd_add("decoder_file", json.dumps({"name": "custom.xml", "content": WELL_FORMED}))

    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "added"
    assert out["_id"] == "custom.xml"
    assert (dirs["decoders"] / "custom.xml").read_text() == WELL_FORMED


def test_add_file_rejects_malformed_xml_without_writing(dirs, capsys):
    with pytest.raises(SystemExit) as exc:
        tool.cmd_add("decoder_file", json.dumps({"name": "broken.xml", "content": MALFORMED}))

    assert exc.value.code == 1
    assert "not well-formed" in json.loads(capsys.readouterr().out)["error"]
    assert not (dirs["decoders"] / "broken.xml").exists()


def test_add_file_rejects_existing_name(dirs, capsys):
    (dirs["decoders"] / "custom.xml").write_text("<decoder name=\"x\"/>")

    with pytest.raises(SystemExit):
        tool.cmd_add("decoder_file", json.dumps({"name": "custom.xml", "content": WELL_FORMED}))
    assert "already exists" in json.loads(capsys.readouterr().out)["error"]


@pytest.mark.parametrize("bad_name", [
    "../evil.xml", "sub/dir.xml", "no-extension", "notes.txt", ".hidden.xml", "",
])
def test_add_file_rejects_unsafe_names(dirs, capsys, bad_name):
    with pytest.raises(SystemExit):
        tool.cmd_add("decoder_file", json.dumps({"name": bad_name, "content": WELL_FORMED}))
    assert "invalid file name" in json.loads(capsys.readouterr().out)["error"]


# ============================================================
# update - create-or-overwrite, backup + rotation
# ============================================================

def test_update_file_overwrites_and_backs_up(dirs, capsys):
    (dirs["rules"] / "local.xml").write_text("<group name=\"old\"/>")

    tool.cmd_update("rule_file", "local.xml", json.dumps({"content": "<group name=\"new\"/>"}))

    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "updated"
    assert (dirs["rules"] / "local.xml").read_text() == "<group name=\"new\"/>"
    backups = list(dirs["rules"].glob("local.xml.bak.*"))
    assert len(backups) == 1
    assert backups[0].read_text() == "<group name=\"old\"/>"
    assert out["backup"].endswith(backups[0].name)


def test_update_file_creates_when_missing(dirs, capsys):
    tool.cmd_update("rule_file", "fresh.xml", json.dumps({"content": "<group name=\"g\"/>"}))

    out = json.loads(capsys.readouterr().out)
    assert out["backup"] is None
    assert (dirs["rules"] / "fresh.xml").exists()


def test_update_file_rejects_malformed_and_preserves_original(dirs, capsys):
    (dirs["rules"] / "local.xml").write_text("<group name=\"old\"/>")

    with pytest.raises(SystemExit):
        tool.cmd_update("rule_file", "local.xml", json.dumps({"content": MALFORMED}))

    assert (dirs["rules"] / "local.xml").read_text() == "<group name=\"old\"/>"
    assert not list(dirs["rules"].glob("local.xml.bak.*"))


def test_update_file_backup_rotation_keeps_five(dirs, capsys):
    (dirs["decoders"] / "d.xml").write_text("<decoder name=\"d\"/>")
    for i in range(7):
        (dirs["decoders"] / f"d.xml.bak.20250101-00000{i}").write_text("old")

    tool.cmd_update("decoder_file", "d.xml", json.dumps({"content": "<decoder name=\"d2\"/>"}))

    capsys.readouterr()
    assert len(list(dirs["decoders"].glob("d.xml.bak.*"))) == 5


# ============================================================
# delete
# ============================================================

def test_delete_file_removes_and_backs_up(dirs, capsys):
    (dirs["decoders"] / "gone.xml").write_text("<decoder name=\"gone\"/>")

    tool.cmd_delete("decoder_file", ["gone.xml"])

    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "deleted"
    assert not (dirs["decoders"] / "gone.xml").exists()
    backups = list(dirs["decoders"].glob("gone.xml.bak.*"))
    assert len(backups) == 1
    assert backups[0].read_text() == "<decoder name=\"gone\"/>"


def test_delete_file_missing_fails(dirs, capsys):
    with pytest.raises(SystemExit):
        tool.cmd_delete("decoder_file", ["missing.xml"])
    assert "id not found" in json.loads(capsys.readouterr().out)["error"]


def test_delete_file_rejects_traversal_names(dirs, capsys):
    with pytest.raises(SystemExit):
        tool.cmd_delete("decoder_file", ["../ossec.conf.xml"])
    assert "invalid file name" in json.loads(capsys.readouterr().out)["error"]
