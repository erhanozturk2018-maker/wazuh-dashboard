"""
Manager-side rsyslog-config-tool.py: list/get/add/update/delete of the
project-owned /etc/rsyslog.d/wazuh-*.conf files.

Covered: the wazuh-*.conf ownership gate (distro files are invisible and
unwritable), create-vs-overwrite semantics, backup + 5-backup rotation on
mutation, and the JSON/exit-code convention. RSYSLOG_DIR is monkeypatched
to tmp_path.
"""

import importlib.util
import json
from pathlib import Path

import pytest

TOOL_PATH = Path(__file__).parent.parent.parent / "wazuh-integration" / "ssh-dispatch" / "tools" / "rsyslog-config-tool.py"

spec = importlib.util.spec_from_file_location("rsyslog_config_tool", TOOL_PATH)
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

CONTENT = 'module(load="imtcp")\ninput(type="imtcp" port="514")\n'


@pytest.fixture
def rsyslog_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(tool, "RSYSLOG_DIR", str(tmp_path))
    return tmp_path


def test_list_only_shows_project_owned_files(rsyslog_dir, capsys):
    (rsyslog_dir / "wazuh-tcp.conf").write_text(CONTENT)
    (rsyslog_dir / "50-default.conf").write_text("distro file, must be invisible")

    tool.cmd_list()

    out = json.loads(capsys.readouterr().out)
    assert [e["name"] for e in out] == ["wazuh-tcp.conf"]
    assert out[0]["content"] == CONTENT


def test_add_creates_file(rsyslog_dir, capsys):
    tool.cmd_add(json.dumps({"name": "wazuh-udp.conf", "content": CONTENT}))

    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "added"
    assert (rsyslog_dir / "wazuh-udp.conf").read_text() == CONTENT


def test_add_rejects_existing_file(rsyslog_dir, capsys):
    (rsyslog_dir / "wazuh-tcp.conf").write_text("existing")

    with pytest.raises(SystemExit):
        tool.cmd_add(json.dumps({"name": "wazuh-tcp.conf", "content": CONTENT}))
    assert "already exists" in json.loads(capsys.readouterr().out)["error"]


@pytest.mark.parametrize("bad_name", [
    "50-default.conf",          # not project-owned
    "../wazuh-evil.conf",       # traversal
    "wazuh-tcp.txt",            # wrong extension
    "wazuh-.conf",              # empty stem
    "",
])
def test_mutations_reject_non_project_names(rsyslog_dir, capsys, bad_name):
    with pytest.raises(SystemExit):
        tool.cmd_add(json.dumps({"name": bad_name, "content": CONTENT}))
    assert "invalid file name" in json.loads(capsys.readouterr().out)["error"]


def test_update_overwrites_with_backup_and_rotation(rsyslog_dir, capsys):
    (rsyslog_dir / "wazuh-tcp.conf").write_text("old content")
    for i in range(7):
        (rsyslog_dir / f"wazuh-tcp.conf.bak.20250101-00000{i}").write_text("older")

    tool.cmd_update("wazuh-tcp.conf", json.dumps({"content": CONTENT}))

    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "updated"
    assert (rsyslog_dir / "wazuh-tcp.conf").read_text() == CONTENT
    assert len(list(rsyslog_dir.glob("wazuh-tcp.conf.bak.*"))) == 5


def test_update_creates_when_missing(rsyslog_dir, capsys):
    tool.cmd_update("wazuh-new.conf", json.dumps({"content": CONTENT}))

    out = json.loads(capsys.readouterr().out)
    assert out["backup"] is None
    assert (rsyslog_dir / "wazuh-new.conf").exists()


def test_delete_removes_with_backup(rsyslog_dir, capsys):
    (rsyslog_dir / "wazuh-tcp.conf").write_text(CONTENT)

    tool.cmd_delete("wazuh-tcp.conf")

    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "deleted"
    assert not (rsyslog_dir / "wazuh-tcp.conf").exists()
    backups = list(rsyslog_dir.glob("wazuh-tcp.conf.bak.*"))
    assert len(backups) == 1
    assert backups[0].read_text() == CONTENT


def test_delete_missing_fails(rsyslog_dir, capsys):
    with pytest.raises(SystemExit):
        tool.cmd_delete("wazuh-missing.conf")
    assert "id not found" in json.loads(capsys.readouterr().out)["error"]


def test_empty_content_rejected(rsyslog_dir, capsys):
    with pytest.raises(SystemExit):
        tool.cmd_add(json.dumps({"name": "wazuh-x.conf", "content": "   "}))
    assert "content cannot be empty" in json.loads(capsys.readouterr().out)["error"]
