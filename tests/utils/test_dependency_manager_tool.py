"""
Manager-side dependency_manager_tool.py: the generic check/install tool
behind the dashboard's Manage Plugins flow.

Covered: dpkg -s parsing (Status + Version lines, including the
removed-but-config-files case), the {"error": 0, "data": {...}} envelope
shape, install-only-what's-missing behavior, apt-get failure handling,
and the package allowlist (the SSH-boundary guard). The subprocess seam
(`_run`) is stubbed per test - dpkg/apt-get never actually run.
"""

import importlib.util
import json
from pathlib import Path

import pytest

TOOL_PATH = Path(__file__).parent.parent.parent / "wazuh-integration" / "ssh-dispatch" / "tools" / "dependency_manager_tool.py"

spec = importlib.util.spec_from_file_location("dependency_manager_tool", TOOL_PATH)
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

DPKG_INSTALLED = (
    "Package: {name}\n"
    "Status: install ok installed\n"
    "Priority: optional\n"
    "Version: {version}\n"
    "Description: something"
)
DPKG_REMOVED = (
    "Package: {name}\n"
    "Status: deinstall ok config-files\n"
    "Version: {version}\n"
)


def _stub_run(monkeypatch, responses, calls=None):
    """responses: dict mapping the command's first two words to
    (code, stdout, stderr)."""
    calls = calls if calls is not None else []

    def fake_run(cmd, env=None):
        calls.append(cmd)
        key = " ".join(cmd[:2])
        return responses[key]

    monkeypatch.setattr(tool, "_run", fake_run)
    return calls


# ============================================================
# check
# ============================================================

def test_check_reports_installed_with_version(monkeypatch, capsys):
    _stub_run(monkeypatch, {
        "dpkg -s": (0, DPKG_INSTALLED.format(name="rsyslog", version="8.2312.0-3ubuntu9"), ""),
    })

    tool.cmd_check(["rsyslog"])

    out = json.loads(capsys.readouterr().out)
    assert out == {"error": 0, "data": {"rsyslog": {
        "installed": True, "version": "8.2312.0-3ubuntu9",
    }}}


def test_check_reports_missing_package(monkeypatch, capsys):
    _stub_run(monkeypatch, {
        "dpkg -s": (1, "", "dpkg-query: package 'postfix' is not installed"),
    })

    tool.cmd_check(["postfix"])

    out = json.loads(capsys.readouterr().out)
    assert out["data"]["postfix"] == {"installed": False, "version": None}


def test_check_removed_but_config_files_counts_as_missing(monkeypatch, capsys):
    _stub_run(monkeypatch, {
        "dpkg -s": (0, DPKG_REMOVED.format(name="postfix", version="3.8.6-1"), ""),
    })

    tool.cmd_check(["postfix"])

    out = json.loads(capsys.readouterr().out)
    assert out["data"]["postfix"] == {"installed": False, "version": None}


def test_check_multiple_packages(monkeypatch, capsys):
    def fake_run(cmd, env=None):
        if cmd[-1] == "rsyslog":
            return 0, DPKG_INSTALLED.format(name="rsyslog", version="8.1"), ""
        return 1, "", "not installed"

    monkeypatch.setattr(tool, "_run", fake_run)

    tool.cmd_check(["rsyslog", "postfix"])

    out = json.loads(capsys.readouterr().out)
    assert out["data"]["rsyslog"]["installed"] is True
    assert out["data"]["postfix"]["installed"] is False


def test_check_rejects_package_outside_allowlist(monkeypatch, capsys):
    with pytest.raises(SystemExit) as exc:
        tool.cmd_check(["netcat"])

    assert exc.value.code == 1
    out = json.loads(capsys.readouterr().out)
    assert out["error"] == 1
    assert "not in the allowed list" in out["message"]


# ============================================================
# install
# ============================================================

def test_install_skips_already_installed(monkeypatch, capsys):
    calls = _stub_run(monkeypatch, {
        "dpkg -s": (0, DPKG_INSTALLED.format(name="rsyslog", version="8.1"), ""),
    })

    tool.cmd_install(["rsyslog"])

    out = json.loads(capsys.readouterr().out)
    assert out["data"]["rsyslog"]["installed"] is True
    # no apt-get call was made
    assert all(cmd[0] != "apt-get" for cmd in calls)


def test_install_installs_missing_then_rechecks(monkeypatch, capsys):
    state = {"installed": False}
    calls = []

    def fake_run(cmd, env=None):
        calls.append(cmd)
        if cmd[0] == "dpkg":
            if state["installed"]:
                return 0, DPKG_INSTALLED.format(name="postfix", version="3.8.6-1"), ""
            return 1, "", "not installed"
        if cmd[0] == "apt-get":
            state["installed"] = True
            return 0, "Setting up postfix...", ""
        raise AssertionError(f"unexpected command {cmd}")

    monkeypatch.setattr(tool, "_run", fake_run)

    tool.cmd_install(["postfix"])

    out = json.loads(capsys.readouterr().out)
    assert out["data"]["postfix"] == {"installed": True, "version": "3.8.6-1"}
    assert ["apt-get", "install", "-y", "postfix"] in calls


def test_install_apt_failure_reports_error(monkeypatch, capsys):
    def fake_run(cmd, env=None):
        if cmd[0] == "dpkg":
            return 1, "", "not installed"
        return 100, "", "E: Unable to locate package"

    monkeypatch.setattr(tool, "_run", fake_run)

    with pytest.raises(SystemExit) as exc:
        tool.cmd_install(["postfix"])

    assert exc.value.code == 1
    out = json.loads(capsys.readouterr().out)
    assert out["error"] == 1
    assert "apt-get install failed" in out["message"]


def test_install_rejects_package_outside_allowlist(monkeypatch, capsys):
    with pytest.raises(SystemExit):
        tool.cmd_install(["nmap"])
    assert "not in the allowed list" in json.loads(capsys.readouterr().out)["message"]
