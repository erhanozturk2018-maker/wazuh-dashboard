"""
Manager-side mail tooling: mail_config_tool.py + postfix_config.py.

These two modules replaced mail-config-tool.sh (Task: mail/Postfix split).
The contract under test is the OLD bash script's external behavior:

- same CLI argument order (`update EMAIL_TO EMAIL_FROM SMTP_SERVER
  MAXPERHOUR RELAYHOST SASL_USER SASL_PASS`), so `dashboard_core`'s
  `run_mail_command_via_ssh` needs no change;
- same validation rules (email regex, numeric maxperhour, non-empty
  smtp_server/relayhost/sasl_user);
- blank SASL password preserves the existing one from sasl_passwd;
- every write backs up ossec.conf, main.cf and sasl_passwd first (with
  the 5-backup rotation) and runs `postmap` then `postfix check`;
- JSON on stdout, non-zero exit + {"error": ...} on failure.

`postmap`/`postfix` binaries don't exist on the test machine, so
`postfix_config._run` is stubbed per test - the seam is the subprocess
call, mirroring how dashboard tests stop at the SSH senders.
"""

import importlib.util
import json
from pathlib import Path

import pytest

TOOLS_DIR = Path(__file__).parent.parent.parent / "wazuh-integration" / "ssh-dispatch" / "tools"


def _load(filename, module_name):
    spec = importlib.util.spec_from_file_location(module_name, TOOLS_DIR / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mail_config_tool = _load("mail_config_tool.py", "mail_config_tool_under_test")
# mail_config_tool loads its own postfix_config instance - patch THAT one
postfix_config = mail_config_tool.postfix_config


OSSEC_FIXTURE = (
    "<ossec_config>\n"
    "  <global>\n"
    "    <email_notification>yes</email_notification>\n"
    "    <email_to>old-to@example.com</email_to>\n"
    "    <email_from>old-from@example.com</email_from>\n"
    "    <smtp_server>127.0.0.1</smtp_server>\n"
    "    <email_maxperhour>6</email_maxperhour>\n"
    "  </global>\n"
    "</ossec_config>\n"
    "<ossec_config>\n"
    "  <email_alerts>\n"
    "    <email_to>alert-block@example.com</email_to>\n"
    "  </email_alerts>\n"
    "</ossec_config>"
)

UPDATE_ARGS = [
    "new-to@example.com", "new-from@example.com", "smtp.example.com",
    "12", "[smtp.example.com]:587", "relay-user", "relay-pass",
]


@pytest.fixture
def mail_env(tmp_path, monkeypatch):
    """Redirects all three managed files into tmp_path and stubs the
    postmap/postfix subprocess calls to succeed, recording them."""
    ossec_conf = tmp_path / "ossec.conf"
    ossec_conf.write_text(OSSEC_FIXTURE)
    main_cf = tmp_path / "main.cf"
    main_cf.write_text("myhostname = wazuh\nrelayhost = [old.relay]:587\n")
    sasl_passwd = tmp_path / "sasl_passwd"
    sasl_passwd.write_text("[old.relay]:587  old-user:old-pass\n")

    monkeypatch.setattr(mail_config_tool, "OSSEC_CONF", str(ossec_conf))
    monkeypatch.setattr(postfix_config, "MAIN_CF", str(main_cf))
    monkeypatch.setattr(postfix_config, "SASL_PASSWD", str(sasl_passwd))

    commands = []

    def fake_run(cmd):
        commands.append(cmd)
        return 0, "", ""

    monkeypatch.setattr(postfix_config, "_run", fake_run)
    return {
        "ossec_conf": ossec_conf, "main_cf": main_cf,
        "sasl_passwd": sasl_passwd, "commands": commands,
        "tmp_path": tmp_path,
    }


# ============================================================
# read
# ============================================================

def test_read_reports_current_state_as_json(mail_env, capsys):
    mail_config_tool.cmd_read()

    out = json.loads(capsys.readouterr().out)
    assert out["email_to"] == "old-to@example.com"
    assert out["email_from"] == "old-from@example.com"
    assert out["smtp_server"] == "127.0.0.1"
    assert out["email_maxperhour"] == "6"
    assert out["relayhost"] == "[old.relay]:587"
    assert out["sasl_user"] == "old-user"
    assert out["sasl_pass_set"] is True
    # the password itself must never be echoed back
    assert "old-pass" not in json.dumps(out)


# ============================================================
# update - happy path
# ============================================================

def test_update_rewrites_all_three_files(mail_env, capsys):
    mail_config_tool.cmd_update(*UPDATE_ARGS)

    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "updated"

    conf_text = mail_env["ossec_conf"].read_text()
    assert "<email_to>new-to@example.com</email_to>" in conf_text
    assert "<email_from>new-from@example.com</email_from>" in conf_text
    assert "<smtp_server>smtp.example.com</smtp_server>" in conf_text
    assert "<email_maxperhour>12</email_maxperhour>" in conf_text
    # the <email_alerts> block's own email_to must NOT be clobbered
    # (the old bash sed did clobber it - that was a defect, not a contract)
    assert "<email_to>alert-block@example.com</email_to>" in conf_text

    assert "relayhost = [smtp.example.com]:587" in mail_env["main_cf"].read_text()
    assert mail_env["sasl_passwd"].read_text() == "[smtp.example.com]:587  relay-user:relay-pass\n"


def test_update_runs_postmap_then_postfix_check(mail_env):
    mail_config_tool.cmd_update(*UPDATE_ARGS)

    assert mail_env["commands"] == [
        ["postmap", str(mail_env["sasl_passwd"])],
        ["postfix", "check"],
    ]


def test_update_backs_up_all_three_files(mail_env):
    mail_config_tool.cmd_update(*UPDATE_ARGS)

    tmp = mail_env["tmp_path"]
    assert list(tmp.glob("ossec.conf.bak.*"))
    main_cf_backups = list(tmp.glob("main.cf.bak.*"))
    sasl_backups = list(tmp.glob("sasl_passwd.bak.*"))
    assert len(main_cf_backups) == 1
    assert len(sasl_backups) == 1
    # backups hold the PRE-update contents
    assert "relayhost = [old.relay]:587" in main_cf_backups[0].read_text()
    assert sasl_backups[0].read_text() == "[old.relay]:587  old-user:old-pass\n"


def test_update_blank_password_preserves_existing(mail_env):
    args = UPDATE_ARGS[:-1] + [""]  # SASL_PASS left blank
    mail_config_tool.cmd_update(*args)

    assert mail_env["sasl_passwd"].read_text() == "[smtp.example.com]:587  relay-user:old-pass\n"


def test_update_appends_relayhost_when_absent(mail_env):
    mail_env["main_cf"].write_text("myhostname = wazuh\n")

    mail_config_tool.cmd_update(*UPDATE_ARGS)

    assert "relayhost = [smtp.example.com]:587" in mail_env["main_cf"].read_text()


def test_update_applies_backup_rotation(mail_env):
    # pre-seed 7 old main.cf backups - after one more write, only 5 remain
    for i in range(7):
        (mail_env["tmp_path"] / f"main.cf.bak.20250101-00000{i}").write_text("old")

    mail_config_tool.cmd_update(*UPDATE_ARGS)

    assert len(list(mail_env["tmp_path"].glob("main.cf.bak.*"))) == 5


# ============================================================
# update - validation (same rules as the bash version), CLI contract
# ============================================================

@pytest.mark.parametrize("bad_args, expected_error", [
    (["not-an-email"] + UPDATE_ARGS[1:], "invalid email_to"),
    ([UPDATE_ARGS[0], "not-an-email"] + UPDATE_ARGS[2:], "invalid email_from"),
    (UPDATE_ARGS[:3] + ["twelve"] + UPDATE_ARGS[4:], "maxperhour must be a number"),
    (UPDATE_ARGS[:2] + [""] + UPDATE_ARGS[3:], "smtp_server cannot be empty"),
    (UPDATE_ARGS[:4] + [""] + UPDATE_ARGS[5:], "relayhost cannot be empty"),
    (UPDATE_ARGS[:5] + [""] + UPDATE_ARGS[6:], "sasl username cannot be empty"),
])
def test_update_rejects_invalid_input_before_writing(mail_env, capsys, bad_args, expected_error):
    with pytest.raises(SystemExit) as exc:
        mail_config_tool.cmd_update(*bad_args)

    assert exc.value.code == 1
    assert json.loads(capsys.readouterr().out)["error"] == expected_error
    # nothing was touched: no subprocess ran, no backup, no content change
    assert mail_env["commands"] == []
    assert not list(mail_env["tmp_path"].glob("*.bak.*"))
    assert "old-to@example.com" in mail_env["ossec_conf"].read_text()
    assert "old-user:old-pass" in mail_env["sasl_passwd"].read_text()


def test_main_accepts_same_cli_argument_order_as_bash(mail_env, monkeypatch, capsys):
    monkeypatch.setattr(
        mail_config_tool.sys, "argv",
        ["mail_config_tool.py", "update"] + UPDATE_ARGS,
    )
    mail_config_tool.main()

    assert json.loads(capsys.readouterr().out)["status"] == "updated"


def test_main_rejects_unknown_mode(mail_env, monkeypatch, capsys):
    monkeypatch.setattr(mail_config_tool.sys, "argv", ["mail_config_tool.py", "bogus"])
    with pytest.raises(SystemExit):
        mail_config_tool.main()

    assert "error" in json.loads(capsys.readouterr().out)


# ============================================================
# update - postmap / postfix check failure rolls the files back
# ============================================================

def test_postmap_failure_restores_both_postfix_files(mail_env, monkeypatch, capsys):
    def failing_run(cmd):
        if cmd[0] == "postmap":
            return 1, "", "postmap: fatal: bad string"
        return 0, "", ""

    monkeypatch.setattr(postfix_config, "_run", failing_run)

    with pytest.raises(SystemExit) as exc:
        mail_config_tool.cmd_update(*UPDATE_ARGS)

    assert exc.value.code == 1
    assert "postmap failed" in json.loads(capsys.readouterr().out)["error"]
    # both Postfix files restored to their pre-update content
    assert "relayhost = [old.relay]:587" in mail_env["main_cf"].read_text()
    assert mail_env["sasl_passwd"].read_text() == "[old.relay]:587  old-user:old-pass\n"
    # and ossec.conf was never rewritten (Postfix runs first)
    assert "old-to@example.com" in mail_env["ossec_conf"].read_text()


def test_postfix_check_failure_restores_both_postfix_files(mail_env, monkeypatch, capsys):
    def failing_run(cmd):
        if cmd[0] == "postfix":
            return 1, "", "postfix: fatal: config problem"
        return 0, "", ""

    monkeypatch.setattr(postfix_config, "_run", failing_run)

    with pytest.raises(SystemExit) as exc:
        mail_config_tool.cmd_update(*UPDATE_ARGS)

    assert exc.value.code == 1
    assert "postfix check failed" in json.loads(capsys.readouterr().out)["error"]
    assert "relayhost = [old.relay]:587" in mail_env["main_cf"].read_text()
    assert mail_env["sasl_passwd"].read_text() == "[old.relay]:587  old-user:old-pass\n"
    assert "old-to@example.com" in mail_env["ossec_conf"].read_text()
