"""
================================================================================
Purpose
================================================================================
This module protects `dashboard_core/services/logs.py`'s `log_action()` -
the application-level activity logger (auth/config-change/plugin-action
events) that is distinct from the Wazuh-side alerts pipeline (`alerts.json`).
It writes one CSV row per logged event to a date-named file under the
application's own log directory (not `/var/ossec/logs/`).

================================================================================
Responsibilities
================================================================================
- Verify a first call to `log_action()` on a given day creates the target
  file with a header row, and that a second call the same day appends
  without repeating the header.
- Verify the file name is derived from the current date, not a fixed name.
- Verify all six fields (timestamp, category, user, action, result, detail)
  land in the correct column, in the same order every time, and that
  omitted optional fields (user/target/detail) default to "-" rather than
  an empty string or None (which would render inconsistently in a CSV
  viewer / on a later database import).
- Verify the parent directory is created automatically if it does not yet
  exist (mirrors `backup_config()`'s own `mkdir(parents=True)` pattern
  elsewhere in this project).

Every test monkeypatches the log directory to `tmp_path` - this suite must
never write into the project's real `data/app_logs/`.
================================================================================
"""

import csv
from datetime import date, datetime

import pytest

from dashboard_core.services import logs as logs_module
from dashboard_core.services.logs import log_action
from dashboard_core import config


@pytest.fixture(autouse=True)
def isolated_log_dir(tmp_path, monkeypatch):
    """Point the module's log directory at tmp_path for every test in this
    file, the same isolation pattern used for SETTINGS_FILE elsewhere in
    this project - never touch the real data/app_logs/ directory."""
    monkeypatch.setattr(config, "APP_LOG_DIR", tmp_path)
    return tmp_path


def _todays_log_file(tmp_path):
    return tmp_path / f"{date.today():%Y-%m-%d}.csv"


def test_first_call_creates_file_with_header(isolated_log_dir):
    log_action(category="auth", action="login", result="success", user="erhan")

    log_file = _todays_log_file(isolated_log_dir)
    assert log_file.exists()

    with open(log_file, newline="") as f:
        rows = list(csv.reader(f))

    assert rows[0] == ["timestamp", "category", "user", "action", "target", "result", "detail"]
    assert len(rows) == 2  # header + one data row


def test_second_call_same_day_appends_without_repeating_header(isolated_log_dir):
    log_action(category="auth", action="login", result="success", user="erhan")
    log_action(category="auth", action="logout", result="success", user="erhan")

    with open(_todays_log_file(isolated_log_dir), newline="") as f:
        rows = list(csv.reader(f))

    header_rows = [r for r in rows if r and r[0] == "timestamp"]
    assert len(header_rows) == 1
    assert len(rows) == 3  # header + two data rows


def test_file_name_is_derived_from_current_date(isolated_log_dir):
    log_action(category="auth", action="login")

    files = list(isolated_log_dir.iterdir())
    assert len(files) == 1
    assert files[0].name == f"{date.today():%Y-%m-%d}.csv"


def test_all_fields_land_in_correct_column_in_order(isolated_log_dir):
    log_action(
        category="config_change",
        action="mail_update",
        result="failed",
        user="erhan",
        target="ossec.conf",
        detail="SSH connection timed out",
    )

    with open(_todays_log_file(isolated_log_dir), newline="") as f:
        rows = list(csv.reader(f))
    row = rows[1]

    # timestamp: just assert it parses as ISO 8601, not an exact value
    datetime.fromisoformat(row[0])
    assert row[1:] == ["config_change", "erhan", "mail_update", "ossec.conf", "failed", "SSH connection timed out"]


def test_omitted_optional_fields_default_to_dash(isolated_log_dir):
    log_action(category="auth", action="login")  # no result/user/target/detail supplied

    with open(_todays_log_file(isolated_log_dir), newline="") as f:
        rows = list(csv.reader(f))
    row = rows[1]

    assert row[2] == "-"  # user
    assert row[4] == "-"  # target
    assert row[6] == "-"  # detail
    assert row[5] == "success"  # result's own default, per the agreed signature


def test_parent_directory_created_automatically(tmp_path, monkeypatch):
    nested = tmp_path / "does" / "not" / "exist" / "yet"
    monkeypatch.setattr(config, "APP_LOG_DIR", nested)

    log_action(category="auth", action="login")

    assert nested.exists()
    assert (nested / f"{date.today():%Y-%m-%d}.csv").exists()