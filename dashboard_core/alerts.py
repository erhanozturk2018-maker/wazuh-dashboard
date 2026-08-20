"""
In-memory alert store and the parsing of incoming Wazuh alert payloads.

Not persistent - this is a test/monitoring tool, alerts are lost on restart
(docs/architecture/system-overview.md).
"""

import re
import threading
from datetime import datetime

# ---- In-memory storage (not persistent - for testing purposes) ----
alerts: list[dict] = []
alerts_lock = threading.Lock()

# Simple regex to capture an IP address (e.g. "from 192.168.X.X port 45026")
IP_PATTERN = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def extract_ip(raw: dict, full_log: str) -> str | None:
    """Tries to extract the source IP address from an alert.

    Priority order:
      1. Wazuh's standard fields: data.srcip / srcip
      2. The first IP address found in the raw log line via regex
    """
    data = raw.get("data") if isinstance(raw.get("data"), dict) else {}
    candidate = data.get("srcip") or raw.get("srcip")
    if candidate:
        return candidate

    if full_log:
        match = IP_PATTERN.search(full_log)
        if match:
            return match.group(1)

    return None


def extract_fields(raw: dict) -> dict:
    """Extracts the fields to display from a Wazuh alert JSON payload.

    The standard alert format produced by the Wazuh manager looks like:
        {
          "rule": {"id": 5710, "level": 5, "description": "...", "groups": [...]},
          "agent": {"name": "...", "id": "..."},
          "timestamp": "...",
          "full_log": "..."
        }

    If these fields are missing (e.g. because Wazuh's built-in "slack"
    integration reformats the payload for Slack), the fields are left
    empty and a descriptive placeholder is shown instead.
    """
    rule = raw.get("rule") if isinstance(raw.get("rule"), dict) else {}
    agent = raw.get("agent") if isinstance(raw.get("agent"), dict) else {}

    level = rule.get("level", raw.get("level"))
    rule_id = rule.get("id", raw.get("rule_id"))
    description = rule.get("description", raw.get("description"))
    agent_name = agent.get("name", raw.get("agent_name"))
    groups = rule.get("groups") or raw.get("groups") or []
    full_log = raw.get("full_log") or raw.get("log")
    wazuh_timestamp = raw.get("timestamp") or raw.get("time")
    ip = extract_ip(raw, full_log)

    return {
        "received_at": datetime.now().strftime("%H:%M:%S"),
        "received_epoch": datetime.now().timestamp(),
        "wazuh_timestamp": wazuh_timestamp if wazuh_timestamp else "No timestamp",
        "level": level if level is not None else "Not specified",
        "rule_id": rule_id if rule_id is not None else "Not specified",
        "description": description if description else "No description found",
        "agent": agent_name if agent_name else "Unknown agent",
        "groups": ", ".join(groups) if groups else "No group info",
        "ip": ip if ip else "IP not found",
        "raw_log": full_log if full_log else "No raw log data",
        "raw_json": raw,
    }
