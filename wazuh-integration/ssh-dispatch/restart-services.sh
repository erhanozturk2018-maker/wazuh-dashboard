#!/bin/bash
# restart-services.sh
# Restarts wazuh-manager and postfix after a config-tool change.
# Called by config-router-wrapper.sh via the "restart" selector.
# Must be run with sudo (NOPASSWD, scoped in /etc/sudoers.d/dashboard-tools).

set -euo pipefail

# Validate postfix config before touching anything (same guard mail-config-tool.sh used)
postfix check

echo "Restarting postfix..."
systemctl restart postfix

if ! systemctl is-active --quiet postfix; then
    echo "ERROR: postfix failed to restart" >&2
    systemctl status postfix --no-pager >&2 || true
    exit 1
fi

echo "postfix restarted OK."

echo "Restarting wazuh-manager (via wazuh-control)..."
/var/ossec/bin/wazuh-control restart

# wazuh-control returns before all daemons are fully up; give it a moment
sleep 5

if ! systemctl is-active --quiet wazuh-manager; then
    echo "ERROR: wazuh-manager failed to restart" >&2
    systemctl status wazuh-manager --no-pager >&2 || true
    exit 1
fi

echo "wazuh-manager restarted OK."

echo '{"status": "restarted", "services": ["wazuh-manager", "postfix"]}'
exit 0
