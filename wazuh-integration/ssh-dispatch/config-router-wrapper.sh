#!/bin/bash
eval set -- "$SSH_ORIGINAL_COMMAND"
tool="$1"
shift
action="$1"

is_mutating_action() {
  case "$1" in
    update|add|delete) return 0 ;;
    *) return 1 ;;
  esac
}

# Selectors are deliberately few: each one is a program a leaked dashboard
# key can run as root, so the list IS the blast radius.
#
# "ossec" and "agents" used to be here. Their work now goes through the
# Wazuh API instead (docs/architecture/wazuh-api.md), so they were removed
# rather than left dispatchable - an unused entry point still widens what a
# leaked key can reach, and buys nothing.
#
# NOTE: ossec-config-tool.py itself still lives in tools/. It is IMPORTED
# by postfix_config.py and rsyslog-config-tool.py for their XML helpers,
# never dispatched - the same arrangement postfix_config.py has always had,
# and the reason it needs no sudoers line of its own.
case "$tool" in
  mail)
    sudo /usr/local/bin/mail_config_tool.py "$@"
    status=$?
    ;;
  restart)
    exec sudo /usr/local/bin/restart-services.sh
    ;;
  rsyslog)
    # rsyslog files affect rsyslog only - restart IT here (central, same
    # mutating/read split as below) and skip the wazuh/postfix restart.
    sudo /usr/local/bin/rsyslog-config-tool.py "$@"
    status=$?
    if [ "$status" -eq 0 ] && is_mutating_action "$action"; then
      echo "--- Applying changes: restarting rsyslog ---"
      if ! sudo /usr/bin/systemctl restart rsyslog; then
        echo "WARNING: rsyslog config was updated but rsyslog restart failed" >&2
      fi
    fi
    exit "$status"
    ;;
  deps)
    # check/install are never mutating actions - no service restart
    sudo /usr/local/bin/dependency_manager_tool.py "$@"
    status=$?
    ;;
  *)
    echo "ERROR: unknown tool selector '$tool'. Use 'mail', 'rsyslog', 'deps', or 'restart'." >&2
    exit 1
    ;;
esac

# Only restart services if the underlying command succeeded AND it was a
# mutating action (update/add/delete). Read-only actions (read/list/get)
# never trigger a restart.
if [ "$status" -eq 0 ] && is_mutating_action "$action"; then
  echo "--- Applying changes: restarting services ---"
  sudo /usr/local/bin/restart-services.sh
  restart_status=$?
  if [ "$restart_status" -ne 0 ]; then
    echo "WARNING: config was updated but service restart failed (exit $restart_status)" >&2
  fi
fi

exit "$status"
