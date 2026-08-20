# SSH Trust Boundary

Scope: the security model governing the **residual** dashboard→manager SSH
channel, and the invariants that define it. The primary channel is now the
Wazuh API, whose own trust properties are in `dashboard-side.md`. Mechanics
of a single request: `../architecture/execution-flow.md` (Flow 3).

## What is still here, and why

Most of what this channel used to carry moved to the Wazuh API. Three
features stayed, because they touch the manager's **operating system**
rather than Wazuh, and the API has no vocabulary for them:

| Selector | Tool | Touches |
|---|---|---|
| `mail` | `mail_config_tool.py` (+ imported `postfix_config.py`) | `/etc/postfix/main.cf`, `sasl_passwd` |
| `rsyslog` | `rsyslog-config-tool.py` | `/etc/rsyslog.d/wazuh-*.conf` |
| `deps` | `dependency_manager_tool.py` | `dpkg -s` / `apt-get install`, allowlisted |
| `restart` | `restart-services.sh` | postfix + wazuh-manager restart |

`ossec` and `agents` are **gone**. Their work goes through the API, and
both the wrapper cases and the dashboard-side senders were deleted rather
than left in place — an unused entry point still widens what a leaked key
can reach, and a plausible-looking unused sender is an invitation to route
new work back down the wrong channel.

`ossec-config-tool.py` still exists in `tools/` but is **no longer
dispatched**. It is imported by `postfix_config.py` and
`rsyslog-config-tool.py` for their XML helpers — the same arrangement
`postfix_config.py` has always had, and the reason neither needs a sudoers
line of its own.

## Threat model

The dashboard machine is assumed **less trusted** than the manager: it may
run on a developer laptop and is explicitly a test tool. The question this
boundary answers: *if the dashboard machine or its SSH private key is fully
compromised, what can an attacker do to the manager?*

The answer, by design: **only what the four dispatched targets implement** —
update mail settings; write or delete a name-validated `wazuh-*.conf`
rsyslog file; check or install a package from a fixed allowlist
(`rsyslog`, `postfix`); restart those services. Not a shell. Not arbitrary
file writes. Not privilege escalation beyond what those operations already
imply.

**This is now the narrower of the two channels.** A leaked SSH key reaches
four validated operations; a leaked API credential reaches whatever its
RBAC role permits, which today is everything (`dashboard-side.md`). When
reasoning about blast radius, the API is the one to worry about.

## How this is enforced

An `authorized_keys` **forced command**
(`command="/usr/local/bin/config-router-wrapper.sh"`, plus
`no-pty,no-agent-forwarding,no-X11-forwarding,no-port-forwarding`) means
that no matter what SSH command the key is used to send, the manager only
ever runs the wrapper. The request arrives as `$SSH_ORIGINAL_COMMAND` —
data the wrapper dispatches on, never a path the client controls.

## Invariants — must never be relaxed without coordinated review

1. **The forced command is always the wrapper, never a tool directly.**
   Binding the key straight to one tool was the first design and was
   replaced precisely because it could not safely support more than one
   downstream target.
2. **The dashboard never sends a path or script name — only a selector
   word and arguments.** If this changes, "leaked key ⇒ bounded blast
   radius" breaks, because the client would then control *what code runs*
   rather than *what arguments a fixed program receives*.
3. **`$SSH_ORIGINAL_COMMAND` is re-split with `eval set --`, never
   naively interpolated.** A prior version interpolated it unquoted, which
   word-split it a second time on the manager and destroyed the
   dashboard's `shlex.quote()` boundaries. This is the difference between
   "arguments are data" and "arguments can inject shell syntax" — and a
   SASL password is the obvious argument containing metacharacters.
4. **`no-pty` / `no-agent-forwarding` / `no-X11-forwarding` /
   `no-port-forwarding` stay set.** These close off every use of the key
   beyond running the forced command.
5. **The SSH account's `sudo` grant stays scoped to exactly the dispatched
   tools' absolute paths** — one explicit line each, no wildcards.
   Following the removal of the `ossec` and `agents` selectors, the grants
   for `ossec-config-tool.py` and `agent-manager-tool.py` should be
   **removed from the manager's sudoers** as well; leaving them is a
   widening with no remaining purpose.
6. **Mutations restart centrally, exactly once, only on success.** The
   wrapper decides, not the individual tool — a tool that forgets writes
   its change correctly and has it silently never take effect. That
   covers the tools the wrapper dispatches. **The dashboard also sends
   `restart` directly**, because work that moved to the Wazuh API stopped
   passing through the wrapper and needed the same guarantee rebuilt on
   that side — see `../knowledge/design-decisions.md`. The selector was
   already there, so this widens nothing.

## Adding a target is a reviewed widening

Each dispatched tool enlarges what a leaked key can do. Before adding one,
the question is not "is SSH convenient here" but **"can the Wazuh API
express this?"** — if it can, it belongs there
(`../architecture/wazuh-api.md`). The three features that remain are here
because the answer was genuinely no.

## What this boundary does *not* protect

It protects the manager's host-OS configuration from a compromised
dashboard. It does **not**: protect alert data confidentiality (Flow 1 is
unauthenticated by design), protect against a compromised *manager*
attacking the dashboard, bound what the **API** credential can do, or
provide audit logging beyond what the dispatched tools print. Do not assume
guarantees it was not designed to provide.
