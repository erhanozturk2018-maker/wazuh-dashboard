# Deployment

Scope: where each artifact actually runs, the manager-side permission model
and *why* it's split the way it is, and ordering constraints. Not: step-by-
step setup commands — those are in `README.md` (Sections 1–5); this file
explains the facts behind those steps that matter for making changes
correctly.

## Two deployment targets, never conflated

| Artifact | Runs on | Fixed path |
|---|---|---|
| `main.py` + the backend modules (`config`/`auth`/`validation`/`storage`/`alerts`, `dashboard_core/services/`, `dashboard_core/routes/`) + `templates/` + `static/` + `data/` | Dashboard machine (any OS) | Wherever the repo is checked out |
| `wazuh-integration/webhook/*` | Wazuh manager (Linux only) | `/var/ossec/integrations/` |
| `wazuh-integration/ssh-dispatch/**` | Wazuh manager (Linux only) | `/usr/local/bin/` |

The manager-side paths are **fixed by convention across the whole system**
— the dashboard never sends a path to the manager (`../security/ssh-boundary.md`
explains why), so if a manager-side script's expected install path ever
changes, every deployment doc/script referencing `/usr/local/bin/*.sh` or
`/var/ossec/integrations/*` must be updated together, and existing manager
installs must be manually migrated — there's no dynamic discovery.

## Manager-side permission model — 750 vs 755 is not arbitrary

`config-router-wrapper.sh` is `755` (root:root). The tools it dispatches to
are `750` (root:root). This asymmetry exists because of *who* actually
executes each file:

- The wrapper is invoked **directly by the SSH forced command**, running
  under the *connecting user's* identity (the restricted
  `wazuh-dashboard-mail` account) — not root, not via `sudo`. That account
  is not the file's owner and isn't in its group, so without "others"
  execute permission the forced command fails with `Permission denied`
  before `sudo` is ever reached.
- The dispatched tools are **always invoked by the wrapper via `sudo`** — at
  that point the process is root, which has owner-level rights regardless of
  "others" permissions. `750` (no "others" access) is therefore both
  sufficient and the tighter, preferred setting for them.

Any further manager-side tool should be `750` like the existing ones
(invoked only via the wrapper's `sudo` call), not `755` — `755` is
specifically for the one file the forced command touches directly.

## Restart ordering is load-bearing

`restart-services.sh` restarts `postfix` **before** `wazuh-manager`,
deliberately — the Wazuh mail module depends on Postfix being up, and the
script fails loudly (non-zero exit, clear stderr) if either service doesn't
come back, without silently leaving the other in a stale state. Any future
service added to this restart step must be ordered relative to its actual
dependencies, not appended arbitrarily.

## The `sudo` grant is scoped to exact absolute paths, one per tool

The dedicated manager-side account's `sudoers` entry
(`/etc/sudoers.d/dashboard-tools`) grants passwordless `sudo` for exactly
`/usr/local/bin/mail_config_tool.py`,
`/usr/local/bin/rsyslog-config-tool.py`,
`/usr/local/bin/dependency_manager_tool.py`,
`/usr/local/bin/restart-services.sh`, and the one exact command
`/usr/bin/systemctl restart rsyslog` (the wrapper's post-mutation rsyslog
restart) — absolute paths, not a wildcard, and not the wrapper itself (the
wrapper doesn't need `sudo`; it calls `sudo` on the tools it dispatches to).

**Two grants must be removed on an existing manager.**
`ossec-config-tool.py` and `agent-manager-tool.py` were dispatched before
the Wazuh API took over their work. `agent-manager-tool.py` is deleted
outright; `ossec-config-tool.py` remains on disk but is now only
*imported* by `postfix_config.py` and `rsyslog-config-tool.py`, which puts
it in the same category as `postfix_config.py` — imported, never
dispatched, and therefore holding no `sudoers` line of its own. Leaving
either grant in place is a widening with no remaining purpose.

A new manager-side tool needs its own explicit `sudoers` line at its exact
install path; do not broaden this to a wildcard or a directory-level
grant.

## `.env` is dashboard-machine-only and never deployed to the manager

`WAZUH_API_URL/USER/PASSWORD/VERIFY_SSL` and
`WAZUH_SSH_HOST/PORT/USER/KEY_PATH` describe how the dashboard reaches the
manager; they have no meaning on the manager side and must never be copied
there. The API password in particular is a manager credential held by the
dashboard, so treat the file with the same care as the SSH private key.
That private key likewise lives only on the dashboard machine — only its
public half is placed in the manager's `authorized_keys`. Treat any
`.env`-shaped file appearing under `wazuh-integration/` as a mistake, not
a new convention.
