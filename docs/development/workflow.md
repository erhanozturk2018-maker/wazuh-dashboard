# Development Workflow

Scope: how to change this repository safely. Not build/run commands
(README) or test procedures (`testing.md`) — specifically the coordination
and sequencing concerns unique to this codebase's split architecture.

## Before any change: locate which side of the boundary it's on

Ask first: does this change affect the dashboard machine, the manager
machine, or the SSH contract between them? (`../architecture/system-overview.md`)
Dashboard-only changes (routes, templates, `data/*.json` schema, session
logic) can be developed and verified locally. Manager-only changes
(`wazuh-integration/**`) cannot be executed in a sandbox — they assume a
live `/var/ossec/etc/ossec.conf`, root/sudo, and real Postfix/Wazuh
services (`testing.md`). Contract changes (anything altering the SSH
argument shape) require the coordinated edit set below.

## First question for any manager-facing change: which channel?

Before anything else, decide whether the Wazuh API can express what you
need. **If it can, it belongs there** — `services/wazuh_api.py` and the
service module that owns the concern. The SSH channel exists only for
host-OS work the API has no vocabulary for (Postfix, rsyslog files,
packages).

Getting this wrong in the SSH direction means writing and deploying a new
manager-side tool, granting it `sudo`, and widening the forced command's
blast radius — to do something the API already implements.

Read `../architecture/wazuh-api.md` before writing the call. Content-Type,
error shape and retry behaviour are measured facts there, not guessable.

## Adding a manager capability over the API

1. **Service module** — a function returning `(ok, result)`, calling
   `wazuh_api.request`. Put it in the module that owns the concern
   (`ossec_config`, `agents`, `custom_files`), not a new one.
2. **Route** — validates format first, and validates *before* calling;
   a rejection that still sends the request is not a rejection. Maps a
   failure to a 502 with the message intact.
3. **Tests** — stub `wazuh_api.request` via `api_stub`, and assert both
   what was sent and, for rejections, that nothing was sent at all.

For `ossec.conf` specifically, mutations go through
`services/ossec_config.py` so they inherit the backup, the lxml round-trip
and the post-write validation. Do not assemble XML anywhere else.

## Coordinated-edit checklist: changing the SSH contract

Still applies to the three remaining SSH features. If you add, rename or
reorder an argument sent over SSH, **all of these must change together** or
the system breaks silently — a mismatched argument count fails on the
manager with no dashboard-visible error until tested:

1. The sender in `dashboard_core/services/ssh_transport.py`
   (`run_mail_command_via_ssh`, `run_rsyslog_command_via_ssh` or
   `run_deps_command_via_ssh`) — what is built and quoted.
2. The receiving tool's argument parsing (`mail_config_tool.py`,
   `rsyslog-config-tool.py` or `dependency_manager_tool.py`) — what is
   expected, in what order.
3. `config-router-wrapper.sh`'s dispatch — only if the *selector word*
   changes. A new selector also needs its own `sudoers` line
   (`deployment.md`), and is a reviewed widening of the blast radius, not
   a routine step (`../security/ssh-boundary.md`).
4. `is_mutating_action()` in the wrapper — if the new action should or
   should not trigger a restart.

Do not skip the manager-side tool's independent validation even if the
route already validates the same field: these scripts can be invoked
directly on the manager, so they must not trust the dashboard.

## Changing anything that could affect service restarts

Restart logic lives in exactly one place: `config-router-wrapper.sh`'s
post-dispatch checks (including the `rsyslog` selector's own rsyslog
restart). Do not add restart calls inside `mail_config_tool.py`
or `rsyslog-config-tool.py` — this was tried before and produced a real bug
(`../knowledge/design-decisions.md`). If a new mutating action needs a
restart, it needs to be recognized by `is_mutating_action()`, not given its
own restart call.

## When to confirm scope before proceeding

Confirm with the user before: introducing a database or ORM, adding a
further layer of abstraction over the existing module split (a DI container,
a service registry, a plugin system), adding CI config or a second test
framework alongside `pytest`, adding a frontend build step/framework, or
loosening the SSH forced-command's scope in any way. These are all deliberate non-goals or hard boundaries
(`../architecture/system-overview.md`, `../security/ssh-boundary.md`) — a
request that seems to require one of them may actually be solvable within
the existing pattern; check before assuming the boundary itself needs to
move.

## Minimizing footprint

Prefer editing the smallest number of files that correctly implements a
change. For a typical API-backed feature this is the three files the
"Adding a manager capability over the API" steps above name — a service
function, a route, a test — plus a template edit if it needs a new UI
element. Touching the wrapper, a `sudoers` line, or a manager-side tool
should be rare and deliberate: it only happens for the three remaining
SSH features, and adding a new SSH target at all is the reviewed
widening described above, not a routine step. If a change is touching
significantly more files than its category above implies, re-check
against `../architecture/repository-map.md`'s "Finding things by task"
table before proceeding, since it likely means the wrong layer was
chosen.
