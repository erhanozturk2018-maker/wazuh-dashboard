# CLAUDE.md

Entry point for AI coding agents (Claude Code, Codex, Gemini CLI, Cursor, etc.)
working in this repository. This file is intentionally short. Detailed,
long-lived knowledge lives under `docs/` — follow the references below rather
than expecting everything here.

## What this repository is

**Wazuh Alert Dashboard** — a FastAPI test/monitoring tool with two coupled
responsibilities: (1) receive and display Wazuh security alerts via webhook,
and (2) remotely reconfigure a Wazuh manager. It is explicitly a
testing/dev tool, not a hardened production system.

Human-facing setup/ops instructions live in `README.md` — do not duplicate
them here or in `docs/`. This documentation tree exists for information the
README doesn't cover: *why* the system is shaped the way it is.

## Architecture in one paragraph

Two machines, two trust levels, **two channels** between them. The
**dashboard machine** runs the FastAPI app (root `main.py` just calls
`uvicorn.run()`; everything else lives in the installable `dashboard_core`
package) and never touches the Wazuh manager's filesystem directly.
Everything Wazuh itself owns — `ossec.conf`, decoders and rules, agents,
groups, `agent.conf`, syscollector — travels over the **Wazuh server API**.
Three host-OS features the API cannot express — Postfix, rsyslog files,
package installation — still travel over one fixed **SSH forced command**.
Alerts flow the other way entirely (manager → dashboard webhook, no auth,
no trust required). Full detail: `docs/architecture/system-overview.md`.

## Before writing code that talks to the manager

Read **`docs/architecture/wazuh-api.md`** first. It records what this
manager's API actually does, measured against a live 4.14.6 instance rather
than taken from vendor documentation. Several things there are not
guessable and getting them wrong is silent:

- Failures arrive **inside HTTP 200 bodies**; the status line is not enough.
- An absent `ossec.conf` section is reported as an **error** (code 1106),
  not as an empty result — that is the normal state of a fresh manager.
- **Content-Type differs per endpoint.** File uploads take
  `application/octet-stream`; `PUT /groups/{g}/configuration` rejects that
  and demands `application/xml`.
- **Never retry a read timeout.** The manager keeps executing a request
  after the client gives up — one abandoned call ran for 325 seconds while
  its retry ran for 352 — so retrying makes an overload worse.

## Repository navigation

Full index of every doc under `docs/`, with a one-line summary of each:
`docs/knowledge/index.md`. Follow that reference rather than re-deriving
the list here.

## Critical architectural constraints

These are invariants, not preferences. Violating them changes the security
model or breaks a documented, previously-fixed failure mode — do not change
without reading the linked rationale first.

- **The dashboard never assumes it runs on the Wazuh manager.** No direct
  reads/writes of `/var/ossec/**`, no local `systemctl`. All manager
  effects go through `services/wazuh_api.py` or, for the three host-OS
  features, `services/ssh_transport.py`.
  → `docs/architecture/system-overview.md`
- **Which channel a feature uses is decided by what it touches, not by
  convenience.** If the Wazuh API can express it, it belongs there. The SSH
  channel is for host-OS concerns only.
  → `docs/security/ssh-boundary.md`
- **The SSH forced command never widens beyond its fixed dispatch targets**
  — now four: `mail`, `rsyslog`, `deps`, `restart`. Adding one is a
  deliberate, reviewed widening of the blast radius, never a convenience.
  → `docs/security/ssh-boundary.md`
- **Every `ossec.conf` mutation backs up the previous document first** —
  to `data/config_backups/` on the dashboard, since the API cannot write
  arbitrary files on the manager — and asks the manager to validate the
  result afterwards. → `docs/knowledge/design-decisions.md`
- **Mutating SSH actions (`add`/`update`/`delete`) trigger a service
  restart centrally in the wrapper; read actions never do.** This
  distinction was the fix for a real, previously-shipped bug.
  → `docs/knowledge/design-decisions.md`
- **Secrets never touch disk on the dashboard.** `sasl_pass` and agent
  registration keys live in memory for one request only; only a `*_set`
  boolean is persisted. → `docs/security/dashboard-side.md`
- **`/wazuh-webhook` and `/health` stay unauthenticated; everything else
  requires a session.** The manager cannot log in.
  → `docs/security/dashboard-side.md`
- **XML edits go through `lxml`, never regex/text munging** — `ossec.conf`
  has multiple XML roots, which is why everything wraps it in a fake
  `<root>` first. → `docs/development/coding-standards.md`
- **Never let a form field influence a connection target.** Host, port,
  user, key and API URL come from `.env` only. Path segments that *do* take
  user input (file names, group names, agent ids) are pattern-validated
  before they reach a URL. → `docs/security/dashboard-side.md`

## Known outstanding risk

The Wazuh API user currently holds the built-in `administrator` role. The
SSH forced command bounded a leaked credential by construction; the API
bounds it by RBAC, and **RBAC has not been scoped yet**. This is an
accepted, recorded debt rather than an oversight — see
`docs/security/dashboard-side.md` for what a minimal role would need.

## Repository rules for AI agents

1. **Measure, don't assume, when the manager is involved.** This project's
   API knowledge came from probing a live instance, and several documented
   behaviours contradict what a reasonable person would guess. If something
   about the manager is unknown, find out before building on it.
2. **Understand before editing.** Read the relevant `docs/` file(s) above
   before modifying architecture, either channel, or manager-side scripts.
3. **Search before creating.** No framework/ORM by convention; the test
   runner is `pytest` and nothing else. Don't introduce another to solve a
   local problem.
4. **Reuse existing patterns** — the `(ok, result)` return convention,
   JSON-file persistence, `shlex.quote`-then-SSH, the `wazuh_api.request`
   seam — rather than inventing a new one for a similar problem.
   → `docs/development/coding-standards.md`
5. **State architectural impact before large changes**, especially anything
   touching either channel, auth, or the two-machine boundary.
   → `docs/development/workflow.md`
6. **Respect the package split.** All backend code lives in
   `dashboard_core` (`pip install -e .`), split by concern.
   `dashboard_core/app.py` is assembly only; root `main.py` is the entry
   point only. Use package-qualified imports. Put new code in the module
   that owns the concern, and don't add abstraction layers unless asked.
7. **When a name moves, move its tests' patch targets with it.** Tests
   patch where a name is *used*, and read redirectable constants as
   `config.X` at call time. A stale patch target silently patches nothing
   and the test passes for the wrong reason.
   → `docs/development/testing.md`
8. **Delete what a migration retires, don't leave it lying around.** An
   unused SSH sender or an undispatched wrapper case is an invitation to
   route new work down the wrong channel, and in the wrapper's case it is
   live blast radius for no benefit.
9. **When a fact could go in more than one doc, it lives in exactly one** —
   follow the reference, don't re-derive it. If you add documentation,
   preserve this rule.
