# System Overview

Scope: *why* the system has the components it has and *why* they're split
this way. Not: how a request moves step-by-step (→ `execution-flow.md`),
not: where files live (→ `repository-map.md`), not: what the manager's API
actually does (→ `wazuh-api.md`), not: security mechanics (→ `../security/`).

## The founding constraint: two machines, two trust levels

The Wazuh manager is a security product running as root-adjacent
infrastructure on a customer's network. The dashboard is a disposable test
tool that might run on a developer's laptop. These must never be assumed to
be the same machine, the same OS, or the same trust level, even though a
developer's test setup often runs both on one physical box.

That constraint has not changed. What changed is how the dashboard reaches
across it.

## Two channels, and the line between them

The dashboard talks to the manager two ways, and **which one a feature uses
is decided by what it touches, not by convenience**:

**The Wazuh server API — the primary channel.** Everything Wazuh itself
owns: `ossec.conf` blocks, custom decoders and rules, agents, groups,
per-group `agent.conf`, and the syscollector inventory. This is Wazuh's own
built-in REST API, already running on the manager as part of the product.

**Restricted SSH — the residual channel.** The three things the API cannot
express because they are the host operating system's concern rather than
Wazuh's: Postfix (mail relay and SASL credentials), rsyslog rule files
under `/etc/rsyslog.d/`, and package installation. These still go through
one fixed forced command (`../security/ssh-boundary.md`).

### Why the API, when an earlier decision rejected exactly this

`../knowledge/design-decisions.md` records "a second HTTP API on the
manager" as a rejected alternative — it would mean opening a new port and
service on security-sensitive infrastructure just to serve one dashboard.

**That rejection never applied to the Wazuh API.** It is not a second API:
it ships with the manager, is already listening, and is the interface
Wazuh's own dashboard uses. Nothing new is exposed by talking to it. The
reasoning that ruled out building an API does not rule out using one that
is already there.

What the switch buys: no custom manager-side scripts to deploy and keep in
sync, no `sudo` grants to maintain, versioned and documented semantics
instead of a bespoke CLI contract, and per-user RBAC instead of
all-or-nothing key possession.

What it costs, stated plainly: the SSH forced command bounded a leaked
credential to roughly six validated operations. An API user with the
`administrator` role can do considerably more. **The blast radius moved
from the transport to RBAC, and RBAC is not yet scoped** — that is a known,
deliberate debt, not an oversight (`../security/dashboard-side.md`).

### Why the three SSH features did not follow

Not stubbornness — the API genuinely has no vocabulary for them. Wazuh
manages Wazuh. It has no endpoint for "edit `/etc/postfix/main.cf`", "write
an rsyslog rule file", or "install a package", and inventing one would mean
writing the very second API that was rejected on its own merits. Keeping a
small, well-bounded SSH channel for exactly those three is the cheaper
answer.

The consequence is that a **hybrid** is the steady state for now, not a
migration half-done. If those three features are ever dropped, the SSH
channel and most of `wazuh-integration/` go with them.

## Components and why each exists

**The dashboard backend.** A single FastAPI process, split by concern:
`main.py` holds only the `uvicorn.run()` entry point,
`dashboard_core/app.py` holds only assembly, and the behaviour lives in
`config.py`, `auth.py`, `validation.py`, `storage.py`, `alerts.py`,
`services/` and `routes/` (file-by-file map: `repository-map.md`).

It is a thin client to the manager, not a proxy that understands Wazuh
internals — with one deliberate exception. **`ossec.conf` parsing now lives
here**, in `services/ossec_config.py`, because the API hands over raw XML
and takes raw XML back; whoever holds the bytes has to parse them. That
logic moved from the manager-side tool essentially intact rather than being
rewritten, since the round trip is byte-safe (`wazuh-api.md`).

**`templates/` + `static/js/app.js` (frontend).** Server-rendered Jinja2,
vanilla JS, no SPA framework, no build step — the UI's job is displaying
lists and submitting forms, and a build pipeline would add maintenance cost
with no corresponding benefit at this scope.

The navigation answers "what am I looking at?" versus "what am I
changing?": **Overview** and **Agents** under Monitor; **Pipeline**,
**Alerting** and **Console** under Configure. Within Configure the order
follows a log's own journey — collected and parsed (Pipeline), turned into
notifications (Alerting) — with Console holding only this application's own
settings. Every settings card carries a **provenance badge** naming what it
actually writes (`This console` / `Manager · ossec.conf` / `Host OS · SSH`),
because half of these screens change a local JSON file and half reconfigure
a separate security-sensitive machine, and nothing in the interface used to
distinguish them.

**Pages fetch only the open tab's data.** This reverses an earlier,
deliberate choice to render every tab on every load so switching was
instant. That trade made sense when the data came from one fast SSH call;
against an API where individual calls have been measured taking tens of
seconds (`wazuh-api.md`), it means paying for calls the operator may never
look at. `/settings` is the exception — both its tabs are local reads, so
it still switches client-side.

**`data/*.json` (dashboard persistence).** No database. Files owned one
concern each (users, settings incl. mail, session key), plus
`data/config_backups/` — see below. Appropriate because the volumes are
tiny and the tool is disposable.

**`wazuh-integration/webhook/*` (manager-side alert forwarder).** Unchanged
by the migration. Exists because Wazuh's built-in `slack` integration
reformats alert payloads and drops fields the dashboard needs
(`../knowledge/common-pitfalls.md`). Alerts still flow manager → dashboard
over an unauthenticated HTTP POST; that path was never part of the SSH
channel and is not part of the API one either.

**`wazuh-integration/ssh-dispatch/**` (shrinking).** Still one dispatcher
plus the tools it is allowed to invoke, but the list is now three:
`mail` (`mail_config_tool.py` + its imported `postfix_config.py`),
`rsyslog` (`rsyslog-config-tool.py`), and `deps`
(`dependency_manager_tool.py`), alongside `restart`. The `ossec` and
`agents` selectors are retired — their work moved to the API, and their
dashboard-side senders were **deleted rather than left in place**, because
a plausible-looking unused sender is an invitation to route new work back
down the wrong channel.

## Where the backup invariant went

The old rule was "every manager-side mutation backs up its target file
before writing". The API offers no way to write an arbitrary file on the
manager, so that rule could not survive unchanged.

**The guarantee was kept and its location moved.** `services/ossec_config.py`
writes the pre-change document to `data/config_backups/` before every
`PUT`, with the same keep-the-five-most-recent rotation. The ability to undo
the last few changes is intact; it now lives on the dashboard.

The API also *adds* something the SSH path never had cleanly: after every
write, `GET /manager/configuration/validation` asks the manager whether the
result is still valid. A malformed `ossec.conf` stops the manager starting,
so catching that while the backup is still the newest thing on disk is
worth one extra round trip.

## Non-goals (deliberate, not oversights)

Do not "fix" these without confirming scope:

- No CI, no linter config. (There *is* a `pytest` suite — `../development/testing.md`.)
- No HTTPS termination in the dashboard.
- No Wazuh Indexer connection. Alerts arrive by webhook; inventory comes
  from the API. Adding Indexer access would be a third channel with its own
  credentials and trust model — a separate decision, not a small one.
- No log rotation for alert data; alerts are explicitly ephemeral.
- No ORM, no migrations — there is no database.
- No framework beyond FastAPI for the module split: plain modules and
  `APIRouter`s.
- No Wazuh 5.0 support. 5.0 removed the inventory endpoints and the
  `manage_agents`/`agent-auth` binaries; supporting it is a separate
  migration, not a stretch goal.

## Scaling this architecture

The two-machine boundary is the part expected to survive unchanged — it is
a security boundary, not an implementation detail. What is expected to
change first, in likely order: **RBAC scoping** for the API user (the
largest outstanding debt); `data/*.json` → a real datastore once concurrent
users matter; and the SSH channel shrinking to nothing if its three
remaining features are ever dropped.
