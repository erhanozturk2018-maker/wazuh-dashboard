# Execution Flow

Scope: how data actually moves at runtime for the flows that aren't obvious
from reading one file, and *why* they're sequenced as they are. Component
responsibilities: `system-overview.md`. File locations: `repository-map.md`.
What the API itself does: `wazuh-api.md`.

## Flow 1 — Alert ingestion (manager → dashboard, one-way, unauthenticated)

Unchanged by the API migration. This path was never part of the SSH channel
and is not part of the API one either — it is the manager pushing to us.

```
Wazuh rule fires
  → custom-webhook (shell wrapper Wazuh invokes with a fixed argv contract)
  → custom-webhook.py: reads the alert file Wazuh wrote (argv[1]),
    POSTs it AS-IS to hook_url (argv[3])
  → routes/dashboard.py: POST /wazuh-webhook (no auth — see why in
    ../security/dashboard-side.md)
  → extract_fields(): normalises into the display schema regardless of
    whether the payload matches Wazuh's standard shape
  → alerts.insert(0, record), trimmed to DASHBOARD_MAX_ALERTS
  → browser polls GET /api/alerts every POLL_MS (2000ms)
```

**Why extraction is defensive:** the same endpoint must handle Wazuh's
standard alert JSON, a hand-sent test payload, and a body that isn't even
JSON, without crashing — this endpoint is also the manual-testing entry
point (`../development/testing.md`), so tolerance here isn't optional.

## Flow 2 — Wazuh configuration (dashboard → manager, over the API)

This is the flow to understand before touching anything on the Pipeline or
Alerting pages. It is **read-modify-write**, and that shape is forced by the
API: `ossec.conf` comes back as raw XML and goes back as raw XML, so the
dashboard is the one holding the document.

```
Phase 1 — VALIDATE (dashboard side)
  Browser submits a form
  → routes/{pipeline,alerting}.py validates format
    (validation.py: EMAIL_RE, HOST_RE, CUSTOM_XML_FILE_RE, well-formedness)
  → fast feedback, and — unlike the old SSH path — now also the ONLY
    dashboard-side gate, because there is no bespoke manager-side tool
    re-checking afterwards. The manager still validates as a product, but
    it validates Wazuh semantics, not this dashboard's field rules.

Phase 2 — READ (the whole document)
  → services/ossec_config.py: GET /manager/configuration?raw=true
  → parse_config(): wrap in a fake <root> (ossec.conf has MULTIPLE
    <ossec_config> roots) and parse with lxml — never regex

Phase 3 — MODIFY (in memory)
  → add/update/delete the addressed block in the parse tree
  → identity rules differ per block type; see "Addressing a block" below

Phase 4 — BACK UP, THEN WRITE
  → write_backup(): the PRE-change document to data/config_backups/,
    rotated to the 5 most recent
  → serialize_config(): strip the fake root, preserving the original
    blocks and everything between them
  → PUT /manager/configuration  (application/octet-stream)

Phase 5 — CONFIRM
  → GET /manager/configuration/validation
  → a "written but invalid" result is reported WITH the backup path,
    because a malformed ossec.conf stops the manager starting

Phase 6 — MAKE IT LIVE
  → services/manager_control.py: SSH "restart" selector
  → Wazuh does NOT hot-reload ossec.conf or the ruleset, so without
    this the change is correct on disk and inert
  → a FAILED restart does not fail the write: it returns a warning,
    the route flags the redirect restart_failed=1, and the page
    offers "Apply changes" → POST /api/manager/restart
```

**Why the backup is taken before the write and kept on this side:** the
API offers no way to write an arbitrary file on the manager, so the old
manager-side `.bak.<timestamp>` could not survive. The guarantee moved
rather than disappearing (`system-overview.md`).

**Why phase 5 exists at all:** the SSH tools validated their own writes.
Nothing does that now, so the dashboard asks the manager directly. One
extra round trip against a slow API is cheap next to a manager that won't
restart.

**Why phase 6 exists at all:** the SSH wrapper used to restart services
centrally on any mutating call. Work that moved to the API stopped
passing through it and inherited nothing, so saves silently never took
effect — a real shipped regression, recorded in
`../knowledge/design-decisions.md`. Phase 6 is that guarantee, rebuilt on
the API path. It applies to decoder/rule writes too, which have no phases
2–5 of their own but do have this one.

### Addressing a block

Not all blocks have a natural key, and getting this wrong edits the wrong
thing:

| Block | Identified by | Guard |
|---|---|---|
| `<integration>` | `name` | Rename refused; delete + add instead |
| `<localfile>` (file) | `location` | — |
| `<localfile>` (command) | `alias`, else the command text | An alias is **required** for command entries |
| `<email_alerts>` | zero-based **position** | Caller must also send the `email_to` it believes is there |

The `email_alerts` positional scheme is the fragile one: positions shift
whenever any block is added or removed, so every mutation carries a
confirmation value and a mismatch is refused rather than applied. The
operator's page may be describing a list that has since changed.

**Command `<localfile>` entries have no `<location>` at all** — Wazuh does
not require one. Keying them on location (as an earlier implementation did)
left them listable but impossible to edit or delete, and they are exactly
the entries the service-monitoring feature creates.

## Flow 3 — Host-OS configuration (dashboard → manager, over SSH)

The residual channel, for the three things the API cannot express. Its
shape is unchanged from before the migration:

```
  → services/ssh_transport.py builds a flat argument list, shlex.quote()s
    each argument, joins into one string ("mail update to@x.com ...")
  → paramiko connects with the restricted key
  → the manager's authorized_keys forced command ignores what was asked
    for and always runs config-router-wrapper.sh
  → the wrapper re-splits $SSH_ORIGINAL_COMMAND with `eval set --`
    (preserving the dashboard's quoting) and dispatches on the first word
    to one of FOUR targets: mail / rsyslog / deps / restart
  → the tool validates independently, backs up its target file, writes
  → IF the action was mutating (add/update/delete) AND succeeded, the
    WRAPPER restarts services — the dashboard never asks for this
```

**Phase 3 (persist) applies only to mail.** `storage.save_mail_settings()`
runs last and only on success, and the SASL password is never part of that
write. `data/settings.json` is meant to reflect what is actually live on the
manager, not what an operator attempted: if the apply step fails, the local
record must stay unchanged so the UI keeps showing the last known-good
state. Any new manager-reconfiguration feature must preserve this ordering.

## Flow 4 — Agents, groups and inventory

```
Browser → routes/agents.py (session required) → services/agents.py
  → GET  /agents                          list      (1 call, all agents)
  → GET  /agents?agents_list=<id>         detail    (1 call PER agent)
  → GET  /agents/<id>/key                 key
  → POST /agents                          register  → {id, key}
  → DELETE /agents?agents_list=<id>&...   remove
  → GET/POST/DELETE /groups...            group inventory
  → PUT/DELETE /agents/<id>/group/<g>     membership
  → GET  /syscollector/<id>/services      inventory (?search= server-side)
```

**1. There is no persistence phase.** Nothing about an agent or group is
written to `data/*.json` — the manager's own database is the single store,
so every page load re-reads it. The key returned by `add`/`key` goes
straight to the browser and is never persisted (same write-only handling as
`sasl_pass`).

**2. The list/detail split is a load-bearing contract, not an
optimisation.** `list` is one call for all agents; `detail` is one call per
agent. `GET /api/agents/<id>` is therefore requested only when an operator
opens a drawer — never while rendering the table. Adding a column that
needs per-agent data would silently turn one call into N against an API
whose individual calls have been measured taking tens of seconds
(`wazuh-api.md`). The same rule is why the custom-file listing carries no
file content.

**3. Membership is free with detail.** `GET /agents?agents_list=<id>`
already returns `group` and `group_config_status`, so the drawer's group
section costs no extra request. After a membership change the dashboard
**re-reads** rather than patching its local copy: the manager decides the
resulting membership — removing an agent's last group puts it back in
`default` — so guessing would drift from the truth.

**4. Delete keeps a confirmation the API does not ask for.** The caller
must pass the name it believes belongs to that id, and a mismatch is
refused before any DELETE is issued. Agent ids get reused and the operator
may be looking at a stale page; with no manager-side tool left, this guard
lives in `services/agents.py`.

**Where agents actually come from:** on a manager running `authd`, agents
enroll themselves. The dashboard's `add` is a secondary path for when
auto-enrollment is off or a key must be issued in advance. Nothing here
pushes a key anywhere: the dashboard can reach the manager, never the
monitored host.

## Flow 5 — Auth (dashboard-local, no manager involvement)

```
POST /register → create_user(): length, case-insensitive uniqueness,
  PBKDF2-HMAC-SHA256 (200k iterations) → data/users.json
POST /login → authenticate() → make_session_token(): username + 12h expiry
  + HMAC-SHA256 signature using a key persisted to data/secret.key
  → httponly, samesite=lax cookie
Every protected route → get_current_user() → username or None
```

This flow never touches the manager and has no dependency on the API or on
paramiko — if debugging an auth issue, stay entirely inside `auth.py` and
`routes/auth.py`.
