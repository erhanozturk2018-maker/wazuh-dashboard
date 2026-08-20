# Common Pitfalls

Scope: traps specific to this repository's architecture that look like bugs
(or get silently misconfigured) but are actually well-understood, documented
gotchas. Not general Python/FastAPI advice.

**API-specific traps live in `../architecture/wazuh-api.md`**, not here —
the 1106 "section not present" error on an empty config, per-endpoint
Content-Type differences, failures arriving inside HTTP 200, and why
retrying a read timeout makes an overload worse. Read that page before
writing manager-facing code. The entries below are the ones that bite
outside the API client itself.

- **The dashboard hanging on a page that "should be instant".** This
  manager's API is bimodal: most calls finish in under 0.2s, a minority
  take tens of seconds to minutes, with nothing in between. A slow page is
  usually the manager, not the code. Two confirmations that it is not the
  dashboard: Wazuh's own `wazuh-wui` shows the same latency in
  `/var/ossec/logs/api.log`, and the host runs manager + indexer +
  dashboard on ~4 GiB with no swap. Do not "fix" it by adding retries —
  that makes it worse.

- **A service search returning the wrong service.** `?search=` on the
  syscollector inventory is a substring match across every field including
  the description, so asking a Windows agent for `Spooler` also returns
  *PrintScanBrokerService*. `find_service()` separates an exact name match
  from mere candidates for exactly this reason; never treat the first
  result as the answer.

- **A service state that looks current but is not.** The inventory is
  snapshot data. Scan times within one inventory on the reference manager
  spanned a month. Every normalized entry carries `scanned_at` and any UI
  showing a state must show it — the inventory answers "what did we last
  see", never "what is true now".

- **A `<localfile>` that cannot be edited or deleted.** Command entries
  (`log_format` of `command`/`full_command`) have no `<location>` — Wazuh
  does not require one. Anything keying them on location will list them
  with an empty id and never find them again. They are identified by
  `alias`, which is why the dashboard requires one when creating them
  (`design-decisions.md`).

- **Using `localhost` as the manager's `hook_url` or as the dashboard's
  advertised address.** `localhost` always resolves to "this machine" —
  from the manager's perspective, pointing `hook_url` at `localhost` sends
  alerts back at itself, not the dashboard. Always use the dashboard's real
  LAN IP (the Settings page auto-detects it via `get_local_ips()` for
  exactly this reason).

- **Configuring `<n>slack</n>` in `ossec.conf` instead of
  `custom-webhook`.** Wazuh's built-in Slack integration reformats the
  payload and drops the `rule`/`agent` fields the dashboard needs — see
  `design-decisions.md` for why the custom script exists specifically to
  avoid this.

- **VM networking left in NAT-only mode.** If the manager runs in a VM, NAT
  mode isolates it from the dashboard machine's LAN — it needs Bridged mode
  (or equivalent) to reach the dashboard directly for the webhook to work.
  Bare-metal manager installs aren't affected by this; only the VM case.

- **Unquoted forced-command expansion.** A `command="sudo /path/tool.sh
  $SSH_ORIGINAL_COMMAND"` style forced command (the original, superseded
  design) breaks on any argument with spaces or shell metacharacters. If
  this pattern is ever reintroduced — even for a *new* manager-side tool
  outside the existing wrapper — it reintroduces a previously-fixed bug
  class. See `../security/ssh-boundary.md`, invariant 3.

- **Testing the forced-command wrapper locally with `sudo` in front of the
  simulation command.** The real forced command runs as the *connecting
  user*, not root. Running
  `sudo SSH_ORIGINAL_COMMAND="mail read" bash config-router-wrapper.sh`
  to "test" it strips the environment/identity context and gives a
  misleading result unrelated to how it actually executes over SSH — see
  `../development/testing.md` for the correct invocation.

- **Windows paths with backslashes passed to `scp`.** A raw
  `C:\Users\name\file.sh` path gets misparsed by `scp` — it reads `C:` as
  if it were a remote hostname and fails with something like `Could not
  resolve hostname c`. Use forward slashes (`C:/Users/name/file.sh`) for
  any `scp` argument. (This does *not* apply to `WAZUH_SSH_KEY_PATH` in
  `.env` — that's read directly by Python via `os.environ.get`, not shelled
  out, so Windows backslashes there are fine.)

- **Assuming `email_alerts` IDs are stable identifiers.** They're a
  temporary, file-order-based index from the most recent `list` call, not a
  durable ID — see `../security/manager-side.md` for the confirmation
  mechanism that guards against acting on a stale one. Don't cache or
  reuse an `email_alerts` ID across page loads/requests.

- **Assuming an `integration` block can be renamed via `update`.** It
  cannot, by design (`../security/manager-side.md`, `design-decisions.md`)
  — rename requires delete + re-add.

- **Assuming an agent's key arrives as a bare string.** This inverted when
  agent management moved to the Wazuh API. The old SSH path
  (`agent_control -j -e`, confirmed on Wazuh 4.14) returned the key
  itself as a plain string, and `_agent_key_from()` existed specifically
  to unwrap that. **The API returns it as a dict entry instead** —
  `GET /agents/{id}/key` → `data.affected_items[0].key` — and
  `get_agent_key()` in `dashboard_core/services/agents.py` reads it that
  way directly; `_agent_key_from()` no longer exists. If you find
  yourself reaching for it, that is a sign the code you're looking at
  (or copying from) predates the migration.

- **Treating agent `000` as an enrolled agent.** `agent_control -l` always
  includes id `000` — the manager's own entry. It has no key to extract
  (`key 000` is meaningless) and must never be passed to `delete`. The
  agents drawer special-cases it: no key section, no danger zone, an
  explanatory note instead (`isManagerEntry()` in `static/js/app.js`). If
  agent handling is ever moved or rewritten, keep that exclusion — the
  manager-side tool does not refuse id `000` on its own.

- **Assuming the manual "Add agent" form is the normal enrollment path.**
  It isn't, on a manager with `authd` (port 1515) enabled: agents enroll
  themselves, and the recovery procedure for a broken agent is to delete
  its `client.keys` and restart the agent service, not to carry a key over
  by hand. The form stays because auto-enrollment can be disabled, and
  because pre-issuing a fixed key is occasionally wanted — it is a
  secondary path, and the UI says so. Don't "simplify" the agents page by
  assuming either path is the only one.

- **Assuming `lastKeepAlive` has one fixed shape.** The Wazuh API returns
  it as an **ISO-8601 string** (e.g. `"2026-08-17T08:35:37+00:00"`,
  confirmed live), which `new Date(...)` parses directly. The older SSH
  path (`agent_control -j`) reported it as a **Unix epoch string**
  (`"1785149045"`) instead — handing that to `new Date(...)` without
  first multiplying into milliseconds produces `Invalid Date`.
  `fmtKeepAlive()` in `static/js/app.js` still branches on both shapes
  defensively, plus the year-9999 "never seen" sentinel; the epoch branch
  is very unlikely to fire against the API path but costs nothing to
  keep.

- **Assuming alert history survives a restart.** The `alerts` list is
  in-memory only, capped at `DASHBOARD_MAX_ALERTS` (default 500). A
  dashboard restart loses everything received before it — there is no
  persistence layer for alert data by design
  (`../architecture/system-overview.md`).

- **Adding a manager-side operation and forgetting to update
  `is_mutating_action()`.** A new `add`/`update`/`delete`-style action that
  isn't recognized there will silently never trigger a restart — the config
  change writes correctly but never takes effect, reproducing the exact bug
  `design-decisions.md` documents as the reason the current wrapper design
  exists.

- **Believing dashboard-side form validation is always UX-only.** True for
  the three SSH-backed features (mail, rsyslog, packages) — their
  manager-side tools re-validate independently and are reachable without
  the dashboard's form at all (direct `sudo` invocation for testing), so
  that's the real boundary. **False for everything Wazuh-API-backed**
  (`ossec.conf` blocks, decoders/rules, agents, groups): nothing on the
  manager re-validates this dashboard's field rules there, so the route's
  validation is the only gate that exists. Assuming the old blanket rule
  for a new API-backed field means shipping one with no real check at
  all. See `../security/manager-side.md`.

- **Pinning a `<script src>`/CDN reference to a version the CDN doesn't
  actually host.** This project originally pinned Chart.js to `4.4.4` via
  `cdnjs.cloudflare.com` — a version cdnjs never published. The failure
  mode looked identical to an ad-blocker issue or a canvas-sizing bug
  (`typeof Chart` returned `"undefined"`, zero console errors, the CDN
  script request itself returned HTTP 200) — nothing pointed directly at
  the version number being the problem. This class of bug is now moot for
  Chart.js/Lucide/fonts specifically, since they're vendored locally
  (`../knowledge/design-decisions.md`), but the lesson generalizes: if a
  *new* CDN reference is ever added, verify the exact pinned version is
  actually published on that specific CDN before assuming a failure is
  network/extension-related.

- **Hand-editing a file under `static/vendor/`.** These are unmodified
  third-party library files (Chart.js, Lucide, font files) copied in
  wholesale, not authored in this repo. Any manual edit is silently wiped
  the next time that library is upgraded (a full-file replace, per
  `../development/coding-standards.md`), and there's no diff/record of
  what was changed. If a vendored library's behavior needs to change,
  either fix it in `static/js/app.js` (the integration layer) or fetch a
  patched/different version of the library — never edit inside `vendor/`.
