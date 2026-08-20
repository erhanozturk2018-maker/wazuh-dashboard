# Design Decisions

Scope: decisions and their rejected alternatives, kept in one place so
other docs can reference rather than re-derive them. New entries should
follow the same shape: decision, alternatives considered, why rejected,
what would justify revisiting it.

## Manager channel: the Wazuh API for Wazuh, SSH for the host OS

**Decision (current):** the dashboard uses **two** channels, and which one
a feature takes is decided by what it touches. Everything Wazuh owns —
`ossec.conf`, decoders and rules, agents, groups, `agent.conf`,
syscollector — goes through the **Wazuh server API**. Three features stay
on the restricted SSH forced command because they touch the manager's
operating system and the API has no vocabulary for them: Postfix, rsyslog
files, and package installation.

**Why this did not contradict the earlier rejection.** The table below
still lists "a second HTTP API on the manager" as rejected, and that
rejection stands — but it never applied to the Wazuh API. That API is not
a second one: it ships with the manager, is already listening, and is what
Wazuh's own dashboard uses. Nothing new is exposed by talking to it. The
argument against *building* an API is not an argument against *using* one
that is already there. Recording this explicitly because the earlier
wording read, at a glance, as though it forbade exactly what was later
done.

**What the switch bought:** no custom manager-side scripts to deploy and
keep in sync, no `sudo` grants to maintain for them, versioned product
semantics instead of a bespoke CLI contract, and per-user RBAC instead of
all-or-nothing key possession.

**What it cost, stated plainly:** the forced command bounded a leaked
credential to a handful of validated operations *by construction*. An API
credential is bounded by RBAC instead — and RBAC is not yet scoped. The
blast radius moved from the transport to configuration, and that
configuration is still outstanding (`../security/dashboard-side.md`).

**Alternatives considered and rejected:**

| Alternative | Why rejected |
|---|---|
| Build a second HTTP API on the manager | Adds a new open port/service on security-sensitive infrastructure that must itself be secured and patched, just to serve one dashboard. Never applied to Wazuh's own built-in API — see above. |
| Full/unrestricted SSH | A leaked key becomes a general-purpose foothold — arbitrary command execution, potentially escalatable. |
| Stay entirely on the SSH forced command | Every manager capability needs a bespoke tool written, deployed, sudo-granted and version-matched by hand. The API already implements them, tested and documented by the vendor. |
| Move everything to the API, dropping the three host-OS features | Would delete working functionality (mail relay, remote log intake, dependency checks) to achieve tidiness. Scaling the product down was not the goal. |
| Hybrid (chosen) | Each feature travels the channel that can actually express it. Costs one extra transport to maintain. |

**What would justify revisiting:** dropping the three host-OS features
(the SSH channel and most of `wazuh-integration/` would go with them), or
a Wazuh version whose API covers them.

## Wazuh 5.0 is explicitly out of scope

**Decision:** target 4.14.x only.

**Why:** 5.0 removed the inventory API endpoints the service-monitoring
feature is built on, removed the `manage_agents`/`agent-auth` binaries, and
revamped RBAC. Supporting both would mean two code paths through the
newest and least-settled part of this codebase. It is a separate migration
with its own measurement pass, not a stretch goal to be absorbed silently.

## Backups moved to the dashboard rather than disappearing

**Decision:** `services/ossec_config.py` writes the pre-change `ossec.conf`
to `data/config_backups/` before every `PUT`, keeping the 5 most recent.

**Why the old rule could not survive:** the invariant used to be "every
manager-side mutation backs up its target file before writing", enforced by
each dispatched tool. The Wazuh API offers no way to write an arbitrary
file on the manager, so nothing on that side can take the backup any more.

**Why keep it at all:** the guarantee exists so the last few changes can be
undone. That need did not change with the transport. The location did.

**What the API added in exchange:** `GET /manager/configuration/validation`
after every write. The SSH tools validated their own output; nothing does
that now, so the dashboard asks the manager directly. A malformed
`ossec.conf` stops the manager starting, which makes one extra round trip
cheap — and the failure is reported *with the backup path*, since that is
the moment the operator needs it.

## Forced-command dispatcher: one router, central restart

**Decision (current):** one dispatcher, `config-router-wrapper.sh`, routes on
the *first word* of the SSH command — **four selectors now**: `mail` /
`rsyslog` / `deps` / `restart`. (`ossec` and `agents` were dispatched here
too until the Wazuh API took over their work; see "Manager channel" above
— this entry describes the router mechanism itself, which is unchanged by
that migration except for having fewer things to route.) The wrapper
re-splits `$SSH_ORIGINAL_COMMAND` with `eval set --` so the dashboard's
`shlex.quote()`ing survives, and centrally triggers a restart after any
successful **mutating** call (`add`/`update`/`delete`) to any underlying
tool. Read-only actions never restart. Two selector-specific refinements
keep that rule sensible: the `rsyslog` selector restarts **rsyslog itself**
(still centrally, in the wrapper, on the same mutating/read split) instead
of postfix+wazuh-manager, because an rsyslog rule file change affects
neither of those; and the `deps` selector never restarts anything, because
`check`/`install` are not mutating actions by the wrapper's definition and
installing a package must not bounce the manager.

**The two failure modes this shape exists to prevent.** Both are recorded
here because they are the reason the current design is not negotiable — not
as a version history:

1. **Unquoted `$SSH_ORIGINAL_COMMAND` expansion.** If the forced command
   interpolates `$SSH_ORIGINAL_COMMAND` directly rather than re-splitting it
   with `eval set --`, the shell word-splits it a *second* time on the
   manager, destroying the argument boundaries the dashboard established
   with `shlex.quote()`. Any argument containing a space or shell
   metacharacter (a SASL password is the obvious one) breaks or, worse,
   changes meaning. This is what the dashboard-side quoting discipline in
   `../development/coding-standards.md` depends on to be worth anything.
2. **Per-tool restart logic.** If restarts live *inside* each tool rather
   than in the wrapper, any tool that forgets one writes its change to disk
   correctly and has it silently never take effect. The concrete shipped
   symptom: an operator saves a new `email_alerts` block, sees a success
   message, and the block does nothing until something unrelated happens to
   restart `wazuh-manager`. Centralising the restart in
   `is_mutating_action()` is what makes every tool get the same guarantee
   for free.

> **Note on provenance.** Earlier drafts of this document narrated a
> numbered "v1 → v7" wrapper lineage. Those version numbers are not
> verifiable from anything in this repository — there is no tagged history,
> changelog, or superseded wrapper file to check them against, and the
> current `config-router-wrapper.sh` carries no version marker. The two
> failure modes above *are* verifiable: they are readable directly from
> what the current wrapper does (`eval set --`, `is_mutating_action()`).
> Treat the numbering as lost provenance and do not cite it as fact;
> other docs referring to "the v1 forced-command bug" mean failure mode 1.

## Restarting after an API-backed write

**Decision:** every write that goes through the Wazuh API restarts the
manager afterwards, from `services/manager_control.py`, over the SSH
`restart` selector. A restart that fails does **not** turn the write into
a failure; it returns a warning and the UI offers a retry.

**This entry exists because failure mode 2 above happened again, on the
other channel.** The wrapper's central restart was never removed — but
when `ossec.conf`, decoders and rules moved to the Wazuh API they stopped
passing through the wrapper, and inherited nothing in its place. The
symptom was identical to the one recorded above, down to the shape: a
save reported success, the file on disk was correct, and nothing took
effect. An operator raised a webhook alert level from 3 to 7 and kept
receiving level-3 alerts. Documentation actively made it worse by
asserting, without measurement, that Wazuh's daemons reload on their own
— see the correction note in `../security/manager-side.md`.

**Why the restart goes over SSH rather than `PUT /manager/restart`.**
`wazuh-control restart` bounces every Wazuh daemon, `wazuh-apid`
included, so the API cannot reliably report on restarting the process
that serves the request. The existing forced command already had a
`restart` selector that survives its own service going down, and it
reports per-service liveness afterwards. This is the one case where the
API *can* express something and SSH is still the right channel — the
usual rule in `../security/ssh-boundary.md` is about blast radius, and
this adds none: the selector was already there.

**Why a failed restart is a warning, not an error.** The change is on
disk. Reporting failure would tell the operator to re-apply something
already applied, and on this manager a redundant write is not free. The
split mirrors what the wrapper already did with its own exit code.
Because routes redirect after a successful save — which would drop the
message — the flag rides the redirect as `restart_failed=1` and the page
renders a retry control wired to `POST /api/manager/restart`.

**The transport had to be fixed before this worked.** The first version
reported restarts as failed — and sometimes never answered at all — while
the manager's own log showed them completing. The cause was not the
restart but the loop that read its result, which every SSH sender carried
its own copy of. Three defects, all now covered by tests in
`tests/services/test_ssh_service.py`:

- **stderr was never drained.** Paramiko buffers stdout and stderr behind
  one flow-control window. `restart-services.sh` writes
  `systemctl status --no-pager` to stderr on its failure paths, which
  overflows that window; once full, the *remote* process blocked on write
  and never reached its exit. Reading only stdout turned a script failure
  into a hang.
- **The poll loop had no deadline.** `recv_ready()` and
  `exit_status_ready()` are non-blocking, so `settimeout()` — which only
  bounds a blocking `recv()` — never applied. A stalled connection meant
  an unbounded busy-wait inside a request handler, so the HTTP response
  never came. This is what an operator saw as "Apply changes spins
  forever."
- **The exit status was read through a guard that discarded it.**
  `recv_exit_status() if exit_status_ready() else -1` returned -1 whenever
  the loop broke on EOF a moment before the status message arrived, so a
  successful restart was reported as a failed one — and the operator was
  shown a retry for work already done.

**Why service checks restart once, not three times.** Creating a check is
three writes, and each would restart by default. Restarts on this
deployment cost tens of seconds, and the two intermediate states are not
worth making live anyway: a collector with no decoder discards its
output, a decoder with no rule alerts on nothing. So `service_checks.py`
passes `apply_changes=False` to the intermediate writes and restarts once
at the end. A rolled-back creation restarts zero times, since nothing
survived to make live.

## `ossec.conf` editing: `lxml` over regex/text munging

**Decision:** parse via `lxml`, wrapping the file's multiple
`<ossec_config>` roots in a fake `<root>` element.

**Where this runs now, and why there are two copies.** The active editor
for `<email_alerts>`/`<integration>`/`<localfile>` blocks is
`dashboard_core/services/ossec_config.py` — the API hands over raw XML and
takes raw XML back, so the wrap/parse/edit/strip logic moved to whoever
holds the bytes. `ossec-config-tool.py` still contains the original
`load_wrapped_tree`/`save_wrapped_tree` pair, but only as a library:
`mail_config_tool.py` (via `postfix_config.py`) and
`rsyslog-config-tool.py` import it for the mail-specific `<global>` edit
and for their own backup helpers. Both copies exist and both matter; they
just don't share one one call path any more the way this entry originally
described.

**Why regex/text-based editing was rejected, on either side:** `ossec.conf`
is not well-formed single-root XML (multiple `<ossec_config>` roots,
repeated `<global>` blocks) — safely locating and replacing a specific
block by text pattern-matching risks either missing edge cases in
formatting/whitespace or corrupting adjacent blocks. A real parse tree,
even with the wrapper workaround, guarantees structural correctness. The
dashboard-side `parse_config()`/`serialize_config()` in `ossec_config.py`
were verified byte-identical on a round trip against a real manager before
anything else was built on top of them.

> **NOTE — historical defect this rule prevents.** An earlier version of
> the mail tool (`mail-config-tool.sh`, since deleted) edited `ossec.conf`
> with `sed -i` substitutions — unanchored and global-per-line, so it
> rewrote **every** matching `<email_to>` tag in the file, including ones
> inside unrelated `<email_alerts>` blocks, and silently "succeeded" when a
> tag was absent. Its replacement, `mail_config_tool.py`, scopes the mail
> fields to the `<global>` block only. The sed behaviour was a defect, not
> a contract, and was deliberately not reproduced anywhere — not in the
> manager-side library, and not in its dashboard-side counterpart.

## Mail tool split: `mail_config_tool.py` + `postfix_config.py`

**Decision:** the bash `mail-config-tool.sh` was replaced by two plain-
function Python modules: `mail_config_tool.py` (the only SSH-dispatched
entry point — CLI contract, validation, the `ossec.conf` `<global>` mail
fields) and `postfix_config.py` (owns `/etc/postfix/main.cf` and
`/etc/postfix/sasl_passwd`, runs `postmap` then `postfix check` after every
write, restores both files from their fresh backups if either check fails).

**Why two files, and why only one sudoers entry:** the two halves mutate
files with different owners, formats and failure modes; splitting them lets
each validate and roll back only what it touches. `postfix_config.py` is
only ever *imported* by `mail_config_tool.py`, never dispatched — so it
gets no `sudoers` line and no wrapper selector, keeping the SSH blast
radius at one entry point for the whole mail feature. The CLI argument
order and JSON-on-stdout convention match the old bash tool exactly, which
is what let the dashboard's `run_mail_command_via_ssh` survive the swap
with zero changes.

## Backup rotation: keep the 5 most recent per file

**Decision:** every backup (`<path>.bak.<timestamp>` on the manager, or the
equivalent under `data/config_backups/` on the dashboard) is followed by a
rotation that keeps only the 5 most recent *for that base path*, sorted by
the timestamp embedded in the filename (not filesystem mtime — the
filename is already the authoritative ordering and can't be perturbed by a
`touch`/copy).

**Two implementations now, by necessity, not by drift.**
`ossec-config-tool.py`'s `rotate_backups()` is what the still-SSH-dispatched
tools (`mail_config_tool.py`, `rsyslog-config-tool.py`) import and share on
the manager. `services/ossec_config.py` has its own `rotate_backups()` on
the dashboard, for the `ossec.conf` backups that moved there with the API
migration — the two sides can't share one Python import across a network
boundary, so this is one decision implemented twice, each keeping the same
keep-5 rule and the same filename-based sort. If the rule ever changes,
change it in both places.

**Alternative rejected:** unbounded accumulation (the previous behaviour)
— on a long-lived manager the config directory fills with hundreds of
stale copies, and the interesting backup (the one just before a bad
change) gets harder to find, not easier. Five covers "undo the last few
changes" — the only recovery scenario these backups exist for.

## Custom decoder/rule files: same verb shape, different transport

**Decision:** decoder and rule files are addressed by the same
list/get/add/update/delete shape as an `ossec.conf` block type. `add` is
create-only; `update` is create-or-overwrite; a file's name is its natural
key. File names are validated against a strict bare-`*.xml` pattern so the
channel can never write outside the owned directory; content is checked
for well-formedness only (Wazuh semantics stay the product's job).

**This moved channels, and the "why" moved with it.** These files used to
be `decoder_file`/`rule_file` kinds inside `ossec-config-tool.py`, reusing
the SSH wrapper's verb-keyed central restart for the same reason described
below for rsyslog. They are now `dashboard_core/services/custom_files.py`,
reached over the Wazuh API — `PUT /{decoders,rules}/files/{name}` — where
there is no wrapper and no verb-keyed restart to hook into. The restart
still has to happen, and it now happens explicitly in the write helpers
themselves (see *Restarting after an API-backed write*, below). The verb
shape was kept anyway, on the dashboard side, because it is what the rest of the
codebase's `(ok, result)` service functions already look like, not because
anything downstream depends on the specific words `add`/`update`/`delete`
any more.

**rsyslog files stay on the original reasoning, because they stay on
SSH.** `rsyslog-config-tool.py` mirrors the same verb set for exactly the
reason this entry originally gave: the wrapper's central mutating-action
restart keys on the verb, and inventing a different one (`put-file` etc.)
would have silently skipped the restart — the class of bug the
central-restart design exists to prevent. This reasoning only still
applies here, since rsyslog is one of the three features that never moved
to the API.

## Dependency manager: one generic tool, allowlisted packages

**Decision:** package check/install for what the UI now calls
**Console → Packages** (formerly "Manage Plugins") lives in its own tool
(`dependency_manager_tool.py`, the `deps` selector) rather than inside
`rsyslog-config-tool.py` or `mail_config_tool.py`, and only accepts
package names from a fixed allowlist (`rsyslog`, `postfix`).

**Why its own tool:** it covers dependencies for multiple unrelated
features — duplicating dpkg/apt logic per feature tool would drift.
**Why the allowlist:** the tool runs `apt-get install` as root through the
SSH channel; an open-ended package argument would turn a leaked dashboard
key into "install anything on the manager", far beyond the bounded blast
radius `ssh-boundary.md` promises. Extending the list is a reviewed
widening, same as adding a dispatch target.

**The `checked_at` contract:** the recorded plugin state in
`data/settings.json` (`"plugins"` key) changes in exactly two situations —
the operator confirming the Manage Plugins dialog, or a scoped
postfix-only re-check after a mail operation fails at runtime. Page loads
and tab switches read the stored state and never re-check; a re-check on
every render would hammer the manager with SSH+dpkg calls just to draw a
status pill, and would make `checked_at` meaningless as "when did a human
last verify this".

## Pages load one tab's data, reversing an earlier decision

**Decision:** `/pipeline` and `/alerting` fetch only the active tab's data;
switching tabs is a page load, not a client-side toggle.

**What this reverses:** the earlier, deliberate choice recorded for the
Settings page — render every tab on every load so switching is instant with
no round trip. That was the right trade when the data came from one fast
SSH call.

**Why it flipped:** measured latency. This manager's API is bimodal —
most calls under 0.2s, a minority 12s to 325s (`../architecture/wazuh-api.md`).
Preparing both tabs means paying for calls the operator may never look at,
and on a bad draw that is a half-minute page open. The same reasoning made
the custom-file listing stop carrying file content, and keeps per-agent
detail out of the agents table.

**`/settings` keeps the old behaviour**, because both its tabs are local
reads — a JSON file and a socket lookup. The principle is "don't pay for
what isn't shown", not "lazy-load everything".

## Provenance badges: naming what a screen actually writes

**Decision:** every settings card carries a small badge naming its target —
`This console`, `Manager · ossec.conf`, `Manager · groups`, `Host OS · SSH`.

**The problem it solves:** roughly half of these screens change a local
JSON file and half reconfigure a separate, security-sensitive machine, and
nothing in the interface distinguished them. The same "Save changes" button
wrote `data/settings.json` on one tab and restarted the Wazuh manager on
the next. An operator had no way to tell which without reading the code.

**Why a badge rather than a warning:** it is orientation, not an alarm. It
sits quietly on the card header and answers the question when asked, rather
than competing with the card's own title. Colour carries the distinction —
host-OS changes are the loudest, because they are the ones the Wazuh API
cannot even validate.

## `<localfile>` identity: location, then alias, then command

**Decision:** a log source is identified by `<location>` if it has one,
otherwise `<alias>`, otherwise the command text. The dashboard **requires**
an alias when creating a command entry, even though Wazuh does not.

**The bug this fixed:** the previous implementation keyed every localfile
on `location` and declared it required. Wazuh does not require a location
for `command`/`full_command` entries — three of the seven on the reference
manager had none. Those entries listed with an empty id and could not be
edited or deleted at all: visible, but unreachable.

**Why require an alias going forward:** it is what makes the entry
addressable afterwards, and it is also what a decoder matches on via
`<program_name>`. Both of the things a command entry is *for* depend on it.
Accepting one without an alias creates an entry the UI cannot manage and no
rule can match.

**Ambiguity is surfaced, not resolved:** two entries sharing a derived key
are flagged and refused for editing rather than having one silently chosen.

## Persistence: plain JSON files over a database

**Decision:** `data/*.json`, no database (`../architecture/system-overview.md`).

**Why:** data volume is small (a handful of users, one settings blob) and
the tool is explicitly disposable/test-scoped — a database would add an
operational dependency (install, migrate, back up) with no corresponding
benefit at this scale. **What would justify revisiting:** multiple
concurrent dashboard instances needing shared state, or a need for
relational integrity/transactions beyond what a single `threading.Lock`
around the in-memory alert list already provides.

## Custom webhook script instead of Wazuh's built-in Slack integration

**Decision:** ship `custom-webhook`/`custom-webhook.py` rather than using
Wazuh's built-in `slack` integration target.

**Why:** the built-in `slack` integration reformats the alert payload into
a Slack-specific message shape (text/attachments) before sending it —
the `rule`/`agent`/`full_log` fields the dashboard's `extract_fields()`
depends on get lost in that reformatting, and the dashboard shows `-`
everywhere. The custom script forwards the raw Wazuh alert JSON unmodified.
This is also documented as a common pitfall (`common-pitfalls.md`) because
it's easy to reach for the familiar `slack` name in `ossec.conf` out of
habit.

## Frontend third-party libraries: vendored locally, not CDN-loaded

**Decision:** Chart.js, Lucide, and the Manrope/JetBrains Mono fonts ship as
plain files under `static/vendor/`, fetched once from npm at setup time,
rather than loaded via `<script src="https://cdn...">` at every page load.

**Why the original CDN approach was abandoned:** three independent CDN
failures surfaced in practice, not in theory — `cdnjs.cloudflare.com` never
published Chart.js `4.4.4` (the version this project had pinned; a known
gap on cdnjs's side, confirmed via chartjs/Chart.js issue #11892), a
browser ad-blocker silently returned an empty response for the CDN script
with no console error, and the failure mode was indistinguishable from a
canvas-sizing bug or a color-contrast bug from the browser alone — costing
significant debugging time to isolate. Lucide is loaded identically on
**every** template (`index.html`, `agents.html`, `pipeline.html`,
`alerting.html`, `settings.html`, `login.html`, `register.html`), so the
same class of failure would break icons sitewide, including the login
page. Google Fonts had a safe CSS fallback
chain already in place, so it was lower-risk, but was vendored anyway for
consistency once the other two were.

**Why this doesn't violate the "no build step" non-goal**
(`../architecture/system-overview.md`): vendoring is a one-time file copy,
not a bundler/transpiler step — `static/vendor/*` are committed, static,
unmodified files, fetched once via `npm pack <package>` (or a manual
browser download) and never rebuilt. No `package.json`, no `node_modules`,
no install step for the dashboard machine at runtime.

**What would justify revisiting:** a library needs a security patch —
vendored files must be manually re-fetched and replaced (see
`../development/coding-standards.md`'s "treat `vendor/` as read-only"
rule), there's no automatic update path by design.
