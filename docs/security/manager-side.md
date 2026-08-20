# Manager-Side Security

Scope: the validation, backup, and identity-confirmation guarantees the
manager-side tools (`wazuh-integration/ssh-dispatch/tools/*`) provide, and why each
exists. The channel that reaches these tools: `ssh-boundary.md`. The
dispatcher/permission model around them: `../development/deployment.md`.

> **This page now covers three features, not six.** `ossec.conf` blocks,
> decoders, rules, agents and groups moved to the Wazuh API and are no
> longer handled by any tool here — for those, the equivalent guarantees
> live on the dashboard side (`dashboard-side.md`,
> `../knowledge/design-decisions.md`). What remains under these tools is
> mail/Postfix, rsyslog files and package installation. The principles
> below still describe how those work, and are worth reading before adding
> anything to this side.

## The manager is the real trust boundary — always re-validate here

The dashboard validates form input for fast UI feedback (`dashboard_core/validation.py`:
`EMAIL_RE`, `HOST_RE`,
digit checks), but this validation is **not sufficient on its own** because
the manager-side tools are independently reachable — directly via `sudo`
on the manager for manual testing (`../development/testing.md`), and in
principle by anything else able to reach the forced-command SSH endpoint.
`mail_config_tool.py` and `rsyslog-config-tool.py` therefore repeat
equivalent validation (email format, numeric fields, non-empty required
host fields, project-owned file names) before touching any file. When
adding a new mutating field to one of these tools, the manager-side check
is the one that actually matters for safety; the dashboard-side check is a
UX convenience on top of it.

**The API path has no such second layer.** Nothing re-validates this
dashboard's field rules on the manager — Wazuh validates Wazuh semantics,
not `EMAIL_RE`. For anything travelling over the API, the route's
validation is the only gate, which is why those routes validate before
calling and the tests assert that nothing was sent when they reject.

## Backup-before-write is universal, not per-feature

Every mutation these tools still perform — mail settings, rsyslog rule
files — takes a timestamped backup (`<file>.bak.<timestamp>`) of the target
*before* writing, unconditionally, then keeps only the 5 most recent per
file (`rotate_backups()`). This is what makes a bad write recoverable
without version control on the manager itself, which may not exist in a
given deployment. Any new manager-side write path must call
`backup_config()` (defined in `ossec-config-tool.py` and imported from
there by the other tools) first — not optional per-feature, a standing
guarantee.

The guarantee did not lapse for the features that moved to the API: it
relocated to `data/config_backups/` on the dashboard, with the same
5-file rotation, because the API cannot write an arbitrary file on the
manager (`../knowledge/design-decisions.md`).

## Three guarantees that moved, and where they actually run now

The next three used to be manager-side guarantees, enforced by
`ossec-config-tool.py` while it was dispatched. **They still exist and
still matter, but the code that enforces them is not this code any
more.** `ossec-config-tool.py` still contains a byte-identical copy of
all three — `INTEGRATION_REQUIRES_HOOK_URL`/`_API_KEY`,
`email_alerts_check_confirm`, the `name`-pop on integration update — but
that copy is dead: nothing dispatches this script, so none of it
executes in production. The live enforcement is
`dashboard_core/services/ossec_config.py`, reached over the Wazuh API.
Recorded here anyway because the *reasoning* hasn't changed and is worth
keeping next to the manager-side history that motivated it; for the
executing code, treat `services/ossec_config.py` as the source of truth.

**`email_alerts` blocks: the ID-confirmation pattern is a race-condition
guard.** `<email_alerts>` blocks in `ossec.conf` have no natural unique
field, so a listing exposes a zero-based, **file-order-dependent,
temporary** index as the ID. Between a page load (which fetched that
index) and a form submit (`update`/`delete` using it), the underlying
file could have changed — another operator's edit, a manual change on
the manager — making the index stale and pointing at the wrong block.
The fix: every update/delete for this block type also sends the block's
current `email_to` value (`_confirm_email_to`); `update_block()`/
`delete_block()` in `services/ossec_config.py` compare it against what's
actually at that index and **refuse the operation on a mismatch** rather
than silently acting on the wrong block. Do not remove or bypass this
confirmation when touching `email_alerts` code — it is the only thing
preventing stale-index corruption for this block type.

**`integration` blocks: rename is refused by design, not unimplemented.**
`<integration>` blocks *do* have a natural unique key (`name`), so
`update` uses it directly — but `update` explicitly **cannot** change
`name` itself. This isn't a missing feature: `name` uniqueness is what
makes `update` identify the right block at all, so an in-place rename
would need its own collision-checking logic duplicating what delete+add
already guarantees for free. `dashboard_core/routes/alerting.py` keeps a
submitted `name` only when it matches the current one and targets
`original_name` (a hidden form field) for the actual update;
`update_block()` in `services/ossec_config.py` refuses a rename
independently if that route-level guard were ever removed. A rename must
always be delete-then-add, done as two explicit operations by the
operator.

## Read operations are guaranteed side-effect-free

This guarantee now applies to two different mechanisms, one per channel:

- **SSH** (`mail`, `rsyslog`, `deps`, `restart`): `is_mutating_action()`
  in `config-router-wrapper.sh` recognizes only `update`/`add`/`delete`
  as mutating (`ssh-boundary.md`, invariant 6), so `mail read`,
  `rsyslog list` and `deps check` never write a file and never trigger a
  restart. Any new read-style action added to an SSH-dispatched tool must
  be recognized as non-mutating in this same function, or every call to
  it will unexpectedly restart services.
- **Wazuh API** (everything else): the restart lives one level up, in
  `services/manager_control.py`. Only the write helpers call it —
  `push_tree()` for `ossec.conf`, `save_file()`/`delete_file()` for
  decoders and rules — so a read path has no way to reach it. There is no
  equivalent of `is_mutating_action()` to keep in sync here, because the
  split is structural rather than a list of action names to match
  against.

Together these are what let a Pipeline or Alerting page render safely on
every visit — reading is never the thing that risks an unwanted service
restart, on either channel.

> **A previous version of this section claimed the opposite** — that
> API-backed writes need no restart because "Wazuh's own daemons pick up
> an `ossec.conf` change on their own terms." That was written from
> assumption, never measured, and it is wrong: Wazuh does not hot-reload
> `ossec.conf` or the ruleset. The cost of the mistake was a shipped
> regression where every API-backed save landed on disk and never took
> effect, found by an operator raising an alert level from 3 to 7 and
> still receiving level-3 alerts. It is recorded here rather than quietly
> deleted because it is the cleanest example in this repository of why
> rule 1 in `CLAUDE.md` says to measure rather than assume when the
> manager is involved.

## Integration-type-specific requirements are enforced, on borrowed knowledge

`INTEGRATION_REQUIRES_HOOK_URL`/`_API_KEY` in `services/ossec_config.py`
(mirrored, unused, in `ossec-config-tool.py`) name which integration
`name`s need a `hook_url` (`slack`, `shuffle`, `maltiverse`) vs an
`api_key` (`pagerduty`, `virustotal`, `maltiverse`). This **is enforced**
— `_validate_integration()` refuses an add/update missing the required
field, it is not merely advisory. What has not changed: the list reflects
Wazuh's own built-in integrations' real requirements, but it was encoded
from external knowledge of those integrations, not derived from
`ossec.conf`'s schema itself. Before extending it, confirm the current
requirement against Wazuh's own integration documentation for the
version in use rather than assuming this repo's list is authoritative.
