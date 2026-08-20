# The Wazuh Server API channel

Scope: what this deployment's Wazuh API actually does, as measured rather
than as documented, and the client behaviour those measurements force.
Why the channel exists at all: `system-overview.md`. What still travels
over SSH instead: `../security/ssh-boundary.md`.

> **Everything below was observed against the live manager on 2026-08-18,
> not read from vendor documentation.** Where the two disagree, this file
> describes what the manager did. Re-measure before trusting any of it
> against a different Wazuh version — 5.0 in particular removed the
> inventory endpoints this feature set depends on.

Measured against: Wazuh `4.14.6` (revision `rc2`), API user `wazuh` with
the built-in `administrator` role, `rbac_mode: white`.

## Three transport rules that are not optional

Each of these was learned by breaking the manager, not by anticipating it.

### 1. One pooled session

A probe that opened a fresh TLS connection per request exhausted the API
after roughly a dozen calls: later requests died inside the TLS handshake,
and `/security/user/authenticate` then answered `500` for some minutes
afterwards. A single pooled `requests.Session` removed the failure
entirely. `services/wazuh_api.py` therefore keeps one module-level
session; do not construct ad-hoc sessions elsewhere.

### 2. Token caching, with the lifetime read from the token

The JWT carries a 900-second lifetime — read from its own `exp`/`nbf`
rather than hardcoded, so the client tracks the manager's configuration
instead of a number that silently rots. Authenticating per request would
triple call volume against an API that is already the bottleneck.

### 3. Never retry a read timeout

This is the counter-intuitive one, and the manager's own log settles it:

```
GET /syscollector/001/services {"search":"cron","limit":"1"}  done in 325.629s: 500
GET /syscollector/001/services {"search":"cron","limit":"1"}  done in 352.652s: 500
```

The client abandoned the first call after 25 seconds. **The manager kept
executing it for 325 seconds anyway** — disconnecting does not cancel the
work — and the retry queued a second job that ran for 352. Retrying a read
timeout stacks load onto an already-starved worker pool; it is how this
API reaches the state where even `GET /` takes 20 seconds.

So the client retries connection-level failures (nothing reached the
manager, so a retry costs it nothing) and the manager's own `error: 3021`
(which it emits only after it has already given up). A read timeout is
reported straight to the caller.

## This manager is slow, and it is not the dashboard's fault

Response times are bimodal: most calls land in 0.02–0.2s, a minority take
12s, 89s, 188s, even 325s. Nothing sits in between.

The decisive evidence that this is a property of the manager rather than
of this client: Wazuh's **own** dashboard (`wazuh-wui`, from 127.0.0.1)
shows 41s and 62s for its routine stats polls in the same log. The host
runs manager + indexer + dashboard on 3.8 GiB with **no swap**, while load
average sits near 0.01 on 4 cores — so the workers are *waiting*, not
computing, which points at `wazuh-db` contention rather than CPU.

Two consequences the UI is built around:

- **Pages fetch only what the open tab needs.** `/pipeline` and
  `/alerting` load one tab's data, not both. The older "render every tab
  so switching is instant" trade made sense over one fast SSH call; over
  this API it means paying for calls the operator may never look at.
- **Anything slow says so.** The agent drawer's fields switch from
  "loading…" to "still waiting for the manager" after four seconds,
  because an unqualified spinner through a 40-second wait is
  indistinguishable from a hung panel.

## Error shape: failures arrive inside HTTP 200

The API reports failure in the body, not the status line:

```json
{"data": {"affected_items": [], "failed_items": [{"error": {"code": 1106, "message": "..."}}]},
 "error": 1}
```

Success therefore means `error == 0` **and** an empty `failed_items` —
either alone is not enough. Checking `response.status_code` swallows real
errors silently.

### The 1106 trap

`GET /manager/configuration?section=email_alerts` returns error `1106`
("Requested section not present in configuration") when the section simply
is not in the file. That is the **normal** state of an untouched manager:
one with no `<email_alerts>` block has not failed at anything.
`wazuh_api.read_section()` maps 1106 to an empty list for exactly this
reason. Without it, a fresh manager greets the operator with an error
banner on a page that is working correctly.

## A rejected write may still have been written

Measured while building the service-check feature: `PUT /rules/files/{name}`
returned an error, and the file was **on the manager afterwards anyway**.

Any rollback that only undoes the writes it believes succeeded therefore
leaves an orphan behind. `services/service_checks.py` attempts its file
deletions unconditionally for this reason — deleting a file that was never
created is harmless, so the safe direction is always to try.

## "XML syntax error" from the rule endpoint usually is not one

`PUT /rules/files/{name}` reports `XML syntax error - Please, ensure file
content has correct XML` for failures that have nothing to do with the XML.
The same byte-identical minimal rule was **accepted in 5.7 seconds** while
the manager was idle and **rejected with that message** while it was busy.

The likely mechanism: validating a rule upload makes the manager re-load
its ruleset, which is expensive here; when that step fails or times out
internally, the API reports it as a content error. Rule uploads are
markedly heavier than decoder uploads, which stay sub-second throughout.

**So do not debug your XML on the strength of that message.** Confirm the
content parses locally, then retry when the manager is idle. Chasing it as
a content problem costs hours and finds nothing.

### It is also what a *rejected ruleset* looks like

A second, entirely different cause produces the identical message, and
this one is reproducible rather than load-dependent: content Wazuh's
ruleset compiler refuses. Measured on 4.14.6, uploading the same file with
only the `<field>` pattern changed:

| `<field name="service.service_id">` | verdict |
| --- | --- |
| `^Spooler$` | accepted |
| `Spooler\|Fax` | accepted |
| `(Spooler)` | accepted |
| `^Spooler$\|^Fax$` | accepted |
| `^Spooler\|Fax$` | accepted |
| `(Spooler\|Fax)` | **rejected** |
| `^(Spooler\|Fax)$` | **rejected** |
| `^(Spooler\|Fax)$` with `type="pcre2"` | accepted |

Every one of those documents is well-formed XML. What separates the two
rejected rows is **grouping**: `<field>`, `<match>` and `<regex>` default
to Wazuh's own OSRegex, which has no `(...)` groups — parentheses are
literal characters there, so parentheses *combined with* `|` is not a
pattern it can compile. Parentheses alone and `|` alone are both fine,
which is why this is easy to misread as random.

Write the alternation without grouping (`^a$|^b$`) or opt the element into
`type="pcre2"`. A duplicate rule id, an unknown `if_sid`, or a decoder
name already defined elsewhere are rejected the same way.

`services/custom_files.py` acts on this: it validates well-formedness
before uploading, so when the API still claims a syntax error the message
is *known* to be wrong, and the operator gets that explanation instead of
the manager's wording.

## Content-Type is not uniform, and guessing gets it wrong

| Operation | Call | Content-Type |
|---|---|---|
| Replace ossec.conf | `PUT /manager/configuration` | `application/octet-stream` |
| Upload decoder/rule | `PUT /{decoders,rules}/files/{name}?overwrite=&relative_dirname=` | `application/octet-stream` |
| **Write agent.conf** | `PUT /groups/{group}/configuration` | **`application/xml`** |

The group endpoint answers `HTTP 415` to octet-stream and names
`application/xml` explicitly, while its sibling upload endpoints require
octet-stream. This is the API's inconsistency, not a mistake in this
codebase — do not "unify" them without re-testing both.

## Read surfaces in use

| Purpose | Call |
|---|---|
| ossec.conf as raw XML | `GET /manager/configuration?raw=true` |
| one section, parsed | `GET /manager/configuration?section=global\|integration\|localfile` |
| config still valid | `GET /manager/configuration/validation` → `status: "OK"` |
| agent list | `GET /agents` |
| agent detail | `GET /agents?agents_list={id}` — carries `group` and `group_config_status` |
| agent key | `GET /agents/{id}/key` → `affected_items[0].key` |
| custom decoders/rules | `GET /{decoders,rules}/files?relative_dirname=etc/{decoders,rules}` |
| one file's content | `GET /{...}/files/{name}?raw=true&relative_dirname=...` |
| groups | `GET /groups`, `GET /groups/{g}/agents` |
| a group's agent.conf | `GET /groups/{g}/files/agent.conf?raw=true` |
| service inventory | `GET /syscollector/{id}/services` |

## ossec.conf round-trips safely

Read raw → edit with `lxml` → `PUT` raw back is byte-safe: writing the
identical bytes back produced a byte-identical file and left validation
reporting `OK`. This is what let the XML editing logic move from the
manager-side tool into `services/ossec_config.py` intact rather than being
rewritten.

## Service inventory — the one that decides a feature

`GET /syscollector/{id}/services` exists in 4.14.6 and is populated (165
entries on the Linux agent). **`?search=` filters server-side**, which is
what makes "does this agent actually run X" one cheap call instead of
fetching a whole inventory — and therefore what makes the
service-monitoring feature possible without connecting to the Indexer at
all.

Two properties any consumer must respect:

**The field shape differs by platform.** Both observed directly:

| | Linux | Windows |
|---|---|---|
| `service.state` | `active` | `RUNNING` / `STOPPED` |
| `service.sub_state` | `running` | blank |
| `service.start_type` | blank | `SYSTEM_START` / `DEMAND_START` / … |
| `service.enabled` | `enabled` / `static` | blank |

`services/agents.py::normalize_service()` flattens this so the UI never
branches on platform. Its `running` field is deliberately **tri-state**:
`True`/`False` when the state is recognised, `None` when it is not — an
unfamiliar value must read as unknown, never as stopped, because reporting
a healthy service as down is the failure that would erode trust in the
whole feature.

**It is snapshot data, not live state.** Scan times within a single
inventory on this manager spanned 16 July to 17 August while "today" was
18 August. Every normalized entry therefore carries `scanned_at`, and any
UI showing a service's state must show that timestamp beside it. A service
inventory answers "what did we last see", never "what is true now".

## Searching matches more than the name

`?search=` is a substring match across every field, including the
description. Searching a Windows agent for `Spooler` also returns
*PrintScanBrokerService*, whose description happens to mention a spooler.
`find_service()` therefore reports an exact name match as `exact` and
offers everything else only as `candidates` — handing back the first
result as though it were the answer would tell an operator a service
exists when it does not, and a check configured against a service the host
never runs is precisely how this feature would manufacture false alerts.
