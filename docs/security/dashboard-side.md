# Dashboard-Side Security

Scope: auth, session, and secret-handling decisions inside the dashboard
backend (`dashboard_core/auth.py`, `dashboard_core/storage.py`, `dashboard_core/routes/`),
plus the credential for the Wazuh API. Manager-side validation/backup
model: `manager-side.md`. The residual SSH channel: `ssh-boundary.md`.

## The Wazuh API credential — the largest open risk

This is where the migration to the Wazuh API moved the security question,
and it should be read before anything else on this page.

The API user's credentials live in `.env`
(`WAZUH_API_URL`/`USER`/`PASSWORD`/`VERIFY_SSL`), are read once at process
start, and are never written anywhere else. `services/wazuh_api.py` holds
the resulting bearer token in memory only, with a lifetime read from the
token itself.

**What is not yet true: the credential is not scoped.** The account in use
carries Wazuh's built-in `administrator` role, which permits far more than
the dashboard needs. The SSH forced command bounded a leaked key to a
handful of validated operations by construction; the API bounds nothing by
construction — it bounds by RBAC, and RBAC has not been configured.

This is a **known, accepted debt**, not an oversight: the migration was
done with a full-privilege user deliberately so that endpoint behaviour
could be measured before deciding what a minimal role looks like. It is the
single largest outstanding item in this repository's security posture, and
it is recorded here rather than in a backlog so it cannot be quietly
forgotten.

When it is addressed, the role needs (at minimum, from what the dashboard
actually calls): read/update on `manager:configuration`; read/write/delete
on decoder and rule files under `etc/`; agent read/create/delete/
modify_group; group read/create/delete/update_config; and syscollector
read. Anything beyond that is unused today.

**TLS verification is off by default.** `WAZUH_API_VERIFY_SSL` defaults to
`false` because the manager ships a self-signed certificate, which means
the API channel is not authenticated in the server direction. On a trusted
LAN with a test tool this is the same posture as the rest of the project;
turning it on requires a trusted certificate or CA bundle on the manager
first. The setting exists so that becomes a config change rather than a
code change.

## Why `/wazuh-webhook` and `/health` are unauthenticated by design

The Wazuh manager posts alerts as an HTTP client with no session and no
practical way to acquire dashboard credentials non-interactively — adding
auth here would mean provisioning and rotating a second credential on the
manager side purely to satisfy the dashboard's own login system, for data
(security alert metadata) that this tool already treats as low-sensitivity
test output. `/health` is open for the same class of reason: it's a
liveness probe, not a data surface. **Every other route** — `/`,
`/api/alerts`, `/api/clear`, and everything under `/settings`, `/alerting`,
`/pipeline`, `/agents` and their JSON APIs — requires a valid session via
`get_current_user()`. The JSON APIs answer an unauthenticated request with
a 401 JSON body rather than a redirect, because the fetch client depends on
that distinction. If asked to "secure" the webhook endpoint, the
correct fix is transport-level (network restriction, mutual TLS from the
manager) — not the dashboard's own login system, which the manager cannot
participate in.

## Password storage

PBKDF2-HMAC-SHA256, 200,000 iterations, random 16-byte salt per user
(`hash_password`/`verify_password`). No external hashing dependency
(`bcrypt`/`argon2`) was introduced — this keeps the dependency list in
`pyproject.toml` minimal
for a test tool where the user base is a handful of operators, not a
public-facing product. If this tool's threat model ever changes (exposed
beyond a trusted LAN, more users), this is the first place to revisit, and
the change should be a hash-scheme upgrade with migration, not a silent
requirements bump.

## Session mechanism

Signed, timestamped bearer token in an `httponly`, `samesite=lax` cookie —
`username:expiry:HMAC-SHA256(secret, username:expiry)`, base64-encoded.
No server-side session store; the token itself is the full session state,
verified statelessly on every request. `SECRET_KEY` is generated once
(`secrets.token_hex(32)`) and persisted to `data/secret.key` specifically
so a server restart doesn't invalidate every active session — treat this
file as equivalent to a signing credential, not a cache. Session lifetime
is fixed at 12 hours (`SESSION_MAX_AGE`); there is no refresh/renewal
mechanism — a session simply expires and the user logs in again.

## Why `data/*.json` files must never be hand-edited or seeded directly

`users.json`, `settings.json`, and `secret.key` are each written only
through the functions that own their schema (`create_user`,
`save_json`/`save_mail_settings`, `get_secret_key`). Hand-writing these
files risks: a user record without a valid salt/hash pair (silently
unauthenticatable, or worse, exploitable if reconstructed carelessly), a
`settings.json` missing the `mail` sub-key structure `load_mail_settings()`
expects, or a `secret.key` that doesn't match the hex-encoding
`get_secret_key()` assumes. To seed test data, drive it through the actual
`create_user`/settings-save code paths, not direct file writes.

## Two write-only secrets

Two values pass through this application and are never persisted. Both
follow the same pattern, and any new secret must follow it too: held for
one request, sent once, never logged, and represented afterwards by a
boolean or by nothing at all.

**The agent registration key.** Returned by `POST /agents` and
`GET /agents/{id}/key`, handed straight to the browser in that one
response, and stored nowhere. The tests assert this by scanning every file
under `data/` rather than checking one known location — the failure being
guarded against is a value leaking somewhere nobody thought to look.

**The SASL relay password**, below.

## The SASL password: write-only, by design

`sasl_pass` (the Postfix relay password) is the secret this tool handles
end-to-end, and it never touches disk on the dashboard:

- Held in a Python variable for the duration of one request only, passed
  directly into the SSH command sent to the manager
  (`../architecture/execution-flow.md`, Flow 3).
- `data/settings.json` stores only `sasl_pass_set: bool` — enough for the
  UI to show "configured"/"not configured" without ever knowing the value.
- Leaving the password field blank on save is a deliberate no-op signal
  ("keep the existing password"), not "clear the password" — this depends
  on the manager-side wrapper correctly re-splitting an empty argument as a
  genuinely empty string (`ssh-boundary.md`, invariant 3), not a literal
  quote-character pair.
- The one debug logging statement in `run_mail_command_via_ssh` prints
  connection parameters (`SSH_HOST`/`PORT`/`USER`/`KEY_PATH`) but
  deliberately never the password. Any new secret field added to this flow
  must follow the same write-only, never-logged, boolean-flag-only pattern.

## SSRF / trust note on manager-directed network calls

Both channels connect to an address configured in `.env` — `WAZUH_API_URL`
for the API, `WAZUH_SSH_HOST` for SSH. These are operator-controlled config
values, not user input from a request, so neither is a per-request
injection surface. Keep it that way: **never let a form field influence the
target host, port, user, key or API URL.** Those values come from `.env`
only, read at call time from `config.*` so tests can patch them, but never
from a request body.

The path *within* the API is a different matter and does take user input —
a file name, a group name, an agent id all end up in a URL. Every one of
those is pattern-validated before it is used (`CUSTOM_XML_FILE_RE`,
`AGENT_NAME_RE` for group names, `AGENT_ID_RE`), specifically so a value
carrying `..` or a path separator cannot steer a call outside the
collection it belongs to. A new endpoint taking a user-supplied path
segment must validate it the same way before it reaches
`wazuh_api.request`.
