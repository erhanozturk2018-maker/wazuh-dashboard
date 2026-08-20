# Coding Standards

Scope: conventions to follow when writing or editing code in this repo, that
aren't self-evident from reading any single file. Skip anything obvious from
PEP 8 / standard FastAPI idioms — only documenting deviations and
repo-specific patterns here.

## Language and typing

Python 3.11+ (`pyproject.toml` sets `requires-python = ">=3.11"`) throughout
the dashboard backend modules and the manager-side
Python tools (`mail_config_tool.py`, `rsyslog-config-tool.py`). Modern union syntax (`str | None`,
`tuple[bool, str]`) is used consistently — match it; don't introduce
`Optional[...]`/`Union[...]` from `typing`. `async def` for every FastAPI
route handler, even ones with no `await` inside, for consistency across the
route table.

## Comment and message language: English throughout

The codebase was originally bilingual — the design rationale in `main.py`
and `wazuh-integration/ssh-dispatch/**` was written in Turkish, and the
`/settings*` routes returned Turkish validation errors. **That is no longer
the case: comments, docstrings and user-facing strings are now English
across the dashboard modules, the manager-side scripts and `tests/`.** Write
new comments and new user-facing messages in English, and keep the *content*
of the translated rationale intact when editing near it — the reasoning it
records (SSH argument construction, ID-confirmation safety logic,
permission-model explanations) is still the reason that code is shaped the
way it is.

## Persistence pattern: JSON files, one owner each

No ORM, no database (`../architecture/system-overview.md` explains why).
Every read/write of `data/*.json` goes through the shared
`load_json(path, default)` / `save_json(path, data)` helpers in `dashboard_core/storage.py` — never
`open()` a data file directly elsewhere. Each file has exactly one logical
owner even though `settings.json` holds two unrelated concerns
(host/port/note and mail) under separate top-level keys — see
`_settings_context()` / `save_mail_settings()` for the pattern of updating
one sub-key without disturbing the other. Follow this sub-key pattern
if you add a new settings category; don't create a new top-level file for
every new setting.

## SSH command construction: always `shlex.quote()`, never string-format

Every argument sent over the **SSH** channel passes through `shlex.quote()`
individually before being joined into the command string (see
`run_mail_command_via_ssh`, `run_rsyslog_command_via_ssh`). This is not
optional hardening — the manager-side wrapper's `eval set --` re-split
depends on receiving properly quoted input to preserve argument boundaries
(spaces in a password, etc.). Never `f"{arg}"` raw user input into an SSH
command string. Full flow: `../architecture/execution-flow.md`.

## XML editing: `lxml`, never regex or plain text munging

`ossec.conf` has multiple root `<ossec_config>` elements, which violates
well-formed single-root XML. Both sides of the codebase work around it the
same way: wrap the raw bytes in a fake `<root>` before parsing with `lxml`,
then strip the wrapper on write while preserving the original blocks and
the comments and whitespace between them.

The dashboard-side implementation is `parse_config()`/`serialize_config()`
in `services/ossec_config.py` — this is where `ossec.conf` editing lives
now that the API hands over raw XML and takes raw XML back. The
manager-side equivalents (`load_wrapped_tree`/`save_wrapped_tree` in
`ossec-config-tool.py`) survive only because `postfix_config.py` and
`rsyslog-config-tool.py` import them.

Any code that edits this file must reuse one of those pairs, never
implement its own parsing. Regex-based edits have already been tried and
rejected as unsafe — see the recorded `sed -i` defect in
`../knowledge/design-decisions.md`.

## Frontend: server-rendered, no framework, no build step

Jinja2 templates + one vanilla JS file (`static/js/app.js`). No npm, no
bundler, no component framework. Tab switching is **not one pattern
across the app** — pick the one that matches where the data comes from:
`settings.html` (Console) keeps client-side show/hide, with both tabs'
data rendered server-side on every load, because both are cheap local
reads. `pipeline.html` and `alerting.html` switch tabs via real page
links instead, loading only the active tab's data — rendering both would
mean paying for a Wazuh API call the operator may never look at, against
a manager whose individual calls have been measured taking tens of
seconds (`../architecture/wazuh-api.md`). Match the existing pattern for
the page you're touching; don't default to the client-side one just
because it used to be the only one. Add new client behavior to
`static/js/app.js`; don't introduce a second first-party JS file or a
framework dependency for a small addition.

`static/` is split into `css/`, `js/`, and `vendor/` — `vendor/` holds
third-party libraries (Chart.js, Lucide, self-hosted fonts) as plain files,
not CDN links (`../knowledge/design-decisions.md` explains why). Treat
`vendor/` as read-only/generated: to upgrade a library, replace the file(s)
wholesale from the upstream release, don't hand-edit them. First-party code
never goes in `vendor/`, and vendored code never goes in `css/`/`js/`.

## Validation is layered on SSH, single-sourced on the API

This split by channel, and getting it backwards means shipping a field
with no real trust boundary:

- **The three SSH-backed features** (mail, rsyslog, packages): validate
  in at least two places — the `dashboard_core/routes/` handler, using
  the patterns in `dashboard_core/validation.py` (fast UI feedback), and
  the manager-side tool it reaches (`mail_config_tool.py`,
  `rsyslog-config-tool.py` — the actual trust boundary, since these
  scripts are independently invokable on the manager). When adding a new
  validated field here, add checks in both places.
- **Everything Wazuh-API-backed** (`ossec.conf` blocks, decoders/rules,
  agents, groups): there is no second layer. Nothing on the manager
  re-validates this dashboard's field rules — Wazuh validates Wazuh
  semantics, not `EMAIL_RE`. The route's validation is the only gate, so
  it must run, and must run *before* the API is called, not after.

Full reasoning for both: `../security/manager-side.md`.

## Secrets: never logged, never persisted where a flag would do

The existing debug `print(f"[DEBUG] ...")` diagnostics in
`dashboard_core/services/ssh_transport.py` deliberately omit `sasl_pass`. Follow this pattern for any new secret field:
log connection parameters and outcomes, never the secret value itself; if a
UI only needs to know "is this configured," persist a boolean, not the
value (`sasl_pass_set` is the existing example). Full rationale:
`../security/dashboard-side.md`.

## Backend layout: an installable package, `main.py` is the entry point only

All backend code lives in the `dashboard_core` package, installed with
`pip install -e .` (`pyproject.toml`, setuptools). It is split into modules
by concern: `dashboard_core/config.py` (constants and the shared Jinja2
environment), `dashboard_core/auth.py`, `dashboard_core/validation.py`,
`dashboard_core/storage.py`, `dashboard_core/alerts.py`,
`dashboard_core/services/` (manager-facing: the Wazuh API transport and
its consumers — `wazuh_api`, `ossec_config`, `agents`, `custom_files`,
`service_checks` — plus the three remaining SSH senders and their
consumers) and `dashboard_core/routes/` (one `APIRouter` per route family).
`dashboard_core/app.py` holds the `FastAPI()` object, the static mount and
the router includes — assembly only. The root `main.py` holds *only* the
entry point: it asks `storage.load_run_host_port()` for the bind address and
calls `uvicorn.run()` — **do not add behaviour to either.** Anything the
entry point needs to *decide* belongs in a package module it can call, not
inlined into `main.py`; `load_run_host_port()` is the pattern to copy. Full
file-by-file map: `../architecture/repository-map.md`.

Imports inside the package are absolute and package-qualified
(`from dashboard_core.storage import load_json`), never bare
(`from storage import ...`) — the latter only ever worked because the
project root happened to be on `sys.path`.

The package deliberately does **not** contain `templates/`, `static/` or
`data/`; those stay in the project root, which is why
`dashboard_core/config.py` sets `BASE_DIR` to the package's *parent*
directory. If you ever move the package deeper, that is the one line that
has to change with it.

Two conventions make this split testable, and both are load-bearing:

- Values that tests need to redirect (`SSH_HOST`, `SSH_USER`,
  `SSH_KEY_PATH`, `SETTINGS_FILE`) are reached as `config.X` **at call
  time** — modules do `from dashboard_core import config` and then
  `config.X`, never `from dashboard_core.config import X`. A `from`-import
  of the *value* would bind it at import time and silently ignore a
  monkeypatch of `dashboard_core.config.X`.
- Everything else is imported by name, so a test patches a function where it
  is *used*, not where it is defined — e.g.
  `patch("dashboard_core.services.wazuh_api.request")`,
  not `patch("dashboard_core.services.ssh_transport....")`.

When a name moves between modules, update every `from ... import` and every
`patch(...)`/`monkeypatch.setattr(...)` target in `tests/` in the same
change. A patch aimed at a module that no longer looks the name up does not
error — it silently patches nothing and the test passes for the wrong
reason.
