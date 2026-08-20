# Repository Map

Scope: pure navigation. Where things live and what owns what. For *why*,
follow the cross-reference — this file does not re-explain rationale.

```
wazuh-dashboard/
├── main.py                  # Entry point ONLY: resolves the bind address via
│                              # storage.load_run_host_port(), then uvicorn.run().
├── pyproject.toml           # setuptools packaging for dashboard_core AND the pinned
│                              # dashboard-machine deps. lxml is a RUNTIME dependency:
│                              # ossec.conf parsing moved here from the manager.
├── dashboard_core/          # THE installable package. All backend behaviour.
│   ├── app.py                 # FastAPI() object, static mount, router includes. Assembly only.
│   ├── config.py              # Constants + shared singletons: API_* (Wazuh API), SSH_*,
│   │                             # HOST/PORT/MAX_ALERTS, DATA_DIR, file paths, SESSION_*,
│   │                             # DEFAULT_MAIL_SETTINGS, the shared Jinja2 `templates`.
│   │                             # Read as `config.X` at call time. BASE_DIR is the PROJECT
│   │                             # ROOT (one level up) - templates/static/data live outside.
│   ├── auth.py                # Password hashing, user records, session tokens, get_current_user().
│   ├── validation.py          # Dashboard-side format checks: EMAIL_RE, HOST_RE, AGENT_*_RE
│   │                             # (AGENT_IP_RE bounds octets 0-255), CUSTOM_XML_FILE_RE,
│   │                             # RSYSLOG_FILE_RE, xml_well_formed_error().
│   ├── storage.py             # JSON persistence + load_run_host_port().
│   ├── alerts.py              # In-memory alert store + extract_ip/extract_fields.
│   ├── services/              # Manager-facing layer. Nothing here knows about HTTP routing.
│   │   ├── wazuh_api.py         # THE Wazuh API transport. Pooled session, token cache,
│   │   │                           # retry policy, error shaping. THE mock seam for tests.
│   │   ├── ossec_config.py      # ossec.conf: parse/serialize via lxml, block CRUD,
│   │   │                           # dashboard-side backups + rotation.
│   │   ├── agents.py            # Agents, groups, agent.conf, service inventory.
│   │   ├── custom_files.py      # Custom decoder/rule files (listing carries no content).
│   │   ├── plugins.py           # deps check/install + settings.json "plugins" writes.  [SSH]
│   │   ├── rsyslog.py           # rsyslog rule files + _friendly_error().               [SSH]
│   │   ├── ssh_transport.py     # The THREE remaining SSH senders: mail / rsyslog / deps.
│   │   └── logs.py              # Audit log writing (log_action).
│   └── routes/                # One APIRouter per route family. Nothing here talks to a
│       │                         # transport directly.
│       ├── dashboard.py         # /, /favicon.ico, /wazuh-webhook, /api/alerts, /api/clear, /health
│       ├── auth.py              # /login, /register, /logout
│       ├── agents.py            # /agents, /api/agents*, /api/groups* + service inventory
│       ├── pipeline.py          # /pipeline (collect | parse) + /api/pipeline/*; /isp redirect
│       ├── alerting.py          # /alerting (email | integrations)
│       └── settings.py          # /settings (general | packages) + redirects for moved URLs
├── tests/                   # pytest suite (../development/testing.md).
├── data/                        # Runtime-generated. Never hand-edit.
│   ├── secret.key                 # Session HMAC key
│   ├── settings.json              # host/port/note + non-secret mail fields + "plugins" status
│   ├── users.json                 # username -> {salt, hash, created}
│   ├── config_backups/            # Pre-change copies of ossec.conf, 5 most recent.
│   │                                 # The manager-side backup guarantee, relocated.
│   └── app_logs/                  # Audit log
├── templates/                       # Jinja2, server-rendered
│   ├── _sidebar.html                 # SHARED nav, included by every logged-in page.
│   │                                    # Active item derived from request.url.path.
│   ├── index.html                     # Dashboard shell
│   ├── agents.html                     # Agent list + groups card + detail drawer
│   ├── pipeline.html                    # Collect | Parse  (one tab's data per render)
│   ├── alerting.html                     # Email (delivery + rules) | Integrations
│   ├── settings.html                      # General | Packages  (both rendered; local reads)
│   └── login.html / register.html          # Logged-out layout, no sidebar
├── static/
│   ├── css/style.css                # All styling, incl. the .prov provenance badge
│   ├── js/app.js                    # ALL client logic. Page-specific blocks guarded by an
│   │                                   # id only that page renders.
│   └── vendor/                      # Vendored third-party (chart.umd.js, lucide.js, fonts).
│                                       # Never hand-edit; replace whole files to upgrade.
└── wazuh-integration/               # MANAGER-side artifacts. Never imported by the dashboard.
    ├── webhook/                       # → /var/ossec/integrations/
    │   ├── custom-webhook               # Shell entry point Wazuh calls
    │   ├── custom-webhook.py             # Passthrough POST logic
    │   └── ossec-conf-example.xml         # <integration> snippet
    └── ssh-dispatch/                  # → /usr/local/bin/. Reached only via the forced command.
        ├── config-router-wrapper.sh     # THE dispatcher. FOUR selectors: mail, rsyslog,
        │                                   # deps, restart. ../security/ssh-boundary.md
        ├── restart-services.sh          # postfix then wazuh-manager restart
        └── tools/
            ├── mail_config_tool.py        # DISPATCHED. Mail entry point.
            ├── postfix_config.py          # IMPORTED by mail_config_tool.py, never dispatched.
            ├── rsyslog-config-tool.py     # DISPATCHED. /etc/rsyslog.d/wazuh-*.conf
            ├── dependency_manager_tool.py # DISPATCHED. Allowlisted dpkg/apt-get.
            └── ossec-config-tool.py       # NOT DISPATCHED ANY MORE. Kept because
                                              # postfix_config.py and rsyslog-config-tool.py
                                              # import its lxml helpers. Its CLI is dead code
                                              # the dashboard no longer calls.
```

## Module map (which file owns what)

| Module | Responsibility | Look here for... |
|---|---|---|
| `main.py` | `uvicorn.run()` entry point | Changing how the server is launched |
| `storage.py` → `load_run_host_port()` | Bind address resolution | Where the runtime host/port comes from |
| `app.py` | The `FastAPI()` object, static mount, router includes | Mounting a new router; nothing else |
| `config.py` | All constants + the shared Jinja2 environment | API/SSH settings, alert cap, cookie name, paths |
| **`services/wazuh_api.py`** | **Build + send every Wazuh API call** | Transport, auth, retries, error mapping. Patch this in tests. |
| `services/ossec_config.py` | `ossec.conf` parse/edit/write + backups | Any ossec.conf block type; the localfile identity rules |
| `services/agents.py` | Agents, groups, agent.conf, inventory | Anything under /agents or /api/groups |
| `services/custom_files.py` | Custom decoder/rule files | The Pipeline page's Parse tab |
| `services/rsyslog.py` | rsyslog rule files **(SSH)** | The Pipeline page's remote log intake |
| `services/plugins.py` | Package check/install **(SSH)** | Console → Packages, the `checked_at` rules |
| `services/ssh_transport.py` | The three remaining SSH senders | What argument shape reaches a manager-side tool |
| `storage.py` | JSON read/write for `data/*.json` | Storage schema, new settings sub-keys |
| `auth.py` | Password hashing, user records, cookie sessions | Password policy, session lifetime, signing |
| `validation.py` | Dashboard-side format checks | Adding/loosening a field's UI-level validation |
| `alerts.py` | Webhook payload → display schema, in-memory store | Adding a displayed alert field |
| `routes/dashboard.py` | `/`, `/wazuh-webhook`, `/api/alerts`, `/health` | Anything the frontend polls or Wazuh posts to |
| `routes/agents.py` | `/agents` + agent/group JSON APIs | Any agent or group feature |
| `routes/pipeline.py` | `/pipeline` — log sources, group collectors, decoders/rules | Any log-pipeline feature |
| `routes/alerting.py` | `/alerting` — mail delivery, alert rules, integrations | Any notification feature |
| `routes/settings.py` | `/settings` — this console's own config + packages | Console-local settings only |

## Finding things by task

| Task | Start here |
|---|---|
| Add a new alert display field | `extract_fields()` in `alerts.py`, then `static/js/app.js`, then `templates/index.html` |
| Add/change anything that talks to the manager | `services/wazuh_api.py` for the call shape, then the owning service module. Check `wazuh-api.md` first — the endpoint's Content-Type and error shape are measured there, not guessable |
| Add a new `ossec.conf` block type | `BLOCK_SPECS` in `services/ossec_config.py`, then the owning route |
| Change what identifies a `<localfile>` | `localfile_key()` in `services/ossec_config.py` — file entries key on location, command entries on alias |
| Add an agent or group action | `services/agents.py` + the matching route in `routes/agents.py` + the agents block in `static/js/app.js` |
| Change what the agents table or drawer shows | `static/js/app.js` + `templates/agents.html`. A new column needing per-agent data first requires reading `execution-flow.md` — list is 1 call, detail is 1 call *per agent* |
| Change mail/Postfix handling | `mail_config_tool.py` + `postfix_config.py` (manager) + `routes/alerting.py` + `DEFAULT_MAIL_SETTINGS`/`load_mail_settings` (dashboard) |
| Change what an SSH mutation restarts | `is_mutating_action()` in `config-router-wrapper.sh` — nowhere else |
| Add an SSH dispatch target | Don't, unless the Wazuh API genuinely cannot express it. This is a reviewed widening of the blast radius — `../security/ssh-boundary.md` |
| Change password/session policy | `auth.py` |
| Move a function between modules | Update every `from ... import` **and** every `patch(...)` target under `tests/` in the same change |
| Add a new backend module | Create it under `dashboard_core/`; new subpackages go in `packages` in `pyproject.toml` |
