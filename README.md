# Wazuh Alert Dashboard (Test Panel)

A lightweight FastAPI-based test tool that captures Wazuh manager alerts via
webhook and displays them in the browser as a live, filterable table. It also
includes a login system and pages that remotely reconfigure the Wazuh manager
without opening a terminal on it: `ossec.conf` blocks, custom decoder/rule XML
files, agents and agent groups, targeted service-status checks, outgoing mail
(Postfix) settings, project-owned rsyslog rule files, and a package
check/install flow for `rsyslog` and `postfix`.

**Two channels reach the manager, and which one a feature uses depends on
what it touches:**

- **The Wazuh server API** (port `55000`) — everything Wazuh itself owns:
  `ossec.conf`, decoders and rules, agents, groups, per-group `agent.conf`,
  and the syscollector inventory. This is Wazuh's own built-in API, already
  running as part of the product.
- **A restricted SSH forced command** — the three things the API has no
  vocabulary for, because they belong to the manager's *operating system*
  rather than to Wazuh: Postfix, rsyslog rule files, and package
  installation.

Both need configuring; Section 5 covers each in turn.

## Folder structure

```
wazuh-dashboard/
├── main.py                        # Entry point only: resolves host/port, then calls uvicorn.run()
├── pyproject.toml                  # Packaging for dashboard_core (pip install -e .)
├── dashboard_core/                  # The installable package — all backend code lives here
│   ├── __init__.py
│   ├── app.py                        # FastAPI() object, static mount, router includes
│   ├── config.py                      # Constants: API_*, SSH_*, HOST/PORT, data paths, session settings
│   ├── auth.py                         # Password hashing, user records, cookie sessions
│   ├── validation.py                    # Input format checks (email/host/agent id/name/IP)
│   ├── storage.py                        # JSON read/write for data/*.json + runtime host/port lookup
│   ├── alerts.py                          # In-memory alert store + webhook payload parsing
│   ├── services/                           # Manager-facing layer (Wazuh API + the residual SSH)
│   │   ├── __init__.py
│   │   ├── wazuh_api.py                      # THE Wazuh API transport (session, token, retries)
│   │   ├── ossec_config.py                    # ossec.conf parse/edit/write + dashboard-side backups
│   │   ├── agents.py                           # Agents, groups, agent.conf, service inventory
│   │   ├── custom_files.py                      # Custom decoder/rule files
│   │   ├── service_checks.py                     # Service checks: collector + decoder + rule together
│   │   ├── ssh_transport.py                       # The three remaining run_*_via_ssh() senders
│   │   ├── rsyslog.py                              # rsyslog rule-file wrappers          [SSH]
│   │   ├── plugins.py                               # Package check/install + "plugins" state  [SSH]
│   │   └── logs.py                                   # Audit log writing
│   └── routes/                                  # One APIRouter per route family
│       ├── __init__.py
│       ├── dashboard.py                          # /, /wazuh-webhook, /api/alerts, /api/clear, /health
│       ├── auth.py                                # /login, /register, /logout
│       ├── agents.py                               # /agents, /api/agents*, /api/groups*
│       ├── pipeline.py                              # /pipeline* (Collect / Parse)
│       ├── alerting.py                               # /alerting* (Email / Integrations)
│       └── settings.py                                # /settings* (General / Packages)
├── tests/                                            # pytest suite (run: pytest)
├── pytest.ini                      # pytest config (sets pythonpath = .)
├── Dockerfile                      # Container image (see "Running with Docker")
├── compose.yaml                    # Compose service: port, .env, data/ + SSH key mounts
├── .dockerignore                   # Keeps venv/data/keys out of the build context
├── .env                             # API + SSH connection settings (not committed, see "Environment variables")
├── data/                            # Created automatically at runtime, DO NOT commit
│   ├── secret.key                   # Session-signing key
│   ├── settings.json                 # Host/port/note + mail settings + package status (no plaintext passwords)
│   ├── users.json                     # Hashed user credentials
│   ├── config_backups/                 # ossec.conf copies taken before every write (5 most recent)
│   └── app_logs/                        # Audit log
├── templates/
│   ├── _sidebar.html                # Shared navigation, included by every logged-in page
│   ├── index.html                    # Overview (alerts)
│   ├── agents.html                    # Agents + agent groups
│   ├── pipeline.html                   # Pipeline (Collect / Parse sub-tabs)
│   ├── alerting.html                    # Alerting (Email / Integrations sub-tabs)
│   ├── settings.html                     # Console (General / Packages sub-tabs)
│   ├── login.html                         # Login page
│   └── register.html                       # Registration page
├── static/
│   ├── css/style.css                # Styling
│   ├── js/app.js                     # Client-side logic (search, filters, chart, detail panel)
│   └── vendor/                        # Vendored third-party libs + self-hosted fonts
└── wazuh-integration/                # Files that belong on the Wazuh MANAGER, not the dashboard
    ├── webhook/                        # Deploys to /var/ossec/integrations/ (Section 4)
    │   ├── custom-webhook                # Wazuh integration script (shell wrapper)
    │   ├── custom-webhook.py               # Wazuh integration script (actual logic, forwards alerts)
    │   └── ossec-conf-example.xml           # Example <integration> block for ossec.conf
    └── ssh-dispatch/                    # Everything reached via the SSH forced command (Section 5)
        ├── config-router-wrapper.sh        # Forced-command dispatcher (see Section 5.3)
        ├── restart-services.sh              # Restarts postfix + wazuh-manager (see Section 5.3)
        └── tools/                            # Independent tools the dispatcher routes to
            ├── mail_config_tool.py              # DISPATCHED — applies mail settings
            ├── postfix_config.py                 # imported by the mail tool, never dispatched
            ├── rsyslog-config-tool.py             # DISPATCHED — /etc/rsyslog.d/wazuh-*.conf files
            ├── dependency_manager_tool.py          # DISPATCHED — package check/install
            └── ossec-config-tool.py                 # NO LONGER DISPATCHED — kept only because the
                                                      # two tools above import its XML helpers
```

> **Note:** everything under `wazuh-integration/` is kept here for version
> control, but **none of it runs on the dashboard machine**. All of it must
> be deployed to the Wazuh manager, at fixed paths under `/usr/local/bin/`
> (except the webhook scripts, which go under `/var/ossec/integrations/`),
> and is only ever triggered remotely over SSH — see Sections 4 and 5 for the
> full setup.

## Two machines, two roles

This project always involves **two separate roles**, no matter what your
actual hardware/virtualization setup looks like:

- **Dashboard machine** — runs `main.py` (this project). Can be
  **Windows, macOS, or Linux** — anything that can run Python 3.
- **Wazuh manager machine** — always **Linux** (Wazuh manager only runs on
  Linux). This can be:
  - a **virtual machine** (VirtualBox/VMware/etc., any distro Wazuh
    supports), or
  - a **bare-metal / direct Ubuntu install** (no VM at all).

The setup steps for the manager side (Sections 4 and 5 below) are
**identical** either way — a VM's Linux and a directly installed Ubuntu look
the same to Wazuh and to this dashboard. The only thing that changes between
a VM and a bare-metal machine is *networking* (see the note in Section 3),
not the Wazuh/dashboard configuration itself.

---

## 1) Installing and running the dashboard (host machine)

Requires **Python 3.11+**. Pick the section for your OS.

> The backend is a package (`dashboard_core`), and its dependencies are
> declared in `pyproject.toml`. A single `pip install -e .` therefore does
> both jobs: it installs the pinned dependencies **and** makes
> `dashboard_core` importable. The `-e` (editable) install means your source
> edits take effect immediately, with no reinstall.

### Windows

```powershell
cd wazuh-dashboard
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -e .
python main.py
```
> If `Activate.ps1` is blocked by execution policy, run PowerShell as
> Administrator once and use:
> `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

### macOS

```bash
cd wazuh-dashboard
python3 -m venv venv
source venv/bin/activate
pip install -e .
python3 main.py
```
> On some Macs `python`/`pip` also work if Python 3 is the default; if not,
> always use `python3`/`pip3`.

### Linux

```bash
cd wazuh-dashboard
python3 -m venv venv
source venv/bin/activate
pip install -e .
python3 main.py
```
> On Debian/Ubuntu, if `venv` creation fails, install it first:
> `sudo apt install python3-venv`

### Running with Docker

A `Dockerfile` and `compose.yaml` are included as an alternative to the
virtualenv setup above. The image installs the package (`pip install .`) and
runs `python main.py`.

```bash
docker compose up -d
```

The compose service publishes port `5000`, passes the whole `.env` through
(`env_file`), so both the `WAZUH_API_*` and `WAZUH_SSH_*` variables reach
the container, and mounts two things from the host:

- `./data` → `/app/data`, so users, settings and the session key survive
  container restarts (this directory is runtime-generated — see Section 1's
  folder structure).
- `./.ssh/mail_updater_key` → `/keys/mail_updater_key`, **read-only**, with
  `WAZUH_SSH_KEY_PATH` overridden to that container path. The private key
  stays on the host; the container only ever gets a read-only view of it
  (the same dashboard-machine-only rule described in Section 5.4 applies).

So the key path inside `.env` is ignored under compose — the compose file
sets `WAZUH_SSH_KEY_PATH` explicitly. Everything else in `.env` is used as-is.

Once running, on the dashboard machine itself:
- UI: `http://localhost:5000` (login/registration required)
- Auto-generated API docs: `http://localhost:5000/docs`

**Do not use `localhost` from any other machine (including the Wazuh
manager)** — `localhost` always means "this machine itself," so from the
manager's point of view it would point back at the manager, not at your
dashboard. The correct address to give the manager is covered in Section 2.

---

## 2) Finding the dashboard machine's real network address

The Wazuh manager needs the dashboard machine's actual IP address, not
`localhost`. The easiest way is to log in to the dashboard and open
**Console → General** (`/settings`) — it auto-detects and lists this
machine's current IP address(es). You can also find it manually:

- **Windows:** `ipconfig` → look for "IPv4 Address" on the adapter connected
  to the manager's network.
- **macOS:** `ifconfig | grep "inet "` (or System Settings → Network).
- **Linux:** `ip addr show` (or `hostname -I`).

Use that IP together with the port (default `5000`) as the `hook_url` in
`ossec.conf` (Section 4), e.g. `http://192.168.X.X:5000/wazuh-webhook`.

---

## 3) Opening the firewall on the dashboard machine

Traffic goes both ways, so two directions have to be open:

- **Manager → dashboard, port `5000`** — for the alert webhook. The
  dashboard machine's OS firewall must allow inbound connections on it.
- **Dashboard → manager, ports `55000` and `22`** — `55000` for the Wazuh
  API (agents, groups, `ossec.conf`, decoders/rules, service inventory) and
  `22` for the three remaining SSH-backed features. Both are covered in
  Section 5.

### Windows
```powershell
New-NetFirewallRule -DisplayName "Wazuh Dashboard" -Direction Inbound -LocalPort 5000 -Protocol TCP -Action Allow
```

### macOS
System Settings → Network → Firewall → Options → allow incoming
connections for Python (or temporarily turn the firewall off while
testing). From the terminal:
```bash
sudo pfctl -d   # disables the firewall temporarily, for testing only
```

### Linux
```bash
sudo ufw allow 5000/tcp
```
(If you're not using `ufw`, allow port 5000/tcp in whatever firewall tool
your distro uses — `firewalld`, `iptables`, etc.)

> **Virtual machine note:** if the Wazuh manager runs inside a VM, make sure
> the VM's network adapter is set to **Bridged mode** (or another mode that
> puts it on the same LAN as the dashboard machine) — NAT-only mode will
> not let the manager reach the dashboard directly. If the manager is a
> **bare-metal / directly installed Ubuntu machine**, this doesn't apply —
> just make sure both machines are on the same network/subnet.

---

## 4) Setting up the Wazuh manager side — alert webhook (same for VM or bare-metal Linux)

**Important:** do NOT use `<name>slack</name>` in `ossec.conf`. The slack
script reformats the payload into a Slack-specific format (the rule/agent
fields get lost, and the panel shows "-" everywhere). Use this project's
`custom-webhook` script instead — it forwards the raw alert data unmodified.

1. Copy the script files to the manager (from the dashboard machine, e.g.
   via `scp`, a shared folder, or a USB drive):
   ```bash
   sudo cp wazuh-integration/webhook/custom-webhook /var/ossec/integrations/
   sudo cp wazuh-integration/webhook/custom-webhook.py /var/ossec/integrations/
   sudo chown root:wazuh /var/ossec/integrations/custom-webhook
   sudo chown root:wazuh /var/ossec/integrations/custom-webhook.py
   sudo chmod 750 /var/ossec/integrations/custom-webhook
   sudo chmod 750 /var/ossec/integrations/custom-webhook.py
   ```

2. Make sure the `requests` library is installed in Wazuh's own Python
   environment:
   ```bash
   sudo /var/ossec/framework/python/bin/pip3 install requests
   ```

3. Open `sudo nano /var/ossec/etc/ossec.conf`, paste the contents of
   `wazuh-integration/webhook/ossec-conf-example.xml` right above the closing
   `</ossec_config>` tag, and set `hook_url` to the dashboard machine's real
   IP address from Section 2 (never `localhost`), e.g.:
   ```xml
   <hook_url>http://192.168.X.X:5000/wazuh-webhook</hook_url>
   ```

4. Restart the manager:
   ```bash
   sudo systemctl restart wazuh-manager
   ```

5. Watch the logs:
   ```bash
   tail -f /var/ossec/logs/integrations.log
   ```

---

## 5) Setting up the Wazuh manager side — the two management channels

Four pages reconfigure the manager from the browser, with no terminal on the
manager involved:

- **Agents** (`/agents`) — registered agents (list, detail, register, remove,
  re-key), plus **agent groups**: create and delete groups, and add or remove
  an agent from one. Each agent's drawer also shows which groups it belongs
  to and whether it has actually synced that configuration yet.
- **Pipeline** (`/pipeline`) — how logs get in and get understood.
  *Collect*: `<localfile>` entries in `ossec.conf` (both file-reading and
  command-running kinds), per-group `agent.conf` collectors, the project's
  rsyslog rule files, and **service checks** — a guided flow that verifies a
  service exists on an agent, then writes the collector, decoder and rule
  needed to alert when it stops. *Parse*: the custom decoder/rule XML files
  under `/var/ossec/etc/decoders|rules/`.
- **Alerting** (`/alerting`) — how findings leave the manager.
  *Email*: mail **delivery** (the Postfix relay and its credentials) and
  mail **rules** (`<email_alerts>` blocks), on one screen but as two clearly
  separated sections, because rules do nothing if delivery is not working.
  *Integrations*: `<integration>` blocks (Slack, PagerDuty, VirusTotal,
  custom webhooks).
- **Console** (`/settings`) — this application's own settings only.
  *General*: the address/port this console binds to, plus a free-form note.
  *Packages*: the recorded status of the system packages the SSH-backed
  features depend on, and the dialog that verifies/installs `rsyslog` and
  `postfix`. That status is written to `data/settings.json` under
  `"plugins"` as
  `{"<package>": {"verified": bool, "version": str|null, "checked_at": ISO-8601}}`,
  and is read-only on page loads — `checked_at` only changes when you
  explicitly run the check, or when a mail save fails and the dashboard
  re-checks postfix (only postfix) automatically.

> Every settings card carries a small badge naming what it actually writes —
> `This console`, `Manager · ossec.conf`, `Host OS · SSH` and so on. Roughly
> half of these screens change a local file and half reconfigure a separate,
> security-sensitive machine, and the badge is how you tell which is which
> before pressing Save.

Older URLs still work: `/isp` redirects to `/pipeline`, and
`/settings/mail`, `/settings/email-alerts` and `/settings/integrations`
redirect into `/alerting`.

### Which channel does what

| Feature | Channel | Reaches |
|---|---|---|
| `ossec.conf` blocks (`email_alerts`, `integration`, `localfile`) | **Wazuh API** | `PUT /manager/configuration` |
| Custom decoder/rule files | **Wazuh API** | `PUT /{decoders,rules}/files/…` |
| Agents, groups, `agent.conf`, service inventory | **Wazuh API** | `/agents`, `/groups`, `/syscollector` |
| Mail delivery (Postfix relay + SASL) | **SSH** | `mail_config_tool.py` |
| rsyslog rule files | **SSH** | `rsyslog-config-tool.py` |
| Package check/install | **SSH** | `dependency_manager_tool.py` |

An API-backed save reads the current document, edits it, writes a backup to
`data/config_backups/` on the dashboard (5 most recent kept), pushes the
change, and then asks the manager to confirm the result is still valid.

An SSH-backed save connects over SSH, applies the change, and — if it was a
mutation (`update`/`add`/`delete`, never a plain `read`/`list`) — the manager
restarts the affected services automatically. Only *after* that succeeds does
the dashboard save a local copy of the non-secret fields to
`data/settings.json`; the SASL password is **never** written to disk here
(see "How the password is handled" below).

### Why the API for most of it, and restricted SSH for the rest

The dashboard could reach the manager several ways. What it does now, and
what was rejected:

| Approach | Verdict |
|---|---|
| **Wazuh's own server API (used for everything Wazuh owns)** | It ships with the manager, is already listening, and is what Wazuh's own dashboard uses — so nothing new is exposed by talking to it. It is versioned, documented, and access is bounded per-user by RBAC instead of by key possession. |
| Building a *second*, custom HTTP API on the manager | Rejected: an extra open port and service to secure and patch, on security-sensitive infrastructure, purely to serve one dashboard. **Note this never applied to Wazuh's own API** — the objection was to *building* one, not to using one that already exists. |
| Full/unrestricted SSH (dashboard can run any command) | Rejected: if the dashboard's private key leaks, an attacker gets arbitrary command execution on the manager. |
| **Restricted forced-command SSH (kept for the three host-OS features)** | The key can only ever trigger one wrapper script, which dispatches to four fixed targets that validate their own input. Even a leaked key cannot run arbitrary commands. |

> **A trade-off worth knowing about.** The forced command bounds a leaked
> credential *by construction* — four validated operations, no more. The API
> bounds one by **RBAC** instead, and the API user this project currently
> uses holds Wazuh's built-in `administrator` role, which is far wider than
> the dashboard needs. Scoping that role is a known, deliberate piece of
> outstanding work; `docs/security/dashboard-side.md` records the minimal
> permission set it would need.

Concretely, the SSH side is done with an `authorized_keys` **forced
command**: on the manager, the key used by the dashboard is bound to
`config-router-wrapper.sh`. Whatever the dashboard sends as its SSH command
(e.g. `mail update foo@bar.com ...`) arrives as `$SSH_ORIGINAL_COMMAND` —
the manager ignores the literal command and always runs the forced wrapper
instead, passing that string as its arguments. The wrapper looks at the
*first* word to decide which tool handles the request, and — if the request
was a mutation — triggers a restart afterwards (see 5.3). This means:

- The dashboard never specifies *where* any script lives or *how* it is
  invoked, and never has to ask for a restart itself. It opens an SSH
  connection with `paramiko` and sends a plain command string, e.g.:
  ```
  mail update to@example.com from@example.com 127.0.0.1 12 [smtp.example.com]:587 relay-user secretpass
  rsyslog list
  deps check rsyslog postfix
  ```
- On the manager, the forced command is what actually decides that this
  string gets handed to `/usr/local/bin/config-router-wrapper.sh`.
- Read-only modes (`mail read`, `rsyslog list`, `deps check`) work the same
  way and never trigger a restart.

### Where the manager-side files live

Everything under `wazuh-integration/ssh-dispatch/` is **manager-side** —
these files must exist on the Wazuh manager (VM or bare-metal), not on the
dashboard machine. Their fixed, expected paths are:

```
/usr/local/bin/mail_config_tool.py
/usr/local/bin/postfix_config.py
/usr/local/bin/rsyslog-config-tool.py
/usr/local/bin/dependency_manager_tool.py
/usr/local/bin/ossec-config-tool.py
/usr/local/bin/config-router-wrapper.sh
/usr/local/bin/restart-services.sh
```

> **Two of these are never dispatched over SSH**, and therefore get no
> `sudoers` entry and no wrapper selector:
> - `postfix_config.py` — a module `mail_config_tool.py` imports.
> - `ossec-config-tool.py` — used to be dispatched for `ossec.conf` work,
>   which now goes through the Wazuh API. It stays on disk only because
>   `postfix_config.py` and `rsyslog-config-tool.py` import its XML helpers.
>
> `agent-manager-tool.py` is **gone** — agent management moved to the API.
> If you are upgrading an existing manager, delete
> `/usr/local/bin/agent-manager-tool.py` and remove the `sudoers` lines for
> it *and* for `ossec-config-tool.py` (see 5.2). Leaving them grants
> privileges nothing uses.

Copies are kept in this repo under `wazuh-integration/` purely so they're
version-controlled together with the rest of the project; deploying them
means copying each file to its path above **on the manager**.

### 5.1 Deploy the scripts on the manager

A normal user can't `scp` straight into `/usr/local/bin/` (root-owned,
restricted directory), so copy to `/tmp/` first and move into place with
`sudo`:

```bash
scp wazuh-integration/ssh-dispatch/tools/mail_config_tool.py <User>@<manager-ip>:/tmp/
scp wazuh-integration/ssh-dispatch/tools/postfix_config.py <User>@<manager-ip>:/tmp/
scp wazuh-integration/ssh-dispatch/tools/rsyslog-config-tool.py <User>@<manager-ip>:/tmp/
scp wazuh-integration/ssh-dispatch/tools/dependency_manager_tool.py <User>@<manager-ip>:/tmp/
scp wazuh-integration/ssh-dispatch/tools/ossec-config-tool.py <User>@<manager-ip>:/tmp/
scp wazuh-integration/ssh-dispatch/config-router-wrapper.sh <User>@<manager-ip>:/tmp/
scp wazuh-integration/ssh-dispatch/restart-services.sh <User>@<manager-ip>:/tmp/
```

> **Windows PowerShell note:** always use forward slashes (`C:/Users/...`)
> when passing a local Windows path to `scp`. A backslash path like
> `C:\Users\<User>\Desktop\file.sh` gets misparsed — `scp` reads the `C:` as
> if it were a remote host, and the command fails with something like
> `Could not resolve hostname c`.

On the manager, back up anything that already exists, then move each file
into place:
```bash
for f in mail_config_tool.py postfix_config.py rsyslog-config-tool.py dependency_manager_tool.py ossec-config-tool.py config-router-wrapper.sh restart-services.sh; do
  [ -f "/usr/local/bin/$f" ] && sudo cp "/usr/local/bin/$f" "/usr/local/bin/$f.bak.$(date +%Y%m%d%H%M%S)"
  sudo mv "/tmp/$f" "/usr/local/bin/$f"
  sudo chown root:root "/usr/local/bin/$f"
done

sudo chmod 750 /usr/local/bin/mail_config_tool.py
sudo chmod 750 /usr/local/bin/postfix_config.py
sudo chmod 750 /usr/local/bin/rsyslog-config-tool.py
sudo chmod 750 /usr/local/bin/ossec-config-tool.py
sudo chmod 750 /usr/local/bin/dependency_manager_tool.py
sudo chmod 750 /usr/local/bin/restart-services.sh
sudo chmod 755 /usr/local/bin/config-router-wrapper.sh
```

> **Why `config-router-wrapper.sh` is `755` but the others are `750`:** the
> wrapper is the one file the SSH **forced command** runs directly, under
> the connecting user's own identity (e.g. `<User>`) — not root, and not via
> `sudo`. That user isn't the file's owner and isn't in its group, so
> without execute permission for "others" the forced command would fail
> with `Permission denied` before it even got a chance to call `sudo`. The
> tools it dispatches to, on the other hand, are always invoked by the
> wrapper *via* `sudo` — at that point the process is running as `root`,
> which always has owner-level rights regardless of "others" permissions,
> so `750` (no access for "others") is enough and is the tighter, preferred
> setting.

The individual tools support modes callable directly on the manager for
testing:

```bash
# Mail settings
sudo /usr/local/bin/mail_config_tool.py read
sudo /usr/local/bin/mail_config_tool.py update \
  to@example.com from@example.com 127.0.0.1 12 "[smtp.example.com]:587" relay-user 'secretpass'

# rsyslog rule files (wazuh-*.conf only)
sudo /usr/local/bin/rsyslog-config-tool.py list
sudo /usr/local/bin/rsyslog-config-tool.py update wazuh-tcp.conf '{"content":"module(load=\"imtcp\")"}'

# Plugin / dependency check (allowlisted: rsyslog, postfix)
sudo /usr/local/bin/dependency_manager_tool.py check rsyslog postfix
sudo /usr/local/bin/dependency_manager_tool.py install rsyslog

# Restart (normally triggered automatically, see 5.3 — can also be run standalone)
sudo /usr/local/bin/restart-services.sh
```

`mail_config_tool.py update` (the Python replacement for the old
`mail-config-tool.sh`, same CLI argument order) validates every field
(email format, numeric max-per-hour, no empty host fields) before touching
anything, then hands the Postfix half to `postfix_config.py`: both
`main.cf` and `sasl_passwd` are backed up, rewritten, recompiled with
`postmap`, and checked with `postfix check` — if either check fails, both
files are restored from the fresh backups. The `ossec.conf` mail fields
are edited through `ossec-config-tool.py`'s `lxml` helpers and scoped to
the `<global>` block (unlike the old bash `sed`, which clobbered every
matching tag file-wide). If the `SASL_PASS` argument is left empty, it
keeps the password that's already configured instead of wiping it. It does
**not** restart any services itself — see 5.3.

`ossec-config-tool.py` **has no CLI role any more.** Editing `ossec.conf`
blocks and the custom decoder/rule files moved to the Wazuh API, so nothing
dispatches it. It stays installed purely as a library: `postfix_config.py`
and `rsyslog-config-tool.py` import its `lxml` helpers for wrapping the
multi-root `ossec.conf` and for the backup/rotation convention. Do not give
it a `sudoers` entry.

`rsyslog-config-tool.py` manages only the project's own `wazuh-*.conf`
files under `/etc/rsyslog.d/` (distro files are unreachable), with the
same backup+rotation and JSON conventions. `dependency_manager_tool.py`
checks (`dpkg -s`) and installs (`apt-get install -y`) the allowlisted
`rsyslog`/`postfix` packages behind **Console → Packages**.

`restart-services.sh` validates the Postfix config (`postfix check`) and
then restarts `postfix` and `wazuh-manager` (via
`/var/ossec/bin/wazuh-control restart`), postfix first since the Wazuh mail
module depends on it. It exits non-zero and prints a clear error if either
service fails to come back up, without touching the other.

### 5.2 Create a dedicated SSH user and key pair (recommended)

Don't reuse your personal admin account for this — create a narrow-purpose
account on the manager whose SSH key can only ever run the wrapper below.

On the manager:
```bash
sudo useradd -m -s /bin/bash wazuh-dashboard-mail
sudo mkdir -p /home/wazuh-dashboard-mail/.ssh
sudo chmod 700 /home/wazuh-dashboard-mail/.ssh
```

Give that user passwordless `sudo` rights **only** for the exact scripts
the wrapper is allowed to call (needed because they edit root-owned files
and/or restart services, and the forced command runs with no TTY to type a
password into):
```bash
sudo visudo -f /etc/sudoers.d/dashboard-tools
```
Add (one entry per script, or combine on one line):
```
wazuh-dashboard-mail ALL=(root) NOPASSWD: /usr/local/bin/mail_config_tool.py
wazuh-dashboard-mail ALL=(root) NOPASSWD: /usr/local/bin/rsyslog-config-tool.py
wazuh-dashboard-mail ALL=(root) NOPASSWD: /usr/local/bin/dependency_manager_tool.py
wazuh-dashboard-mail ALL=(root) NOPASSWD: /usr/local/bin/restart-services.sh
wazuh-dashboard-mail ALL=(root) NOPASSWD: /usr/bin/systemctl restart rsyslog
```
> **One line per dispatched tool, and no more.** There is deliberately no
> entry for `postfix_config.py` or `ossec-config-tool.py` — both are only
> ever *imported* by other tools, never invoked directly — and none for
> `agent-manager-tool.py`, which no longer exists. **Upgrading an existing
> manager? Delete the `ossec-config-tool.py` and `agent-manager-tool.py`
> lines if they are still there.** The `systemctl restart rsyslog` line is
> the one exact command the wrapper runs after a mutating `rsyslog` call
> (rsyslog changes don't restart postfix/wazuh-manager).
Then:
```bash
sudo chmod 0440 /etc/sudoers.d/dashboard-tools
sudo visudo -c
```
> If `visudo -c` reports `bad permissions, should be mode 0440`, the file
> wasn't saved with the right mode — `chmod 0440` it again and re-check.

On the dashboard machine, generate a dedicated key pair (no passphrase,
since it needs to connect unattended):
```bash
ssh-keygen -t ed25519 -f wazuh-dashboard-mail-key -N ""
```
This creates `wazuh-dashboard-mail-key` (private key — stays on the
dashboard machine) and `wazuh-dashboard-mail-key.pub` (public key — goes to
the manager).

### 5.3 Bind the key to the forced command (router + auto-restart)

The same restricted SSH key serves every remaining manager-side operation,
so the forced command points at a small dispatcher,
`config-router-wrapper.sh`, that decides which tool handles a given request
based on its first argument and — if the request changed anything —
triggers a restart automatically afterwards.

**There are exactly four selectors: `mail`, `rsyslog`, `deps`, `restart`.**
That list is the blast radius: each selector is a program a leaked key can
run as root. `ossec` and `agents` used to be here and were **removed**, not
left in place, once their work moved to the Wazuh API — an unused entry
point still widens what a leaked key can reach and buys nothing.

> **Note on earlier, superseded versions of this section:**
> - The very first version bound the key directly with
>   `command="sudo /usr/local/bin/mail-config-tool.sh $SSH_ORIGINAL_COMMAND"`.
>   That's broken for any argument containing spaces or shell
>   metacharacters (e.g. a SASL password with a space in it):
>   `$SSH_ORIGINAL_COMMAND` is expanded *unquoted*, so the shell
>   word-splits it a second time and any quoting `shlex.quote()` added on
>   the dashboard side is destroyed instead of being honored.
> - A later version added a two-way dispatcher, `mail-config-wrapper.sh`,
>   that only ever routed between `mail-config-tool.sh` and
>   `ossec-config-tool.py`, and restarts were hard-coded inside
>   `mail-config-tool.sh` itself. That worked for the Mail tab, but meant
>   `ossec-config-tool.py` changes were never followed by a restart — so an
>   `<email_alerts>`/`<integration>` edit would be written to `ossec.conf`
>   correctly but silently never take effect until something unrelated
>   happened to restart the manager.
>
> The current `config-router-wrapper.sh` fixes both issues: it re-splits
> `$SSH_ORIGINAL_COMMAND` with `eval set --` (preserving the dashboard's
> quoting), routes on the **first** word
> (`mail` / `ossec` / `agents` / `rsyslog` / `deps` / `restart`) rather
> than assuming a fixed shape, and restarts services itself, centrally,
> after *any* mutating call to any tool succeeds — so every tab gets a
> consistent "change → restart" guarantee, and no tool needs its own
> restart logic.

Copy the **public** key's contents to the manager, then edit
`/home/wazuh-dashboard-mail/.ssh/authorized_keys` on the manager so the line
looks like this (all on one line):

```
command="/usr/local/bin/config-router-wrapper.sh",no-agent-forwarding,no-X11-forwarding,no-port-forwarding,no-pty ssh-ed25519 AAAA...your-public-key... wazuh-dashboard-mail
```

Then lock down permissions:
```bash
sudo chown -R wazuh-dashboard-mail:wazuh-dashboard-mail /home/wazuh-dashboard-mail/.ssh
sudo chmod 600 /home/wazuh-dashboard-mail/.ssh/authorized_keys
```

`config-router-wrapper.sh` itself (deployed to
`/usr/local/bin/config-router-wrapper.sh`, owned by `root:root`, mode `755`
— see 5.1 for why it differs from the other scripts) reads
`$SSH_ORIGINAL_COMMAND`, re-splits it *while preserving quoting*, dispatches
on the first word, and restarts services if the call both succeeded and was
a mutation:

```bash
#!/bin/bash
eval set -- "$SSH_ORIGINAL_COMMAND"
tool="$1"
shift
action="$1"

is_mutating_action() {
  case "$1" in
    update|add|delete) return 0 ;;
    *) return 1 ;;
  esac
}

case "$tool" in
  mail)
    sudo /usr/local/bin/mail_config_tool.py "$@"
    status=$?
    ;;
  restart)
    exec sudo /usr/local/bin/restart-services.sh
    ;;
  rsyslog)
    # rsyslog files affect rsyslog only - restart IT here (central, same
    # mutating/read split as below) and skip the wazuh/postfix restart.
    sudo /usr/local/bin/rsyslog-config-tool.py "$@"
    status=$?
    if [ "$status" -eq 0 ] && is_mutating_action "$action"; then
      echo "--- Applying changes: restarting rsyslog ---"
      if ! sudo /usr/bin/systemctl restart rsyslog; then
        echo "WARNING: rsyslog config was updated but rsyslog restart failed" >&2
      fi
    fi
    exit "$status"
    ;;
  deps)
    # check/install are never mutating actions - no service restart
    sudo /usr/local/bin/dependency_manager_tool.py "$@"
    status=$?
    ;;
  *)
    echo "ERROR: unknown tool selector '$tool'. Use 'mail', 'rsyslog', 'deps', or 'restart'." >&2
    exit 1
    ;;
esac

if [ "$status" -eq 0 ] && is_mutating_action "$action"; then
  echo "--- Applying changes: restarting services ---"
  sudo /usr/local/bin/restart-services.sh
  restart_status=$?
  if [ "$restart_status" -ne 0 ]; then
    echo "WARNING: config was updated but service restart failed (exit $restart_status)" >&2
  fi
fi

exit "$status"
```

A few details worth calling out:
- **Only mutating actions restart anything.** `mail read`, `rsyslog list`
  and `deps check` never touch the services — only `update`/`add`/`delete`
  do, and only if the underlying tool actually reported success
  (`status -eq 0`).
- **The dashboard's own request never asks for a restart.** It only ever
  sends `mail ...`, `rsyslog ...` or `deps ...`; the wrapper decides on its
  own based on which command was sent and whether it succeeded.
- **A failed restart doesn't hide a successful config change.** The
  wrapper's own exit code (`exit "$status"`) always reflects whether the
  underlying `mail`/`ossec` command succeeded, not whether the restart
  afterwards did. If the restart fails, a `WARNING:` line is printed to
  stderr (visible in the dashboard's error output) but the tool call itself
  is still reported as successful — the config is on disk correctly, it
  just may not be live yet.
- `restart` can also be sent directly (`SSH_ORIGINAL_COMMAND="restart"`),
  mainly for manual/manager-side testing — the dashboard itself never needs
  to send this, since mutations trigger it automatically.

What the `authorized_keys` line does:
- `command="..."` — **forces** every login with this key to run
  `config-router-wrapper.sh`, no matter what the client asked for.
- `$SSH_ORIGINAL_COMMAND` — the string the dashboard actually sent (e.g.
  `mail update to@example.com ...` or `rsyslog list`) is what the wrapper
  reads and dispatches on — never something the client controls the path or
  script name of.
- `no-pty`, `no-agent-forwarding`, `no-X11-forwarding`, `no-port-forwarding`
  — disables everything this key doesn't need, so it can't be used to open
  an interactive shell or tunnel through the manager.

### 5.4 Point the dashboard at both channels (`.env`)

On the **dashboard machine**, create a `.env` file next to `main.py` (this
file is not committed to version control). **Both blocks are needed** — the
API block powers most of the product, the SSH block powers the three
host-OS features:

```dotenv
# --- Wazuh server API (primary channel) ---
WAZUH_API_URL=https://192.168.X.X:55000
WAZUH_API_USER=wazuh
WAZUH_API_PASSWORD=<the API user's password>
WAZUH_API_VERIFY_SSL=false

# --- Restricted SSH (mail / rsyslog / packages only) ---
WAZUH_SSH_HOST=192.168.X.X
WAZUH_SSH_PORT=22
WAZUH_SSH_USER=wazuh-dashboard-mail
WAZUH_SSH_KEY_PATH=C:/path/to/wazuh-dashboard-mail-key
```

**API settings**

- `WAZUH_API_URL` — the manager's API base URL. Note `https` and port
  `55000`.
- `WAZUH_API_USER` / `WAZUH_API_PASSWORD` — the **server API** account.
  This is *not* the `admin` account you log into the Wazuh web interface
  with; that one belongs to the Indexer/Dashboard, and they are separate
  accounts with separate passwords. The API's own default user is usually
  `wazuh`. If the install left a `wazuh-install-files.tar` behind, the
  credentials are inside it as `wazuh-passwords.txt`.
- `WAZUH_API_VERIFY_SSL` — `false` by default, because the manager ships a
  self-signed certificate. Set it to `true` once a trusted certificate is
  in place.
- `WAZUH_API_TIMEOUT` — seconds to wait for one API call, default `60`.

**SSH settings**

- `WAZUH_SSH_HOST` — the manager's IP/hostname. `WAZUH_SSH_PORT` defaults
  to `22`.
- `WAZUH_SSH_USER` — the dedicated user created in 5.2.
- `WAZUH_SSH_KEY_PATH` — full path to the **private** key from 5.2 (never
  the `.pub` file).

The two channels are independent: one working does not imply the other. If
the API settings are missing, the pages that need them report
`Wazuh API settings are missing (...)`; if the SSH ones are, mail delivery,
rsyslog and packages report `SSH settings are missing (check
WAZUH_SSH_HOST/USER/KEY_PATH in the .env file)` instead of attempting a
connection.

> **If pages feel slow, suspect the manager before the dashboard.** A host
> running the Wazuh manager, indexer and web interface together on modest
> hardware answers most API calls in well under a second but some in tens of
> seconds. The dashboard tolerates this deliberately — it loads only the open
> tab's data and says so when it is still waiting — but raising
> `WAZUH_API_TIMEOUT` does not make a saturated manager faster. More RAM, or
> moving the indexer off it, does.

### 5.5 Test it end-to-end

1. Restart the dashboard so it picks up the new `.env` values.
2. Log in and open **Agents**. If the agent list loads, the API channel
   works — that page is API-only.
3. Open **Alerting → Email**. The *rules* half reads `ossec.conf` over the
   API; the *delivery* half writes Postfix over SSH, so saving delivery
   exercises the SSH channel end to end.
4. On success you are redirected back with a confirmation and the manager
   is already reconfigured (and, for SSH-backed changes, the affected
   services restarted). On failure the form re-renders with the error
   inline and nothing is written to `data/settings.json`.
5. Double-check the SSH side directly on the manager:
   ```bash
   sudo /usr/local/bin/mail_config_tool.py read
   sudo /usr/local/bin/rsyslog-config-tool.py list
   sudo /usr/local/bin/dependency_manager_tool.py check rsyslog postfix
   ```
6. Confirm the wrapper's restart logic, running it **without `sudo`** (the
   forced command runs as the connecting user, not root — adding your own
   `sudo` strips the environment and gives a misleading result):
   ```bash
   SSH_ORIGINAL_COMMAND="mail read" bash /usr/local/bin/config-router-wrapper.sh
   # should NOT print "--- Applying changes ---"

   SSH_ORIGINAL_COMMAND="restart" bash /usr/local/bin/config-router-wrapper.sh
   # should print postfix + wazuh-manager restarted OK
   ```
7. Confirm the retired selectors really are gone (important when upgrading
   an existing manager):
   ```bash
   SSH_ORIGINAL_COMMAND="ossec list integration" bash /usr/local/bin/config-router-wrapper.sh
   # should print: ERROR: unknown tool selector 'ossec'
   ```

### How the password is handled

The SASL/relay password (`sasl_pass`) is treated as write-only:

- It's only ever kept in memory on the dashboard for the duration of the
  request, then sent once over the encrypted SSH channel as part of the
  `mail update` command.
- `data/settings.json` never stores it — only a boolean,
  `sasl_pass_set`, so the UI can show "Password configured" /
  "Password not configured" without knowing the value.
- Leaving the password field blank when saving tells
  `mail_config_tool.py` to keep whatever password is already configured in
  `/etc/postfix/sasl_passwd`, rather than clearing it. This relies on the
  wrapper re-splitting `$SSH_ORIGINAL_COMMAND` with `eval set --`, so an
  empty argument arrives as a genuinely empty string rather than a literal
  pair of quote characters.

---

## 6) Manual test (without Wazuh)

Run this **from the dashboard machine itself** first, then, once that
works, run it **from the manager machine** to confirm the network path
actually works end-to-end (replace `localhost` with the dashboard's real IP
when testing from the manager).

**Windows (PowerShell):**
```powershell
Invoke-RestMethod -Uri http://localhost:5000/wazuh-webhook -Method Post -ContentType "application/json" -Body '{"timestamp":"2026-07-17T14:30:00","rule":{"id":5710,"level":10,"description":"Bruteforce attempt detected","groups":["authentication_failed"]},"agent":{"name":"Kali-Test"},"full_log":"Failed password for invalid user root from 10.0.X.X"}'
```

**macOS / Linux (or Windows with curl installed):**
```bash
curl -X POST http://localhost:5000/wazuh-webhook \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2026-07-17T14:30:00",
    "rule": {"id": 5710, "level": 10, "description": "Bruteforce attempt detected", "groups": ["authentication_failed"]},
    "agent": {"name": "Kali-Test"},
    "full_log": "Failed password for invalid user root from 10.0.X.X"
  }'
```

If the second row appears in the dashboard table when run from the manager,
the network path and `hook_url` are correctly configured.

---

## Environment variables (`.env`)

Two groups are required, one per channel (Section 5.4). Everything else
falls back to a sensible default if omitted.

| Variable | Used for | Default |
|---|---|---|
| `DASHBOARD_HOST` | Interface the dashboard binds to | `0.0.0.0` |
| `DASHBOARD_PORT` | Port the dashboard listens on | `5000` |
| `DASHBOARD_MAX_ALERTS` | Max alerts kept in memory | `500` |
| `WAZUH_API_URL` | Wazuh server API base URL, e.g. `https://host:55000` | *(required)* |
| `WAZUH_API_USER` | Server API account — **not** the Indexer/Dashboard `admin` | *(required)* |
| `WAZUH_API_PASSWORD` | That account's password | *(required)* |
| `WAZUH_API_VERIFY_SSL` | Verify the manager's TLS certificate | `false` |
| `WAZUH_API_TIMEOUT` | Seconds to wait for one API call | `60` |
| `WAZUH_SSH_HOST` | Manager address for the SSH-backed features | *(required)* |
| `WAZUH_SSH_PORT` | SSH port on the manager | `22` |
| `WAZUH_SSH_USER` | Restricted SSH user (Section 5.2) | *(required)* |
| `WAZUH_SSH_KEY_PATH` | Path to the private key (Section 5.2) | *(required)* |

The API variables cover most of the product; the SSH ones cover mail
delivery, rsyslog files and package management. Missing one group disables
only that group's features.

Host/port set via the **Settings** page (General tab) take priority over
`DASHBOARD_HOST`/`DASHBOARD_PORT` once saved.

---

## v9.0 — Wazuh API as the primary channel, regrouped interface

- **Everything Wazuh owns moved to Wazuh's own server API** — `ossec.conf`
  blocks, custom decoder/rule files, agents, groups, per-group `agent.conf`,
  and the syscollector inventory. New `.env` block: `WAZUH_API_URL`,
  `WAZUH_API_USER`, `WAZUH_API_PASSWORD`, `WAZUH_API_VERIFY_SSL`,
  `WAZUH_API_TIMEOUT` (Section 5.4).
- **SSH narrowed from six dispatch targets to four** — `mail`, `rsyslog`,
  `deps`, `restart`. The `ossec` and `agents` selectors were removed rather
  than left dispatchable; `agent-manager-tool.py` is deleted. **Upgrading an
  existing manager also means deleting that file and its `sudoers` line, plus
  the one for `ossec-config-tool.py`** (Section 5.2).
- **`ossec.conf` backups moved to the dashboard** (`data/config_backups/`,
  5 most recent), since the API cannot write arbitrary files on the manager.
  Every write is now followed by asking the manager to validate the result.
- **Pages regrouped by what they write:** Overview, Agents | Pipeline,
  Alerting, Console. The meaningless "ISP" name is retired; `/isp` and the
  old `/settings/*` URLs redirect. Every settings card carries a badge naming
  its target, because half these screens change a local file and half
  reconfigure a separate machine.
- **New: agent group management** — create/delete groups, add and remove
  agents, and see whether an agent has synced its group configuration.
- **New: service checks** — a guided flow that verifies a service exists on
  an agent, then writes the three coupled pieces needed to alert when it
  stops (a `full_command` collector in the group's `agent.conf`, a decoder,
  and a rule). A partial failure rolls back what already landed.
- **Fixed:** `<localfile>` command entries had no `<location>` and were
  therefore listed but not editable or deletable; they are now identified by
  their alias. Also fixed: an IP field that counted digits instead of
  validating octets, and an integration rename that reported success without
  renaming anything.
- `lxml` is now a runtime dependency (`pip install -e .` covers it).
- Test suite rebuilt around the single API seam: 361 tests.

## v8.0 — ISP page, rsyslog & plugin management, Python mail tool

- **Mail tool rewritten in Python.** `mail-config-tool.sh` was deleted and
  replaced by `mail_config_tool.py` (same CLI arguments, same JSON/exit
  conventions — no dashboard-side change needed) plus `postfix_config.py`
  (the Postfix half: `main.cf`, `sasl_passwd`, `postmap`, `postfix check`,
  with rollback to the fresh backups if either check fails). `ossec.conf`
  mail fields are now edited via `lxml` and scoped to `<global>` — the old
  `sed` clobbered every matching tag file-wide.
- **Backup rotation.** Every manager-side `*.bak.<timestamp>` backup now
  keeps only the 5 most recent copies per file (sorted by the timestamp in
  the filename).
- **New ISP page** (`/isp`, its own sidebar entry) with two sub-tabs:
  *Decoders & Rules* — write/upload custom decoder and rule XML files
  (`/var/ossec/etc/decoders|rules/`); *Log Ingestion* — toggle
  `<localfile>` Logcollector entries in `ossec.conf` and manage the
  project's rsyslog rule files (`/etc/rsyslog.d/wazuh-*.conf`).
- **New Plugins tab** in Settings, with a Manage Plugins dialog that
  checks (and installs, if missing) the `rsyslog`/`postfix` packages on
  the manager via `dependency_manager_tool.py`, recording per-package
  `{"verified", "version", "checked_at"}` under `data/settings.json`'s
  `"plugins"` key. Page loads only read that state; a failed mail save
  additionally triggers a scoped re-check of postfix only.
- **Two new wrapper selectors:** `rsyslog` (restarts rsyslog — not
  postfix/wazuh-manager — after mutations) and `deps` (never restarts
  anything). Two new `sudoers` lines per tool plus one for
  `systemctl restart rsyslog` (see 5.2).
- Deferred to a future iteration: live running/active service status for
  `wazuh-manager`/`postfix`/`rsyslog` in the UI, and any in-app
  version-upgrade flow for those services.

## v7.0 — centralized auto-restart via the router wrapper

- Replaced the two-way `mail-config-wrapper.sh` with
  `config-router-wrapper.sh`, which routes on the **first** word of the SSH
  command (`mail` / `ossec` / `restart`) instead of assuming a fixed
  two-tool shape.
- Added `restart-services.sh`: validates Postfix config (`postfix check`),
  then restarts `postfix` and `wazuh-manager` (via
  `/var/ossec/bin/wazuh-control restart`), in that order, and fails loudly
  (non-zero exit + clear stderr message) if either service doesn't come
  back up.
- Removed the hard-coded `systemctl restart postfix` /
  `/var/ossec/bin/wazuh-control restart` calls from the end of
  `mail-config-tool.sh update` — restarts are now handled centrally by the
  wrapper, not duplicated inside individual tools.
- The wrapper now restarts services automatically after **any** successful
  mutating call (`mail update`, `ossec add`, `ossec update`,
  `ossec delete`) to either tool. Read-only calls (`mail read`, `ossec list`,
  `ossec get`) never trigger a restart.
- Root cause this fixes: previously, `<email_alerts>`/`<integration>`
  changes made via `ossec-config-tool.py` were written to `ossec.conf`
  correctly but **never took effect**, because nothing restarted
  `wazuh-manager` afterwards — only the Mail tab's tool had a restart step,
  and only for itself. All three tabs now get the same "change → restart"
  guarantee.
- `config-router-wrapper.sh` is deployed at `755` (root:root); the tools it
  dispatches to (`mail-config-tool.sh`, `ossec-config-tool.py`,
  `restart-services.sh`) are `750` — see Section 5.1 for why these differ
  (the wrapper runs directly under the connecting user's identity, the
  tools always run via `sudo` as root).

## v6.0 — email alerts & integrations management

- Two new tabs on the Settings page: **Email alerts** and **Integrations**,
  for managing `<email_alerts>` and `<integration>` blocks in the manager's
  `ossec.conf` without opening a terminal on the manager.
- Each existing block is shown as its own card with inline **Edit**/Delete
  actions, plus a fixed **+ Add new** card at the bottom of each tab —
  same server-rendered, no-AJAX pattern as the General/Mail tabs.
- Backend calls go over the same restricted SSH key as the Mail tab (see
  Section 5.3), reaching `ossec-config-tool.py` on the manager via the
  forced-command wrapper.
- `email_alerts` blocks have no natural unique key — the manager uses a
  temporary, file-order-based index as the ID, so every update/delete also
  sends the block's current `email_to` value for the manager to confirm
  before touching anything (protects against acting on a stale ID if the
  file changed between page load and submit).
- `integration` blocks are keyed by their `name` field, which cannot be
  changed via update (rename = delete + re-add).

## v5.0 — remote mail settings over SSH

- New **Mail** tab on the Settings page — configure the Wazuh manager's
  outgoing SMTP relay (`email_to`, `email_from`, `smtp_server`,
  `email_maxperhour`, `relayhost`, `sasl_user`, `sasl_pass`) without
  touching the manager directly.
- Changes are applied on the manager via a restricted/forced-command SSH
  key that can only run `mail-config-tool.sh` — see Section 5 for the full
  security model and setup.
- The SASL password is never written to disk on the dashboard; only a
  "configured / not configured" flag is stored locally.
- New dependency: `paramiko` (SSH client) — already listed in
  `requirements.txt`.

## v4.0 — login system + settings page

- **Register / Log in** — the dashboard is no longer open by default; create
  an account at `/register` and log in at `/login`. Passwords are never
  stored in plain text; they're hashed with `hashlib.pbkdf2_hmac` and kept
  in `data/users.json`.
- **Sessions** — handled with a signed cookie, no database or extra
  dependency required. Sessions last 12 hours.
- **Settings page** (`/settings`, requires login) — saves the host/port
  configuration persistently to `data/settings.json`. Fields start empty on
  first run; once saved, they're read automatically on the next
  `python main.py` run. It also auto-detects this machine's current IP
  address(es) so you always know what to put in the Wazuh manager's
  `hook_url` when moving the dashboard to a different machine.
- `/wazuh-webhook` and `/health` remain **open** (the Wazuh manager can't log
  in); the dashboard page, `/api/alerts`, and `/api/clear` require login.
- The new `data/` folder (users.json, settings.json, secret.key) is created
  automatically at runtime — no manual setup needed. **Do not commit this
  folder to version control**, it contains hashed credentials and the
  session-signing key.

## v3.0 features

- **Timeline chart** — a line chart (Chart.js, loaded from a CDN) showing
  alert volume per minute for recent alerts.
- **IP-based view** — the source IP is extracted either from the raw log
  line (e.g. `from 1.2.3.4 port ...`) or from Wazuh's `data.srcip` field,
  shown as its own table column; an IP seen more than once is highlighted
  in red.
- **Top triggered rules / top seen IPs** panels — live-updating summary
  lists at the top, based on the currently filtered data.
- **Tab title counter** — while the tab is in the background, new alerts
  show up as `(3) Wazuh Alert Dashboard` in the browser tab; it resets when
  you switch back to the tab.
- **Agent filter** — a dropdown automatically populated from the agent
  names seen in incoming data.
- **Time range filter** — quick "Last 5 min / Last 1 hour / Last 24 hours /
  All" buttons; the table, stats, chart, and summary panels all update
  together based on this filter.

Note: search, level, agent, and time filters are **all applied together**,
and every panel (table, stats, chart, summary lists) updates in sync.

## Notes

- Alert data is kept **in memory only** and is lost when the server
  restarts. For persistent storage, a database (e.g. SQLite) would need to
  be added.
- This tool is intended for **testing/development** only, not production
  (things like HTTPS and log rotation are still missing; basic login is
  now included but hasn't been hardened for production use).
- Chart.js, Lucide, and the project fonts are vendored locally under static/vendor/ — 
  no CDN or internet access is required at runtime.
- Keep the dashboard's private SSH key (Section 5.2) and `.env` out of
  version control — `.env` and any `*key*` files should be in `.gitignore`.
  `.env` now also holds the **Wazuh API password**, so treat that file with
  the same care as the private key.
- The API account currently used holds Wazuh's built-in `administrator`
  role, which is wider than this dashboard needs. Scoping it down is known,
  outstanding work — see `docs/security/dashboard-side.md`.
- `docs/` explains *why* the system is shaped this way (architecture,
  security model, the measured behaviour of this manager's API). This README
  covers setup and operation; the two are deliberately not duplicated.
