# Testing

Scope: what the `pytest` suite covers, where it cuts, and the conventions
it depends on. Run it with `pytest` from the repo root (`pytest.ini` sets
`pythonpath = .`). 315 tests, no network access required.

## The one rule that matters most

**Nothing in the suite may reach a real Wazuh manager.** An autouse fixture
in `tests/conftest.py` blocks both transports at their lowest level:
`paramiko.SSHClient.connect` and `requests.Session.request`/`post`.

Blocking at the transport rather than at each caller is deliberate: one
seam covers every current caller and any future one, and it cannot be
forgotten when a new one is added. This is a **backstop**, not a substitute
for mocking — a test that needs a call to return something stubs it.

This guard was strengthened during the API migration and the reason is
worth remembering: the original version blocked only paramiko. When the
manager channel became HTTP, the suite could — and briefly did — issue real
requests to the operator's live manager just by rendering a page.

## The seam: `wazuh_api.request`

Everything the manager does over the API funnels through one function.
Patch it and the whole manager side is under test control. The `api_stub`
fixture does this:

```python
def test_x(authenticated_client, api_stub):
    api_stub.set("/agents", envelope([...]))       # succeed
    api_stub.fail("/groups", "manager unreachable") # fail
    ...
    assert api_stub.paths() == [...]                # what was actually sent
```

Two properties are load-bearing:

- **Anything not registered raises.** A test cannot quietly pass on a call
  it never intended to make — which is exactly how "rejects invalid input
  before calling the manager" assertions stay honest.
- **Longest matching fragment wins**, not insertion order. A test
  registering `/groups/ldap/configuration` beats a fixture's general
  `/groups` regardless of which was set first.

`api_with_config` builds on it, pre-serving a structurally real
`ossec.conf` (two `<ossec_config>` roots, one of each editable block) plus
the validation and listing calls a manager-backed page makes. Most block
CRUD tests want this one.

**This seam is one layer lower than the pre-migration suite's.** That
version mocked service functions such as `agent_command()` and therefore
exercised only the route body. Stubbing the transport means route, service
and error mapping are all under test together.

## What each directory covers

| Directory | Covers | Seam |
|---|---|---|
| `tests/services/` | Service-layer logic in isolation — `ossec_config` (XML round-trip, block CRUD, identity rules, backups), `agents` (agents, groups, inventory normalisation), `ssh_transport` (the three remaining senders), logging | `api_stub`, or a mocked `paramiko.SSHClient` |
| `tests/api/` | Route behaviour — auth gating, validation-before-call, response shapes, error → status mapping | `api_stub` |
| `tests/integrations/` | The composed path: browser → route → service → transport, and the ordering guarantees | `api_stub` + mocked SSH senders |
| `tests/utils/` | Manager-side tools as units, run directly on this machine | none — they touch tmp files only |

`tests/utils/` is the odd one: those tools are a **separate deployable**
that never executes in this repo at runtime, but they are plain Python and
their parsing/validation logic is worth testing here rather than only on a
live manager. Note that `test_xml_parser.py` and `test_custom_files_tool.py`
exercise `ossec-config-tool.py`, which is **no longer dispatched** — it
survives only as an imported module for the other tools' XML helpers, so
those tests now cover a library rather than a CLI.

## Assertions worth writing, and why

**Assert on what was *not* done.** Several tests check `api_stub.calls == []`
alongside a 400, because a rejection that still sends the request is not a
rejection. The same shape appears in `no_config_written()` in the
integration tests.

**Assert on the resulting document, not the call arguments.** The old suite
checked SSH argument vectors (`["add", "email_alerts", '{"..."}']`). With
read-modify-write there is no such vector — the meaningful assertion is
what the written XML contains, and crucially what it still contains: a
delete test that only checks the target is gone would miss a neighbour
being clobbered.

**Scan for secrets rather than checking one location.** The tests covering
the SASL password and agent keys walk every file under `data/`. The failure
being guarded against is a value leaking somewhere nobody thought to look,
which a targeted assertion cannot catch.

**Pin the surprising things.** `application/xml` on the group-configuration
endpoint, the tri-state `running` field, the 1106-means-empty mapping — all
have explicit tests, because each is a behaviour a well-meaning
simplification would break silently.

## Patch-target convention

Tests patch where a name is **used**, not where it is defined, and read
redirectable constants as `config.X` at call time. A stale patch target
silently patches nothing and the test passes for the wrong reason.

When a function moves between modules, update every `from ... import`
**and** every `patch(...)`/`monkeypatch.setattr(...)` target in the same
change. The migration produced a concrete example: `routes/settings.py`'s
mail handler moved to `routes/alerting.py`, so
`patch("dashboard_core.routes.settings.run_mail_command_via_ssh")` had to
become `...routes.alerting...` — the old target raised `AttributeError`
rather than passing quietly, which is the good outcome, but only because
the name disappeared entirely.

## What is not covered here

- **Anything requiring a live manager.** Endpoint behaviour was measured
  once and recorded in `../architecture/wazuh-api.md`; the suite trusts
  that record rather than re-verifying it on every run.
- **Client-side rendering.** `static/js/app.js` has no test infrastructure;
  changes there are verified by driving the running app.
- **The manager-side tools' effects on a real system** — Postfix reloads,
  `apt-get`, service restarts. `tests/utils/` covers their logic, not their
  consequences.

## Manual testing entry point

`POST /wazuh-webhook` accepts anything and degrades to placeholder text
rather than erroring, which makes `curl` the quickest way to exercise the
alert path without a manager. That tolerance is a documented property of
the endpoint, not an accident (`../architecture/execution-flow.md`).
