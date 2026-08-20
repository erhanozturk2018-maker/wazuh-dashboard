"""
================================================================================
Purpose
================================================================================
This module protects the single liveness surface of the Wazuh Alert
Dashboard: `GET /health` in `dashboard_core/routes/dashboard.py`. `/health` is one of exactly two
routes in the application that are deliberately unauthenticated (the other
is `/wazuh-webhook`) because it exists to answer one question cheaply and
without ceremony: "is the FastAPI process up and able to touch its own
in-memory state?" Nothing else in the system depends on this endpoint being
elaborate, and this test module exists to keep it that way while still
catching real regressions (e.g. an accidental auth requirement, a crash
under lock contention, or a schema change that breaks whatever external
tooling polls it).

================================================================================
Responsibilities
================================================================================
- Verify `GET /health` responds with HTTP 200 under normal conditions.
- Verify the JSON body always contains the two documented keys,
  `status` and `alert_count`, with correct types (`status` a string,
  `alert_count` a non-negative integer).
- Verify `alert_count` accurately reflects the current length of the
  in-memory `alerts` list at call time (0 when empty, N after N alerts
  have been ingested via `/wazuh-webhook`, back to 0 after `/api/clear`).
- Verify the endpoint requires no authentication/session cookie — this is
  a documented, intentional property (`docs/security/dashboard-side.md`),
  not an oversight, and a regression here (e.g. someone adding
  `get_current_user()` to this route "for consistency") should fail loudly.
- Verify the endpoint is safe to call concurrently with alert ingestion
  (it reads `alerts` under `alerts_lock`, same as `/wazuh-webhook` writes
  under it) — at minimum, that a call while alerts are being written does
  not raise.

================================================================================
System Boundaries
================================================================================
In scope: the `/health` route handler itself, and its direct read of the
module-level `alerts` list guarded by `alerts_lock`.

Out of scope: anything about *how* alerts got into that list (that is
`extract_fields`/`extract_ip`/`POST /wazuh-webhook`'s job — see whichever
module ends up covering the webhook itself), SSH/manager connectivity
(this endpoint has and should have zero dependency on `WAZUH_SSH_*`), and
authentication mechanics (this endpoint bypasses auth entirely by design).
If a future change makes `/health` report anything about SSH/manager
reachability, that is a deliberate scope change requiring an update to
this specification, not something to test defensively in advance.

================================================================================
Why These Tests Matter
================================================================================
`/health` is the cheapest possible smoke test for "is this deployment
alive," and it is also explicitly called out in `docs/development/testing.md`
as one of the two synthetic entry points usable without a real Wazuh
manager. If this endpoint silently starts requiring auth, returning a
different shape, or throwing under concurrent access, every piece of
tooling (manual `curl` checks, future CI smoke tests, uptime monitors)
that assumes "a 200 with `status`/`alert_count` means the process is
healthy" breaks quietly. Because the route is trivial, a regression here
is almost always a sign that something upstream (e.g. a shared
authentication decorator, a global middleware) was changed too broadly.

================================================================================
Production Files to Understand First
================================================================================
- `dashboard_core/alerts.py` — specifically: the `alerts`/`alerts_lock` module-level state
  (declared just above `extract_ip`), and the `@app.get("/health")`
  handler at the bottom of the file.
- `docs/security/dashboard-side.md` — "Why `/wazuh-webhook` and `/health`
  are unauthenticated by design" section; the authoritative rationale for
  this endpoint's auth-free status.
- `docs/development/testing.md` — confirms `/health` as one of the two
  routes designed as convenient synthetic-test entry points.

================================================================================
Testing Strategy
================================================================================
This is a Unit/Functional test module: it exercises a single FastAPI route
via `fastapi.testclient.TestClient` (or `httpx.AsyncClient` against the
app) with no real network, no SSH, and no manager involved. No mocking of
`paramiko` or the `run_*_via_ssh` functions is needed because `/health`
never calls them. State setup (empty vs. populated `alerts` list) should
be done by driving the actual application surface — e.g. posting to
`/wazuh-webhook` and reading `data/*.json`-free in-memory state back —
rather than by reaching into `alerts.alerts` directly, so the test also
incidentally exercises the real ingestion path. Reaching into `alerts.alerts`
directly is acceptable only for isolating a `/health`-specific edge case
(e.g. asserting `alert_count == 0` at the very start of a test run) where
going through the webhook would conflate two behaviors in one assertion.

================================================================================
Expected Test Scenarios
================================================================================
- Health check on a freshly started app (no alerts yet) returns 200 with
  `alert_count == 0`.
- Health check after one or more alerts have been ingested returns
  `alert_count` matching the actual count.
- Health check after `/api/clear` reflects the reset count.
- Health check succeeds with no `Cookie` header at all (proving no auth
  requirement).
- Response `Content-Type` and top-level JSON shape remain stable
  (`status`, `alert_count` keys present, no unexpected required keys).
- Repeated/rapid calls to `/health` do not raise or deadlock, including
  when interleaved with concurrent writes to `alerts`.

================================================================================
Out of Scope
================================================================================
- Testing SSH connectivity, manager reachability, or `.env`/SSH
  configuration — `/health` has no such dependency and must never be given
  one inside this module's tests (that would misrepresent the endpoint's
  actual contract).
- Testing the correctness of alert *content* (field extraction, IP
  parsing) — that belongs to whichever module covers `/wazuh-webhook` and
  `extract_fields`/`extract_ip`.
- Testing authenticated routes' behavior for comparison — a single
  assertion that `/health` requires no cookie is sufficient; broader
  auth-flow testing belongs to a dedicated auth test module.
- Load/performance testing beyond a basic concurrency sanity check.

================================================================================
Mocking Strategy
================================================================================
Nothing needs mocking for this module's core assertions: no `paramiko`,
no filesystem, no external service. The only "dependency" worth
controlling is the shared in-memory `alerts` state, which should be reset
between tests (e.g. via a fixture that clears `alerts.alerts` before/after
each test, or by calling `POST /api/clear` through an authenticated
session if session setup already exists in `conftest.py`) so that test
ordering does not leak `alert_count` between cases.

================================================================================
Assumptions
================================================================================
- Assumption: the project intends to adopt `pytest` + FastAPI's
  `TestClient` for any future automated suite, per the explicit
  recommendation in `docs/development/testing.md`; no test framework or
  `conftest.py` fixtures currently exist in the repository as of this
  writing.
- Assumption: `alerts`/`alerts_lock` remain process-global, in-memory,
  non-persistent state (per `docs/architecture/system-overview.md`'s
  "Non-goals" — no log rotation, no persistence for alert data). If this
  ever changes (e.g. alerts move to a database), this module's assumptions
  about test isolation via list-clearing become invalid and must be
  revisited.
- Assumption: `/health` will continue to report only process/in-memory
  status, never manager/SSH status — this is inferred from current code
  and the two-machine trust boundary described in
  `docs/architecture/system-overview.md`, not stated as an explicit
  permanent guarantee anywhere.

================================================================================
Success Criteria
================================================================================
A fully passing suite in this module guarantees that the dashboard process
can be reliably probed for liveness by any external tool without
authentication, that the reported alert count is trustworthy as a
lightweight signal of ingestion activity, and that this endpoint remains
free of any accidental new dependency (auth, SSH, disk I/O) that would
make it unsuitable as a liveness probe.

================================================================================
Maintenance Notes
================================================================================
Keep this module minimal on purpose — if `/health` grows new fields or
starts reflecting manager connectivity, add scenarios here but resist the
temptation to fold in unrelated coverage (e.g. full alert-ingestion
correctness) just because it is convenient to test via the same client
fixture. If `/health` ever gains an authentication requirement, this is a
breaking architectural change per `docs/security/dashboard-side.md` and
should be flagged for documentation review, not silently accommodated by
updating this test file's assertions alone.
"""

from fastapi.testclient import TestClient
from dashboard_core.app import app

client = TestClient(app)


def test_health_returns_200():
    response = client.get("/health")
    assert response.status_code == 200


def test_health_returns_expected_shape():
    response = client.get("/health")
    body = response.json()
    print("Health check response body:", body)
    assert "status" in body
    assert "alert_count" in body
    assert isinstance(body["alert_count"], int)


def test_health_requires_no_auth():
    # no cookies set at all
    response = client.get("/health")
    assert response.status_code == 200