# Tests

This directory contains automated tests for the Wazuh Dashboard project.

Structure

api/
    FastAPI endpoint tests.

services/
    Business logic tests.

utils/
    Helper function tests.

integrations/
    Cross-component workflow tests.

conftest.py
    Shared fixtures:
    - `authenticated_client` / `unauthenticated_client` — a `TestClient`
      with or without a valid session cookie.
    - `api_stub` — replaces `wazuh_api.request`, the single seam for
      everything the Wazuh API does. Register replies with `.set(...)` /
      `.fail(...)`; any call not registered raises, so a test cannot
      quietly pass on a request it never intended to make.
    - `api_with_config` — an `api_stub` pre-loaded with a structurally
      real `ossec.conf` sample, for tests that exercise block CRUD.
    - An autouse `no_real_manager` guard that blocks both transports
      (`paramiko.SSHClient.connect` and `requests.Session.request`/
      `post`) for the whole suite. See `docs/development/testing.md` for
      why it covers both channels and what it deliberately does not cover.

All tests are implemented using pytest. Run them with `pytest` from the
repo root (`pytest.ini` sets `pythonpath = .`); the `dashboard_core`
package must be installed first: `pip install -e .`.
