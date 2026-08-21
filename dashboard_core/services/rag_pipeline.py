"""
The dashboard's own RAG assistant service - a separate local process
(default http://localhost:8000, see config.RAG_API_URL), not the Wazuh
manager and not part of this application's own process.

**Every call goes through the dashboard's backend, never from the
browser.** The alternative - the browser's JS calling RAG_API_URL
directly - has two real failure modes: the RAG service would need CORS
headers permitting the dashboard's origin, and "localhost" in a browser
resolves to whatever machine that browser is running on, which is only
the same machine as this service by coincidence. Proxying here means the
address is only ever resolved server-side, on the one machine it is
actually configured for - the same reason services/wazuh_api.py exists
instead of letting a template call the Wazuh API directly.

Same (ok, result) convention as the rest of the services layer. Unlike
wazuh_api.py there is no auth token to manage here - the endpoints shown
take no credentials - so this is the plain version of that module: one
pooled session, no retry-on-timeout complexity, because nothing here has
(yet) shown the pathological latency the Wazuh API was measured to have.
If that changes, the retry/timeout reasoning in wazuh_api.py's module
docstring is the place to borrow from, not reinvent.
"""

import threading

import requests

from dashboard_core import config

_session: requests.Session | None = None
_session_lock = threading.Lock()


def get_session() -> requests.Session:
    global _session
    with _session_lock:
        if _session is None:
            _session = requests.Session()
        return _session


def reset_session() -> None:
    """Drops the pooled session. Used by tests."""
    global _session
    with _session_lock:
        if _session is not None:
            _session.close()
        _session = None


def _request(method: str, path: str, **kwargs) -> tuple[bool, object]:
    """One call to the RAG service, translated to (ok, result).

    On success, result is the parsed JSON body. On failure, result is a
    message suitable for showing an operator - this service being off
    entirely (config.RAG_API_URL unreachable) is the expected common case
    given the feature is opt-in, not a surprise to hide.
    """
    session = get_session()
    url = f"{config.RAG_API_URL}{path}"
    try:
        response = session.request(method, url, timeout=config.RAG_API_TIMEOUT, **kwargs)
    except requests.ConnectTimeout:
        return False, f"Could not reach the assistant service at {config.RAG_API_URL}."
    except requests.ReadTimeout:
        return False, (
            f"The assistant service did not answer within {config.RAG_API_TIMEOUT}s."
        )
    except requests.RequestException as e:
        return False, f"Could not reach the assistant service: {e}"

    try:
        payload = response.json()
    except ValueError:
        payload = response.text

    if response.status_code >= 400:
        detail = payload.get("detail") if isinstance(payload, dict) else payload
        return False, str(detail) if detail else f"HTTP {response.status_code}"
    return True, payload


def status() -> tuple[bool, dict | str]:
    """configured: a model API key is set. chunks_available: anything has
    been ingested. Both false is the expected state the very first time
    an operator turns this feature on."""
    return _request("GET", "/status")


def ask(query: str, user: str | None = None) -> tuple[bool, dict | str]:
    body = {"query": query}
    if user:
        body["user"] = user
    return _request("POST", "/ask", json=body)


def list_documents() -> tuple[bool, dict | str]:
    """Read-only. What is actually indexed, for a small reference panel
    next to the question box - not a management UI (see routes/rag.py)."""
    return _request("GET", "/documents")
