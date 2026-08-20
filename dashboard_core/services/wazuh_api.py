"""
The transport to the Wazuh server API - the primary manager channel.

This module owns exactly one thing: getting a request to the manager's
REST API and turning its answer into ``(ok, result)``. It knows nothing
about ossec.conf, decoders, agents or groups - those live in the modules
that call this one.

Three behaviours here are not defensive luxuries. Each was measured
against a live Wazuh 4.14.6 manager and each is load-bearing:

1. **One pooled session.** A probe that opened a fresh TLS connection per
   request exhausted the API after roughly a dozen calls: subsequent
   requests died inside the TLS handshake and even
   ``/security/user/authenticate`` answered 500 for a while afterwards.
   A single pooled ``requests.Session`` removed the failure completely.

2. **Token caching with proactive refresh.** The API's JWT carries a
   900-second lifetime (read from the token's own ``exp``/``nbf``). One
   authentication per request would triple the call volume for no gain,
   so the token is cached and renewed before it expires - with a retry on
   401 in case the manager invalidated it early.

3. **Retry ONLY what a retry can help - never a read timeout.** The
   manager's API log settles what actually happens when a request runs
   long: a syscollector query this client abandoned after 25 seconds kept
   executing server-side for **325 seconds**, and the retry queued a
   second one that ran for **352 seconds**. Disconnecting does not cancel
   the work. Retrying a read timeout therefore stacks more long-running
   work onto an already-saturated worker pool and makes the outage worse,
   which is exactly how this manager gets into the state where even
   ``GET /`` takes 20 seconds.

   So: connection-level failures (nothing reached the server) are
   retried, and so is the manager's own ``error: 3021``, which it emits
   only after it has already given up. A read timeout is reported
   straight to the caller.

   This is not a local quirk of this client. The manager's own official
   dashboard (``wazuh-wui`` on 127.0.0.1) shows the same latency in the
   same log - 41s and 62s for a routine stats poll - so slow responses
   are a property of the manager, and the dashboard must be built to
   tolerate them rather than to hammer through them.

Error shape: the API reports *failures inside HTTP 200 bodies*, carrying
``error: <non-zero>`` and/or ``data.failed_items``. Checking the HTTP
status alone silently swallows real errors, so ``request()`` inspects the
body.

Settings are read as ``config.API_*`` at call time so tests can patch a
single module attribute and have every consumer see it.
"""

import base64
import binascii
import json
import threading
import time

import requests

from dashboard_core import config

# The API answers "that section isn't in ossec.conf" as an ERROR rather
# than as an empty result. For a manager with, say, no <email_alerts>
# block at all - a perfectly normal state - a naive caller would show the
# operator a failure. read_section() maps this code to "empty" instead.
MISSING_SECTION_CODE = 1106

# The manager's own distributed-API timeout. Transient, always retryable.
INTERNAL_TIMEOUT_CODE = 3021

_TOKEN_PATH = "/security/user/authenticate?raw=true"
# Renew this many seconds before the token actually expires, so a request
# never starts with a token that dies mid-flight.
_TOKEN_REFRESH_MARGIN = 120
# Used only if the token's own expiry cannot be read.
_TOKEN_FALLBACK_LIFETIME = 600

_session: requests.Session | None = None
_session_lock = threading.Lock()

_token: str | None = None
_token_expires_at: float = 0.0
_token_lock = threading.Lock()


class WazuhApiError(Exception):
    """Raised only for configuration problems that no retry can fix."""


def _require_settings() -> None:
    missing = [
        name
        for name, value in (
            ("WAZUH_API_URL", config.API_URL),
            ("WAZUH_API_USER", config.API_USER),
            ("WAZUH_API_PASSWORD", config.API_PASSWORD),
        )
        if not value
    ]
    if missing:
        raise WazuhApiError(
            "Wazuh API settings are missing (check "
            + "/".join(missing)
            + " in the .env file)."
        )


def get_session() -> requests.Session:
    """The one pooled session every call shares. See note 1 in the module
    docstring - per-request connections break this manager."""
    global _session
    with _session_lock:
        if _session is None:
            session = requests.Session()
            session.verify = config.API_VERIFY_SSL
            session.mount(
                "https://",
                requests.adapters.HTTPAdapter(pool_connections=2, pool_maxsize=8),
            )
            _session = session
        return _session


def reset_session() -> None:
    """Drops the pooled session and the cached token. Used by tests, and
    whenever the API settings change at runtime."""
    global _session, _token, _token_expires_at
    with _session_lock:
        if _session is not None:
            _session.close()
        _session = None
    with _token_lock:
        _token = None
        _token_expires_at = 0.0


def _token_lifetime(token: str) -> float:
    """Seconds until this JWT expires, read from the token itself.

    The payload is decoded WITHOUT verifying the signature - we are not
    authenticating anything here, only asking the issuer how long it
    intends the token to live, so the refresh interval tracks the
    manager's configuration instead of a number hardcoded here. Any
    parsing problem falls back to a conservative default.
    """
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        remaining = float(payload["exp"]) - time.time()
    except (IndexError, KeyError, ValueError, TypeError, binascii.Error):
        return _TOKEN_FALLBACK_LIFETIME
    return remaining if remaining > 0 else _TOKEN_FALLBACK_LIFETIME


def _authenticate() -> str:
    """Exchanges the configured credentials for a bearer token.

    Basic auth is accepted ONLY on this endpoint - every other path needs
    the bearer token, which is why a missing token shows up as
    "No authorization token provided" rather than as a credentials error.
    """
    _require_settings()
    session = get_session()
    last = "no attempt made"
    for attempt in range(3):
        try:
            response = session.post(
                f"{config.API_URL}{_TOKEN_PATH}",
                auth=(config.API_USER, config.API_PASSWORD),
                timeout=config.API_TIMEOUT,
            )
        except requests.ConnectTimeout:
            # Never reached the manager at all - a routing/firewall/wrong-host
            # problem, not a busy API. Worth another try.
            last = (
                f"could not reach {config.API_URL} within {config.API_TIMEOUT}s"
            )
        except requests.ReadTimeout:
            # The manager accepted the connection and then did not answer.
            # Authentication is normally sub-second here (its own log shows
            # 0.17-0.35s), so this means the API is saturated - the one
            # situation where retrying is worst. See note 3 in the module
            # docstring.
            raise WazuhApiError(
                f"The Wazuh API accepted the connection but did not answer the "
                f"login within {config.API_TIMEOUT}s - it is saturated. Wait a "
                "few minutes rather than retrying immediately."
            )
        except requests.RequestException as e:
            last = f"{type(e).__name__}: {e}"
        else:
            if response.status_code == 200 and response.text.strip():
                return response.text.strip()
            if response.status_code in (401, 403):
                raise WazuhApiError(
                    "Wazuh API rejected the credentials "
                    f"(HTTP {response.status_code}) - check WAZUH_API_USER / "
                    "WAZUH_API_PASSWORD."
                )
            last = f"HTTP {response.status_code}: {response.text[:200]}"
        time.sleep(2 * (attempt + 1))
    raise WazuhApiError(f"Could not authenticate against the Wazuh API - {last}")


def get_token(*, force_refresh: bool = False) -> str:
    global _token, _token_expires_at
    with _token_lock:
        if not force_refresh and _token and time.time() < _token_expires_at:
            return _token
        token = _authenticate()
        _token = token
        _token_expires_at = time.time() + max(
            _token_lifetime(token) - _TOKEN_REFRESH_MARGIN, 30
        )
        return token


def _describe_failure(payload) -> str:
    """Turns the API's failure body into one operator-readable line.

    Failures arrive as HTTP 200 with a non-zero ``error`` and often a
    ``failed_items`` list whose entries carry the useful message and a
    remediation hint.
    """
    if not isinstance(payload, dict):
        return str(payload)[:300]

    for item in payload.get("data", {}).get("failed_items", []) or []:
        error = item.get("error") or {}
        message = error.get("message") or error.get("title")
        if message:
            remediation = error.get("remediation")
            return f"{message}{' - ' + remediation if remediation else ''}"

    for key in ("detail", "message", "title"):
        value = payload.get(key)
        if value:
            return str(value)
    return json.dumps(payload)[:300]


def error_code(payload) -> int | None:
    """The API's own error code from a response body, if it carries one -
    including the per-item code inside ``failed_items``."""
    if not isinstance(payload, dict):
        return None
    for item in payload.get("data", {}).get("failed_items", []) or []:
        code = (item.get("error") or {}).get("code")
        if code is not None:
            return int(code)
    code = payload.get("error")
    return int(code) if isinstance(code, int) and code != 0 else None


def _succeeded(payload) -> bool:
    """Success means the API said error 0 AND nothing landed in
    failed_items - either one alone is not enough."""
    if not isinstance(payload, dict):
        return True  # a raw (?raw=true) body carries no envelope
    if payload.get("error") not in (0, None):
        return False
    return not payload.get("data", {}).get("failed_items")


def request(
    method: str,
    path: str,
    *,
    json_body=None,
    raw_body: str | None = None,
    content_type: str | None = None,
    timeout: int | None = None,
    retries: int = 2,
    tolerate_error_codes: frozenset[int] | set[int] = frozenset(),
) -> tuple[bool, object]:
    """Sends one API call and reports ``(ok, result)``.

    On success ``result`` is the parsed JSON body, or the plain text for
    a ``?raw=true`` request. On failure it is a message suitable for
    showing an operator.

    ``content_type`` matters and is NOT uniform across the API: the file
    upload endpoints take ``application/octet-stream`` while
    ``PUT /groups/{id}/configuration`` rejects that and demands
    ``application/xml``. Callers pass what their endpoint wants; this
    module does not guess.

    ``tolerate_error_codes`` names API error codes that are not really
    failures for this caller. Such a response comes back as
    ``(True, payload)`` with its error envelope intact, so the caller can
    tell "nothing there" apart from "it worked and was empty".
    """
    try:
        _require_settings()
    except WazuhApiError as e:
        return False, str(e)

    session = get_session()
    url = f"{config.API_URL}{path}"
    effective_timeout = timeout or config.API_TIMEOUT
    refreshed = False
    last = "no attempt made"

    for attempt in range(retries + 1):
        # get_token() raises for anything no retry can fix (bad credentials,
        # a saturated API). This function promises (ok, message) to every
        # caller, so the exception is converted here rather than escaping
        # into a route handler and becoming a 500.
        try:
            headers = {"Authorization": f"Bearer {get_token()}"}
        except WazuhApiError as e:
            return False, str(e)
        data = None
        if raw_body is not None:
            headers["Content-Type"] = content_type or "application/octet-stream"
            data = raw_body.encode("utf-8")

        try:
            response = session.request(
                method,
                url,
                headers=headers,
                data=data,
                json=json_body,
                timeout=effective_timeout,
            )
        except requests.ConnectTimeout:
            # Nothing reached the manager, so a retry costs it nothing.
            last = (
                f"could not reach {config.API_URL} within {effective_timeout}s"
            )
        except requests.ReadTimeout:
            # Deliberately NOT retried - see note 3 in the module docstring.
            # The manager is still executing this request after we give up, so
            # a retry would add a second long-running job to a pool that is
            # already starved.
            return False, (
                f"The Wazuh manager did not answer within {effective_timeout}s. "
                "It is most likely still processing the request - retrying now "
                "would only add load. Try again in a few minutes."
            )
        except requests.RequestException as e:
            last = f"{type(e).__name__}: {e}"
        else:
            # An expired/invalidated token: renew once, then retry.
            if response.status_code == 401 and not refreshed:
                refreshed = True
                try:
                    get_token(force_refresh=True)
                except WazuhApiError as e:
                    return False, str(e)
                continue

            try:
                payload = response.json()
            except ValueError:
                payload = response.text

            code = error_code(payload)
            if code is not None and code in tolerate_error_codes:
                return True, payload
            if code == INTERNAL_TIMEOUT_CODE:
                last = "the manager timed out executing the request (error 3021)"
            elif response.status_code >= 500:
                last = f"HTTP {response.status_code}: {_describe_failure(payload)}"
            elif response.status_code >= 400 or not _succeeded(payload):
                # A genuine rejection - retrying will not change the answer.
                return False, _describe_failure(payload)
            else:
                return True, payload

        if attempt < retries:
            time.sleep(2 * (attempt + 1))

    return False, f"Wazuh API request failed after {retries + 1} attempts - {last}"


def read_section(section: str) -> tuple[bool, list | str]:
    """One ossec.conf section as the API's parsed ``affected_items``.

    A section that simply is not present in ossec.conf comes back as
    error 1106. That is the normal state for an untouched manager - one
    with no <email_alerts> block has not failed at anything - so it is
    reported here as an empty list. Without this mapping the Settings
    page would greet a fresh manager with an error banner.
    """
    ok, payload = request(
        "GET",
        f"/manager/configuration?section={section}",
        tolerate_error_codes={MISSING_SECTION_CODE},
    )
    if not ok:
        return False, payload
    if error_code(payload) == MISSING_SECTION_CODE:
        return True, []
    items = (
        payload.get("data", {}).get("affected_items", [])
        if isinstance(payload, dict)
        else []
    )
    return True, items
