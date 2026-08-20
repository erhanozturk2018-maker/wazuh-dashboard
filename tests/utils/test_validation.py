"""
================================================================================
Purpose
================================================================================
This module protects the dashboard-side format-validation logic used to
give fast UI feedback before any manager-bound field is sent over SSH.
This logic lives in `dashboard_core/validation.py`: `EMAIL_RE`, `HOST_RE`,
`_relay_host_only()`, `AGENT_ID_RE`, `AGENT_NAME_RE`, `AGENT_IP_RE` — plus
the inline digit checks for `port`/`email_maxperhour`, which stay in the
`dashboard_core/routes/settings.py` handlers because they are one-line `str.isdigit()`
calls rather than shared patterns. This module exists to unit-test that logic in
isolation, independent of the HTTP routes that use it, so a validator's
correctness doesn't depend on standing up a `TestClient` or mocking SSH.

================================================================================
Responsibilities
================================================================================
- Verify `EMAIL_RE` accepts well-formed addresses and rejects inputs
  missing an `@`, missing a domain dot, or containing whitespace.
- Verify `HOST_RE` accepts hostnames/IPv4 addresses made of letters,
  digits, dots, and hyphens, and rejects inputs containing anything else
  (spaces, protocol prefixes, path segments, shell metacharacters).
- Verify `_relay_host_only()` correctly extracts just the host portion
  from all three documented input shapes: bracketed
  (`"[smtp.gmail.com]:587"`), unbracketed with port
  (`"smtp.gmail.com:587"`), and bare (`"localhost"`).
- Verify the inline "digits only" checks used for `port` and
  `email_maxperhour` (`str.isdigit()`) behave as expected for empty
  strings, non-numeric strings, and negative-looking strings (e.g.
  `"-1"`, which `isdigit()` correctly rejects since it isn't a digit
  character).
- Verify `AGENT_ID_RE` (`^\\d{1,8}$`) accepts numeric IDs up to 8 digits
  and rejects non-numeric, empty, oversized, or negative-looking IDs.
- Verify `AGENT_NAME_RE` (`^[A-Za-z0-9._\\-]{1,128}$`) accepts names
  built from letters/digits/dot/underscore/hyphen and rejects names
  containing spaces, slashes, or other punctuation, at both length
  extremes (1 char, 128 chars, 129 chars).
- Verify `AGENT_IP_RE` accepts the literal string `"any"`, a bare IPv4
  address, and an IPv4/CIDR pair, and rejects malformed IPs, IPv6, and
  out-of-range octets that don't match the character-class pattern (note:
  the regex itself does not range-check octets — see Assumptions).

================================================================================
System Boundaries
================================================================================
In scope: the dashboard-side (`dashboard_core/validation.py`) regex constants and small
helper functions listed above, tested as pure functions/pattern objects
with no FastAPI, no SSH, and no filesystem involvement.

Out of scope, and covered elsewhere:
- Manager-side field validation (`integration_validate()`,
  `BLOCK_SPECS[...]["required"]` checks, and `email_alerts_check_confirm()`
  in `ossec-config-tool.py`). This is a deliberate scope boundary, not an
  oversight: that code lives in a separately deployed artifact
  (`docs/architecture/system-overview.md` — "versioned in this repo but
  never executed by anything in this repo"), and per
  `docs/security/manager-side.md`, it is *the* actual trust boundary,
  while the dashboard-side checks this module tests are UX-only. If the
  team wants pure-function coverage of that manager-side validation logic
  too (it has no filesystem/subprocess dependency itself, only the
  surrounding tool does), that deserves its own explicitly-scoped module
  rather than being folded in here silently — see Assumptions.
- How a validation failure is surfaced to the browser (the rendered
  error messages, HTTP status codes) — that belongs to
  `tests/api/test_configuration.py`.
- Anything about whether a *valid* value is subsequently accepted by the
  manager — dashboard-side validation passing says nothing about that.

================================================================================
Why These Tests Matter
================================================================================
Every one of these validators is the first line of defense against
sending a malformed argument toward an SSH command construction step
(`docs/development/coding-standards.md`: "Validation is layered, not
single-sourced... add checks in both places"). A regression that loosens
`HOST_RE` or `AGENT_NAME_RE` doesn't create a security hole by itself
(the manager re-validates independently), but it does mean a bad value
travels further before being rejected, produces a worse error message for
the operator, and — for the agent regexes specifically — determines
whether `AGENT_ID_RE`/`AGENT_IP_RE`/`AGENT_NAME_RE` correctly gate
`/api/agents*` input before an SSH round-trip is spent, as asserted (but
not re-derived) in `tests/api/test_agents.py`.

================================================================================
Production Files to Understand First
================================================================================
- `dashboard_core/validation.py` — `EMAIL_RE`, `HOST_RE`, `_relay_host_only()`, and
  `AGENT_ID_RE`/`AGENT_NAME_RE`/`AGENT_IP_RE`.
- `docs/development/coding-standards.md` — "Validation is layered, not
  single-sourced," for why this module's scope is explicitly limited to
  UX-level checks.
- `docs/security/manager-side.md` — "The manager is the real trust
  boundary — always re-validate here," for the explicit statement that
  what this module tests is *not* the security-relevant validation.

================================================================================
Testing Strategy
================================================================================
This is a Unit test module in the strictest sense: every test should call
a regex's `.match()` (or the small wrapper functions) directly with a
string input and assert on the boolean/string result — no `TestClient`,
no mocking, no fixtures beyond simple parametrized input/expected-output
tables. Because these are all pure, side-effect-free functions and
compiled regex patterns, this module should be the fastest-running and
least fragile in the entire suite.

================================================================================
Expected Test Scenarios
================================================================================
- Valid and invalid emails for `EMAIL_RE`, including edge cases (multiple
  `@`, trailing dot, no TLD).
- Valid and invalid hosts for `HOST_RE`, including edge cases (IPv6
  literal — expected to be rejected since only `.`/`-` are allowed
  alongside alphanumerics, a bare IPv4, a hostname with a trailing dot).
- All three `_relay_host_only()` input shapes, plus an edge case with no
  port and no brackets.
- Digit-only checks for `port`/`email_maxperhour`: empty string, purely
  numeric, mixed alphanumeric, negative sign, decimal point.
- Boundary values for `AGENT_ID_RE` (1 digit, 8 digits, 9 digits, `"0"`,
  non-numeric).
- Boundary values for `AGENT_NAME_RE` (1 char, 128 chars, 129 chars, each
  disallowed character class individually).
- All three accepted `AGENT_IP_RE` shapes (`"any"`, bare IPv4, IPv4/CIDR)
  plus rejected shapes (IPv6, hostname, malformed CIDR suffix).

================================================================================
Out of Scope
================================================================================
- Manager-side validation logic in `ossec-config-tool.py` (unless the
  team explicitly decides to add a separate, clearly-scoped module for
  it — see Assumptions below; it must never be silently merged into this
  module's coverage without that decision being made deliberately).
- Any HTTP-level behavior — status codes, redirects, rendered error
  messages.
- Semantic/business validation beyond format (e.g. whether an email
  domain actually exists, whether a host is reachable) — none of these
  validators attempt that, and this module should not imply they do by
  testing for it.

================================================================================
Mocking Strategy
================================================================================
No mocking required or appropriate. Every unit under test here is a
compiled regex or a pure string-manipulation function with no I/O, no
network, and no dependency on the FastAPI app object, session
state, or SSH configuration. If a test in this module ever needs a mock,
that is a signal the test belongs in a different module.

================================================================================
Assumptions
================================================================================
- Assumption: "utils" in this repository's test layout refers to
  dashboard-side pure functions in `dashboard_core/validation.py`, since no separate
  `utils.py`/`utils/` package exists in production code
  (`tests/README.md` describes `utils/` as "Helper function tests," which
  this module interprets as scoped to `main.py`'s helpers specifically).
- Assumption: manager-side pure validation logic
  (`integration_validate()`, the `BLOCK_SPECS["required"]` checks) is
  *not* covered by this module by default, since it lives in a
  separately-deployed script. If the team decides such logic is valuable
  to unit-test directly (it is pure Python with no filesystem dependency,
  making it technically importable and testable without a live manager),
  that should be an explicit, separately-documented decision — e.g. a
  `tests/utils/test_manager_tool_validation.py` module — rather than
  quietly expanding this module's boundary.
- Assumption: `AGENT_IP_RE`'s lack of per-octet range checking (it
  accepts `"999.999.999.999"` as a syntactic match) is existing,
  intentional-or-at-least-accepted behavior, not a bug this module should
  fail on — the manager-side tool would ultimately reject a nonsensical
  IP. This module tests the regex's actual documented behavior, not a
  stricter behavior it doesn't implement.

================================================================================
Success Criteria
================================================================================
A fully passing suite in this module guarantees that every dashboard-side
format validator behaves correctly and consistently across its documented
accepted/rejected input space, independent of any route, session, or SSH
concern — giving confidence that a validation bug, if one exists, is
detectable here rather than only surfacing as a confusing end-to-end
failure in `tests/api/test_configuration.py` or `tests/api/test_agents.py`.

================================================================================
Maintenance Notes
================================================================================
If a new manager-bound field is added anywhere in `main.py` with its own
regex or format check (per `docs/development/coding-standards.md`'s
instruction to add checks in both dashboard and manager layers for any
new validated field), add its dashboard-side validator's coverage here as
a new parametrized scenario set, following the existing pattern of
valid-input/invalid-input tables per validator rather than one sprawling
test per field.
"""

from dashboard_core.validation import EMAIL_RE, HOST_RE, _relay_host_only, AGENT_ID_RE, AGENT_NAME_RE, AGENT_IP_RE

#EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$") # DONE
#HOST_RE = re.compile(r"^[A-Za-z0-9.\-]+$") # DONE
#AGENT_ID_RE = re.compile(r"^\d{1,8}$") # DONE
#AGENT_NAME_RE = re.compile(r"^[A-Za-z0-9._\-]{1,128}$") # DONE
#AGENT_IP_RE = re.compile(r"^(any|\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)$") # DONE

"""
def _relay_host_only(value: str) -> str: # DONE
    Extracts just the host part (for validation) from values such as
    '[smtp.gmail.com]:587', 'smtp.gmail.com:587' or a plain 'localhost'.
    v = value.strip()
    if v.startswith("[") and "]" in v:
        return v[1:v.index("]")]
    return v.split(":")[0]
"""
def test_email_re_valid():
  valid_emails = ["test@example.com", "user@domain.co.uk"]
  assert all(EMAIL_RE.match(email) for email in valid_emails)

def test_email_re_invalid():
  invalid_emails = ["invalid-email", "test@.com", "user@domain"]
  assert all(not EMAIL_RE.match(email) for email in invalid_emails)

def test_host_re_valid():
  valid_hosts = ["localhost", "example.com", "sub.domain.org"]
  assert all(HOST_RE.match(host) for host in valid_hosts)

def test_host_re_invalid():
  invalid_hosts = ["invalid host", "http://example.com", "example.com/path"]
  assert all(not HOST_RE.match(host) for host in invalid_hosts)

def test_relay_host_only():
  assert _relay_host_only("[smtp.gmail.com]:587") == "smtp.gmail.com"
  assert _relay_host_only("smtp.gmail.com:587") == "smtp.gmail.com"
  assert _relay_host_only("localhost") == "localhost"

def test_agent_id_re_valid():
  valid_ids = ["1", "12345678"]
  assert all(AGENT_ID_RE.match(agent_id) for agent_id in valid_ids)

def test_agent_id_re_invalid(): #look
  invalid_ids = ["0512738190321", "1234567892131313", "abc"]
  assert all(not AGENT_ID_RE.match(agent_id) for agent_id in invalid_ids)

def test_agent_name_re_valid():
  valid_names = ["agent1", "agent_name-123", "A.B_C-D"]
  assert all(AGENT_NAME_RE.match(agent_name) for agent_name in valid_names)

def test_agent_name_re_invalid():
  invalid_names = ["agent name", "agent/name", "agent@name"]
  assert all(not AGENT_NAME_RE.match(agent_name) for agent_name in invalid_names)

def test_agent_ip_re_valid():
  valid_ips = ["any", "192.168.1.1", "10.0.0.1/24"]
  assert all(AGENT_IP_RE.match(ip) for ip in valid_ips)

def test_agent_ip_re_invalid(): #look
  invalid_ips = ["::1", "invalid", "192.168.1.2568adfgh"]
  assert all(not AGENT_IP_RE.match(ip) for ip in invalid_ips)