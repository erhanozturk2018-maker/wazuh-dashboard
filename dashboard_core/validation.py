"""
Dashboard-side input validation patterns.

These are the first of the tri-layer validation checks (browser -> dashboard ->
manager). They exist for fast UI feedback; the real trust boundary is the
manager-side tool (docs/security/manager-side.md).
"""

import re
import xml.etree.ElementTree as ET

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
HOST_RE = re.compile(r"^[A-Za-z0-9.\-]+$")

AGENT_ID_RE = re.compile(r"^\d{1,8}$")
AGENT_NAME_RE = re.compile(r"^[A-Za-z0-9._\-]{1,128}$")

# Each octet is bounded to 0-255 and the prefix length to 0-32. An earlier
# version used \d{1,3} per octet, which accepted 999.999.999.999 and sent
# it to the manager - the field claimed to validate an address while
# really only counting digits and dots.
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_PREFIX = r"(?:3[0-2]|[12]?\d)"
AGENT_IP_RE = re.compile(
    rf"^(?:any|{_OCTET}(?:\.{_OCTET}){{3}}(?:/{_PREFIX})?)$"
)

# Custom decoder/rule files (ISP tab): bare .xml file name, no path parts.
CUSTOM_XML_FILE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*\.xml$")

# Project-owned rsyslog rule files: the wazuh- prefix is the ownership
# marker (the manager-side tool refuses anything else).
RSYSLOG_FILE_RE = re.compile(r"^wazuh-[A-Za-z0-9._-]+\.conf$")


def xml_well_formed_error(content: str) -> str | None:
    """First-layer well-formedness check for custom decoder/rule XML.

    The files hold multiple top-level elements with no shared root (same
    style as ossec.conf), so the content is wrapped in a fake <root>
    before parsing. Uses the stdlib parser for fast feedback; the Wazuh
    API re-validates on upload and is the real trust boundary now that
    these files are written through it rather than by a manager-side
    tool."""
    try:
        ET.fromstring(f"<root>{content}</root>")
    except ET.ParseError as e:
        return str(e)
    return None


def _relay_host_only(value: str) -> str:
    """Extracts just the host part (for validation) from values such as
    '[smtp.gmail.com]:587', 'smtp.gmail.com:587' or a plain 'localhost'."""
    v = value.strip()
    if v.startswith("[") and "]" in v:
        return v[1:v.index("]")]
    return v.split(":")[0]
