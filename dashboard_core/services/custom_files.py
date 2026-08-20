"""
Custom decoder and rule XML files on the manager, through the Wazuh API.

These are the individually-named files under ``/var/ossec/etc/decoders/``
and ``/var/ossec/etc/rules/``. The API exposes them as two parallel file
collections that behave identically apart from their path, so one set of
functions covers both via the ``kind`` argument.

**Listing does not fetch content.** The API's file listing returns only
metadata; reading a file body costs one further call each. The previous
SSH tool read every file in a single call and could afford to hand back
content for all of them, but doing that here would turn one page render
into N API calls against a manager that is measurably slow
(docs/architecture/execution-flow.md). Content is therefore fetched only
when an operator actually opens a file - the same list/detail split the
agents flow already commits to.
"""

from dashboard_core import validation
from dashboard_core.services import manager_control, wazuh_api

# UI-facing kind -> the API's collection path and the directory it owns.
# relative_dirname pins writes to the custom directories; without it the
# API would default to wherever it pleases, and Wazuh's own ruleset
# directory is overwritten on upgrade.
KINDS = {
    "decoder": {"collection": "decoders", "dirname": "etc/decoders"},
    "rule": {"collection": "rules", "dirname": "etc/rules"},
}


def _kind(kind: str) -> dict:
    try:
        return KINDS[kind]
    except KeyError:
        raise ValueError(f"Unknown file kind: {kind}") from None


# What the API says when it refuses an uploaded decoder/rule file. It says
# this for ANY rejection, not only a malformed document - see
# _upload_rejection_reason().
_API_XML_REJECTION = "xml syntax error"

_UPLOAD_REJECTION_HINT = (
    "The manager rejected this file. Its message says \"XML syntax error\", "
    "but the XML was already checked here and is well-formed, so the real "
    "cause is something Wazuh's ruleset compiler refused. The usual one is "
    "regex syntax: a <field>/<match>/<regex> pattern uses OSRegex unless it "
    "says otherwise, and OSRegex has no grouping - combining parentheses "
    "with | (as in ^(a|b)$) is rejected. Write it as ^a$|^b$, or add "
    "type=\"pcre2\" to that element. A duplicate rule id, an unknown "
    "if_sid, or a decoder name already defined elsewhere produce the same "
    "message."
)


def _upload_rejection_reason(payload: object) -> str:
    """Turns the API's upload refusal into something an operator can act on.

    The file endpoints answer every rejection with the same
    "XML syntax error - Please, ensure file content has correct XML",
    whether or not the document is actually malformed. Measured against
    4.14.6 with a document this module had already parsed successfully:

        ^Spooler$          accepted
        ^Spooler$|^Fax$    accepted     (alternation, no grouping)
        Spooler|Fax        accepted     (| alone)
        (Spooler)          accepted     (parentheses alone)
        (Spooler|Fax)      REJECTED     (grouping)
        ^(Spooler|Fax)$    REJECTED     (grouping)
        ^(Spooler|Fax)$ type="pcre2"    accepted

    So the message names the one thing that was not wrong. Callers reach
    this only after xml_well_formed_error() has passed, which is what
    makes "the document is fine, look elsewhere" a fact here rather than
    a guess.
    """
    text = str(payload)
    if _API_XML_REJECTION in text.lower():
        return f"{_UPLOAD_REJECTION_HINT} (manager said: {text})"
    return text


def _name_error(name: str) -> str | None:
    """Rejects anything that is not a bare ``*.xml`` name.

    This is what keeps the channel unable to write outside the two owned
    directories - a name carrying a path component or ``..`` would
    otherwise be handed straight to the API.
    """
    if not validation.CUSTOM_XML_FILE_RE.match(name or "") or ".." in name:
        return (
            "Invalid file name: letters, digits, dot, dash and underscore "
            "only, ending in .xml, with no path components."
        )
    return None


def list_files(kind: str) -> tuple[bool, list[dict] | str]:
    """Metadata for every custom file of one kind - no content.

    Each entry is ``{"name", "_id", "status"}``; ``_id`` mirrors the name
    so callers share one identifier convention with the ossec.conf blocks.
    """
    spec = _kind(kind)
    ok, payload = wazuh_api.request(
        "GET",
        f"/{spec['collection']}/files?relative_dirname={spec['dirname']}",
    )
    if not ok:
        return False, str(payload)

    items = payload.get("data", {}).get("affected_items", []) if isinstance(payload, dict) else []
    return True, [
        {
            "name": item.get("filename", ""),
            "_id": item.get("filename", ""),
            "status": item.get("status", ""),
        }
        for item in items
    ]


def read_file(kind: str, name: str) -> tuple[bool, str]:
    """One file's raw XML, fetched on demand."""
    spec = _kind(kind)
    error = _name_error(name)
    if error:
        return False, error

    ok, payload = wazuh_api.request(
        "GET",
        f"/{spec['collection']}/files/{name}"
        f"?raw=true&relative_dirname={spec['dirname']}",
    )
    if not ok:
        return False, str(payload)
    return True, payload if isinstance(payload, str) else str(payload)


def save_file(kind: str, name: str, content: str, *, overwrite: bool,
              apply_changes: bool = True) -> tuple[bool, str]:
    """Writes one file. ``overwrite=False`` creates only and the API
    rejects an existing name; ``True`` is create-or-replace.

    Restarts the manager afterwards: analysisd loads the ruleset at
    startup, so a decoder or rule written without one is inert
    (`services/manager_control.py`). ``apply_changes=False`` is for a
    caller writing several files in a row that should end in a single
    restart - `services/service_checks.py` writes two."""
    spec = _kind(kind)
    error = _name_error(name)
    if error:
        return False, error
    if not (content or "").strip():
        return False, "The file content cannot be empty."

    xml_error = validation.xml_well_formed_error(content)
    if xml_error:
        return False, f"The content is not well-formed XML: {xml_error}"

    ok, payload = wazuh_api.request(
        "PUT",
        f"/{spec['collection']}/files/{name}"
        f"?overwrite={'true' if overwrite else 'false'}"
        f"&relative_dirname={spec['dirname']}",
        raw_body=content,
        # Measured: these upload endpoints take octet-stream. The sibling
        # group-configuration endpoint does NOT - it demands
        # application/xml. Do not unify these without re-checking.
        content_type="application/octet-stream",
    )
    if not ok:
        # The document already passed xml_well_formed_error() above, so an
        # "XML syntax error" from here is describing the wrong thing.
        return False, _upload_rejection_reason(payload)
    warning = manager_control.restart_warning() if apply_changes else ""
    return True, " ".join(p for p in (f"Saved {name}.", warning) if p)


def delete_file(kind: str, name: str, *, apply_changes: bool = True) -> tuple[bool, str]:
    spec = _kind(kind)
    error = _name_error(name)
    if error:
        return False, error

    ok, payload = wazuh_api.request(
        "DELETE",
        f"/{spec['collection']}/files/{name}?relative_dirname={spec['dirname']}",
    )
    if not ok:
        return False, str(payload)
    warning = manager_control.restart_warning() if apply_changes else ""
    return True, " ".join(p for p in (f"Deleted {name}.", warning) if p)
