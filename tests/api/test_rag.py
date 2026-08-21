"""
The RAG assistant page and its feature flag.

What actually needs protecting here is the GATE, not the question box. The
flag has two enforcement points - the sidebar link and the routes - and the
failure that matters is them disagreeing: a route that stays reachable
after the feature is switched off would be a service the operator never
opted into, still answering requests, with nothing in the UI to show for
it. So most of these assert the off state rather than the on state.

The assistant service itself is stubbed. Reaching a real one would make
the suite depend on a second local process being up, which is exactly the
coupling tests/conftest.py's `no_real_manager` fixture exists to prevent
for the Wazuh manager.
"""

import pytest

from dashboard_core.storage import load_feature_flags, save_feature_flags


@pytest.fixture(autouse=True)
def isolated_settings(tmp_path, monkeypatch):
    """Point settings.json at a temp file so these tests never read or
    write the developer's own feature flags."""
    monkeypatch.setattr("dashboard_core.config.SETTINGS_FILE", tmp_path / "settings.json")


@pytest.fixture
def rag_stub(monkeypatch):
    """Canned replies for the assistant service."""
    class Stub:
        def __init__(self):
            self.status_reply = (True, {"configured": True, "chunks_available": True})
            self.ask_reply = (True, {"answer": "42", "sources": []})
            self.docs_reply = (True, {"documents": {"Wazuh": 29}})
            self.asked = []

        def status(self):
            return self.status_reply

        def ask(self, query, user=None):
            self.asked.append((query, user))
            return self.ask_reply

        def list_documents(self):
            return self.docs_reply

    stub = Stub()
    for name in ("status", "ask", "list_documents"):
        monkeypatch.setattr(f"dashboard_core.services.rag_pipeline.{name}",
                            getattr(stub, name))
    return stub


def enable():
    save_feature_flags({"rag_assistant": True})


# ======================================================================
# THE GATE
# ======================================================================

def test_the_feature_is_off_until_someone_turns_it_on():
    """A dashboard that has never heard of the assistant service must not
    advertise it."""
    assert load_feature_flags()["rag_assistant"] is False


def test_the_page_is_not_reachable_while_off(authenticated_client):
    assert authenticated_client.get("/rag").status_code == 404


def test_asking_is_not_reachable_while_off(authenticated_client, rag_stub):
    """The route, not just the link. Hiding a nav item is presentation;
    a caller that knows the URL must still be refused."""
    response = authenticated_client.post("/rag/ask", data={"query": "hello"})
    assert response.status_code == 404
    assert rag_stub.asked == [], "the assistant was contacted despite the feature being off"


def test_the_sidebar_link_appears_only_when_enabled(authenticated_client, api_stub):
    api_stub.set("/", {"error": 0, "data": {"affected_items": [], "failed_items": []}})
    assert 'href="/rag"' not in authenticated_client.get("/").text
    enable()
    assert 'href="/rag"' in authenticated_client.get("/").text


def test_the_page_renders_once_enabled(authenticated_client, rag_stub):
    enable()
    response = authenticated_client.get("/rag")
    assert response.status_code == 200
    assert "ask-input" in response.text


def test_asking_still_needs_a_session(unauthenticated_client, rag_stub):
    enable()
    response = unauthenticated_client.post("/rag/ask", data={"query": "hello"})
    assert response.status_code == 401
    assert rag_stub.asked == []


# ======================================================================
# THE TOGGLE
# ======================================================================

def test_the_toggle_persists_and_redirects(authenticated_client):
    response = authenticated_client.post(
        "/settings/features", data={"rag_assistant": "1"}, follow_redirects=False)
    assert response.status_code == 303
    assert "tab=features" in response.headers["location"]
    assert load_feature_flags()["rag_assistant"] is True


def test_an_unchecked_box_turns_it_off(authenticated_client):
    """An unchecked HTML checkbox submits nothing at all, so "off" arrives
    as an absent field rather than a false value - reading it as "leave
    unchanged" would make the switch one-way."""
    enable()
    authenticated_client.post("/settings/features", data={}, follow_redirects=False)
    assert load_feature_flags()["rag_assistant"] is False


def test_the_toggle_leaves_other_settings_alone(authenticated_client):
    """settings.json is shared with host/port/mail/plugins - this write
    must not clobber its neighbours."""
    from dashboard_core import config
    from dashboard_core.storage import load_json, save_json
    save_json(config.SETTINGS_FILE, {"host": "1.2.3.4", "port": 5000,
                                     "mail": {"email_to": "a@b.c"}})

    authenticated_client.post("/settings/features", data={"rag_assistant": "1"})

    data = load_json(config.SETTINGS_FILE, {})
    assert data["host"] == "1.2.3.4"
    assert data["port"] == 5000
    assert data["mail"] == {"email_to": "a@b.c"}
    assert data["features"]["rag_assistant"] is True


# ======================================================================
# ASKING
# ======================================================================

def test_a_question_reaches_the_service_with_the_session_user(
        authenticated_client, rag_stub):
    enable()
    response = authenticated_client.post("/rag/ask", data={"query": "  why?  "})
    assert response.status_code == 200
    assert response.json()["answer"] == "42"
    # Trimmed, and attributed to the logged-in user rather than to whatever
    # the client claimed to be.
    assert rag_stub.asked == [("why?", "testuser")]


def test_an_empty_question_is_refused_before_the_service_is_called(
        authenticated_client, rag_stub):
    enable()
    response = authenticated_client.post("/rag/ask", data={"query": "   "})
    assert response.status_code == 400
    assert rag_stub.asked == []


def test_a_service_failure_is_reported_not_swallowed(authenticated_client, rag_stub):
    enable()
    rag_stub.ask_reply = (False, "the assistant service is not running")
    response = authenticated_client.post("/rag/ask", data={"query": "hello"})
    assert response.status_code == 502
    assert "not running" in response.json()["error"]


def test_an_unreachable_service_still_renders_the_page(authenticated_client, rag_stub):
    """The page must explain itself when the service is down, rather than
    failing to load - "it isn't working" with no reason is the state this
    page exists to avoid."""
    enable()
    rag_stub.status_reply = (False, "Could not reach the assistant service.")
    rag_stub.docs_reply = (False, "Could not reach the assistant service.")

    response = authenticated_client.get("/rag")
    assert response.status_code == 200
    assert "could not be reached" in response.text.lower()

    # And it must not invite a question it cannot answer. Asserted on the
    # control itself: a bare `"disabled" in response.text` passes on the
    # word appearing anywhere on the page, which is passing for the wrong
    # reason. It is a <textarea> rather than an <input> because a question
    # can wrap and the composer grows to fit it.
    import re
    tag = re.search(r'<textarea[^>]*id="ask-input"[^>]*>', response.text, re.S)
    assert tag and "disabled" in tag.group(0)
