from ntfy_hermes_bridge.config import RedactionSettings, TopicSettings, UserPolicy
from ntfy_hermes_bridge.jev import build_state
from ntfy_hermes_bridge.normalize import normalize
from ntfy_hermes_bridge.redact import Redactor, sanitize_url

SECRET_TEXT = """Login failed for admin@example.com
Authorization: Bearer abcDEF123456789xyz
password=hunter2 token: s3cr3t-value
Cookie: session=abc123
key sk-proj-ABCDEF1234567890abcdef
blob Zm9vYmFyQmF6UXV4MTIzNDU2Nzg5MEFCQ0RFRkdI
see https://user:pw@nas.lan/ui?view=pool&access_token=XYZ&sig=123
commit 3f786850e387550fdab836ed7e6dc881de23001b"""


def test_redaction_removes_credentials_and_pii_but_keeps_context():
    text = Redactor(RedactionSettings()).redact(SECRET_TEXT)
    for leaked in (
        "admin@example.com",
        "abcDEF123456789xyz",
        "hunter2",
        "s3cr3t-value",
        "session=abc123",
        "sk-proj-",
        "Zm9vYmFy",
        "user:pw",
        "XYZ",
        "sig=123",
    ):
        assert leaked not in text
    assert "Login failed" in text
    assert "https://nas.lan/ui?view=pool&access_token=REDACTED&sig=REDACTED" in text
    assert "3f786850e387550fdab836ed7e6dc881de23001b" in text  # plain hex hashes are not secrets
    assert Redactor(RedactionSettings()).leaks({"message": text}) == []


def test_leak_guard_catches_unredacted_state():
    redactor = Redactor(RedactionSettings(patterns=("INTERNAL-\\d+",)))
    assert redactor.leaks({"tags": ["Bearer abcdefghijklmnop"], "title": "INTERNAL-42"}) == ["bearer", "custom"]


def test_sanitize_url_drops_userinfo():
    assert sanitize_url("http://u:p@host:8080/a?b=1") == "http://host:8080/a?b=1"


def canonical(msg: dict, topic: TopicSettings, chars: int = 2000):
    return normalize(
        {"id": "abc", "time": 1_790_000_000, **msg},
        event_id="ntfy:t:abc",
        topic=topic,
        received_at="2026-09-24T00:00:00+00:00",
        raw_sha256="0" * 64,
        redactor=Redactor(RedactionSettings()),
        title_chars=200,
        message_chars=chars,
    )


def test_changedetection_normalizer_extracts_entity_kind_and_safe_link():
    event = canonical(
        {
            "title": "ChangeDetection.io Notification - https://shop.example.com/gpu?ref=abc&token=t0k3n",
            "message": "https://shop.example.com/gpu had a change.\n---\nNow: In stock\n---\nhttps://cd.lan/diff/1b2c",
            "tags": ["restock"],
        },
        TopicSettings(name="cd", normalizer="auto"),
    )
    assert event.normalizer == "changedetection-v2"
    assert event.source == "changedetection"
    assert event.source_entity == "shop.example.com/gpu"
    assert event.event_kind == "restock_changed"
    assert event.click_url == "https://cd.lan/diff/1b2c"
    assert "t0k3n" not in event.title


def test_cloud_state_is_bounded_and_only_contains_allowed_fields():
    event = canonical({"title": "x" * 500, "message": "y" * 10_000}, TopicSettings(name="t"), chars=2000)
    state = build_state(event, UserPolicy())
    assert len(state["message_excerpt"]) == 2000
    assert len(state["title"]) == 200
    assert "raw_sha256" not in state and "click_url" not in state and "event_id" not in state


def test_changedetection_structured_body_is_parsed_and_compacted():
    event = canonical(
        {
            "title": "ChangeDetection - https://www.linsoul.com/collections/coming-soon",
            "message": "source: changedetection\nwatch: Coming Soon – Linsoul Audio\n"
            "watch_url: https://www.linsoul.com/collections/coming-soon\n"
            'diff_url: ("Base URL" not set - see settings - notifications)/diff/08139644\n'
            "triggered_text: \nchange:                 Availability\n                  * In stock (0)\n"
            "(changed)                   * Out of stock (2)\n(into)                   * Out of stock (3)",
        },
        TopicSettings(name="change", normalizer="auto"),
    )
    assert event.normalizer == "changedetection-v2"
    assert event.source_entity == "Coming Soon – Linsoul Audio"
    assert event.event_kind == "restock_changed"
    assert event.message == "Availability\n* In stock (0)\n(changed) * Out of stock (2)\n(into) * Out of stock (3)"
    assert event.click_url == "https://www.linsoul.com/collections/coming-soon"  # broken diff_url is skipped
