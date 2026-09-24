"""Secret/PII redaction applied to every field before it is stored canonically or leaves the host."""

from __future__ import annotations

import re
from collections import Counter
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .config import RedactionSettings

REDACTED = "[REDACTED]"

URL_RE = re.compile(r"https?://[^\s<>\"'`)\]]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b")

SENSITIVE_PARAM_PARTS = (
    "token",
    "key",
    "secret",
    "pass",
    "pwd",
    "sig",
    "auth",
    "session",
    "sid",
    "code",
    "cred",
    "jwt",
)

# (kind, pattern, replacement). Order matters: structured forms before generic assignments.
SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "private_key",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)", re.S),
        "[REDACTED:private_key]",
    ),
    ("cookie", re.compile(r"(?im)^(\s*(?:set-)?cookie\s*:).*$"), r"\1 " + REDACTED),
    (
        "auth_header",
        re.compile(r"(?i)\b((?:proxy-)?authorization\s*[:=]\s*)(?:(?:bearer|basic|token)\s+)?[^\s,;]+"),
        r"\1" + REDACTED,
    ),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}"), "Bearer " + REDACTED),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "[REDACTED:jwt]"),
    (
        "api_key",
        re.compile(
            r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}"
            r"|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|tk_[A-Za-z0-9]{20,}"
            r"|glpat-[A-Za-z0-9_-]{20,})"
        ),
        "[REDACTED:api_key]",
    ),
    (
        "assignment",
        re.compile(
            r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|client[_-]?secret"
            r"|private[_-]?key)(\s*[:=]\s*)(?!\[?REDACTED)(\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
        ),
        r"\1\2" + REDACTED,
    ),
    # Long mixed-case alphanumeric blobs are almost always credentials; plain hex hashes are left alone.
    (
        "high_entropy",
        re.compile(
            r"(?<![A-Za-z0-9+_-])(?=[A-Za-z0-9+_-]*[A-Z])(?=[A-Za-z0-9+_-]*[a-z])(?=[A-Za-z0-9+_-]*\d)"
            r"[A-Za-z0-9+_-]{32,}={0,2}(?![A-Za-z0-9+_-])"
        ),
        "[REDACTED:blob]",
    ),
)


def _sensitive_param(name: str) -> bool:
    lowered = name.lower()
    return any(part in lowered for part in SENSITIVE_PARAM_PARTS)


def sanitize_url(url: str, counts: Counter | None = None) -> str:
    """Strip userinfo and sensitive query/fragment values from a URL."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        if counts is not None:
            counts["bad_url"] += 1
        return "[REDACTED:url]"
    netloc = parts.netloc
    if parts.username or parts.password:
        netloc = host + (f":{port}" if port else "")
        if counts is not None:
            counts["url_credentials"] += 1

    def clean(query: str) -> str:
        if not query:
            return query
        pairs = parse_qsl(query, keep_blank_values=True)
        changed = False
        out = []
        for name, value in pairs:
            if value and _sensitive_param(name):
                out.append((name, "REDACTED"))
                changed = True
            else:
                out.append((name, value))
        if not changed:
            return query
        if counts is not None:
            counts["url_query"] += 1
        return urlencode(out, safe="/:")

    return urlunsplit((parts.scheme, netloc, parts.path, clean(parts.query), clean(parts.fragment)))


class Redactor:
    def __init__(self, settings: RedactionSettings):
        self.redact_emails = settings.redact_emails
        self.custom = tuple(re.compile(p) for p in settings.patterns)

    def redact(self, text: str, counts: Counter | None = None) -> str:
        if not text:
            return text
        counts = counts if counts is not None else Counter()
        text = URL_RE.sub(lambda m: sanitize_url(m.group(0), counts), text)
        for kind, pattern, replacement in SECRET_PATTERNS:
            text, n = pattern.subn(replacement, text)
            if n:
                counts[kind] += n
        if self.redact_emails:
            text, n = EMAIL_RE.subn("[REDACTED:email]", text)
            if n:
                counts["email"] += n
        for pattern in self.custom:
            text, n = pattern.subn("[REDACTED:custom]", text)
            if n:
                counts["custom"] += n
        return text

    def leaks(self, value: object) -> list[str]:
        """Final outbound guard: kinds of secret patterns still present anywhere in a JSON-like value."""
        found: list[str] = []

        def walk(node: object) -> None:
            if isinstance(node, str):
                for kind, pattern, _ in SECRET_PATTERNS:
                    for match in pattern.finditer(node):
                        if "REDACTED" not in match.group(0):
                            found.append(kind)
                            break
                for pattern in self.custom:
                    if pattern.search(node):
                        found.append("custom")
            elif isinstance(node, dict):
                for item in node.values():
                    walk(item)
            elif isinstance(node, (list, tuple)):
                for item in node:
                    walk(item)

        walk(value)
        return found


def truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"
