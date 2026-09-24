"""Runtime logging: JSON lines for containers and log shippers, key=value text for terminals.

Structured fields are passed with `extra=` and rendered as JSON keys or trailing `key=value` pairs.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime

# Attributes every LogRecord carries; anything else on a record came from `extra=`.
_STANDARD = frozenset(vars(logging.LogRecord("", 0, "", 0, "", None, None))) | {"message", "asctime"}


def _fields(record: logging.LogRecord) -> dict:
    return {k: v for k, v in vars(record).items() if k not in _STANDARD and not k.startswith("_")}


def _timestamp(record: logging.LogRecord) -> str:
    return datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": _timestamp(record),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
            **_fields(record),
        }
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry, ensure_ascii=False, default=str)


class TextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        pairs = " ".join(f"{k}={_text_value(v)}" for k, v in _fields(record).items())
        line = f"{_timestamp(record)} {record.levelname:<7} {record.name}: {record.getMessage()}"
        if pairs:
            line += " " + pairs
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line


def _text_value(value: object) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    return json.dumps(text, ensure_ascii=False) if not text or any(c in text for c in ' ="\n') else text


def setup_logging(level: str, fmt: str) -> None:
    """`fmt` is "json", "text", or "auto" (JSON unless stderr is a terminal)."""
    if fmt == "auto":
        fmt = "text" if sys.stderr.isatty() else "json"
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter() if fmt == "json" else TextFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    # httpx logs full request URLs at INFO; keep them out of the bridge log.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
