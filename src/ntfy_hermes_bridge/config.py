from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
import stat
import tomllib
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from .questions import CATEGORIES, QUESTION_SET_VERSION


class ConfigError(Exception):
    pass


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


Prob = Annotated[float, Field(ge=0.0, le=1.0)]
Mode = Literal["shadow", "guarded", "full"]
FallbackRoute = Literal["auto", "review", "digest"]
FingerprintField = Literal["source", "source_entity", "event_kind", "title", "message", "topic"]

TOPIC_PATTERN = r"^[-_A-Za-z0-9]{1,64}$"


class BridgeSettings(_Model):
    mode: Mode = "shadow"
    database: str = "bridge.db"
    env_file: str = ""
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_format: Literal["auto", "json", "text"] = "auto"  # auto: JSON unless stderr is a terminal
    timezone: str = "UTC"
    workers: int = Field(default=8, ge=1, le=64)

    @field_validator("timezone")
    @classmethod
    def _timezone(cls, value: str) -> str:
        ZoneInfo(value)
        return value


class TopicSettings(_Model):
    name: str = Field(pattern=TOPIC_PATTERN)
    source: str = ""
    normalizer: Literal["auto", "generic", "changedetection"] = "auto"

    @field_validator("name")
    @classmethod
    def _not_internal(cls, value: str) -> str:
        if value == "_bridge":
            raise ValueError("topic name '_bridge' is reserved for bridge health events")
        return value


class NtfySettings(_Model):
    base_url: str
    token_env: str = ""
    initial_since: str = Field(default="", pattern=r"^(|all|\d+[smhd])$")
    read_timeout_seconds: float = Field(default=90, gt=0)
    reconnect_max_seconds: float = Field(default=60, gt=0)
    topics: tuple[TopicSettings, ...] = Field(min_length=1)


class TypeSafeSettings(_Model):
    enabled: bool = False
    accept_cloud_data_boundary: bool = False
    allow_model_alias: bool = False
    base_url: str = "https://api.typesafe.ai"
    model: str = "jev-1.13.0"
    api_key_env: str = "TYPESAFE_API_KEY"
    timeout_seconds: float = Field(default=8, gt=0)
    max_retries: int = Field(default=3, ge=0, le=10)
    backoff_base_seconds: float = Field(default=0.5, ge=0)
    price_per_million_input_tokens: float = Field(default=0.042, ge=0)
    excerpt_chars: int = Field(default=2000, ge=100, le=20000)

    @model_validator(mode="after")
    def _guard(self) -> TypeSafeSettings:
        if self.enabled and not self.accept_cloud_data_boundary:
            raise ValueError(
                "typesafe.enabled requires typesafe.accept_cloud_data_boundary = true "
                "(redacted excerpts leave the LAN; see README 'TypeSafe data boundary')"
            )
        if not self.allow_model_alias and not re.fullmatch(r"jev-\d+\.\d+\.\d+", self.model):
            raise ValueError(
                f"typesafe.model {self.model!r} is not a pinned version; set allow_model_alias = true "
                "only after replaying the labeled corpus"
            )
        if urlsplit(self.base_url).scheme != "https":
            raise ValueError("typesafe.base_url must use https")
        return self


class HermesSettings(_Model):
    base_url: str = "http://127.0.0.1:8644"
    secret_env: str = "HERMES_WEBHOOK_SECRET"
    compose_route: str = Field(default="notification-compose", pattern=TOPIC_PATTERN)
    review_route: str = Field(default="notification-review", pattern=TOPIC_PATTERN)
    digest_route: str = Field(default="notification-digest", pattern=TOPIC_PATTERN)
    source_profiles: dict[str, str] = {}
    timeout_seconds: float = Field(default=15, gt=0)
    max_body_bytes: int = Field(default=1_000_000, ge=16_384)

    @field_validator("source_profiles")
    @classmethod
    def _source_profiles(cls, value: dict[str, str]) -> dict[str, str]:
        if any(not re.fullmatch(TOPIC_PATTERN, source) or not re.fullmatch(TOPIC_PATTERN, profile)
               for source, profile in value.items()):
            raise ValueError("source_profiles requires source and profile names containing only letters, digits, - or _")
        return value

    def profile_for_source(self, source: str) -> str:
        return self.source_profiles.get(source, "default")

    def route_for(self, kind: str, profile: str) -> str:
        name = {"compose": self.compose_route, "review": self.review_route, "digest": self.digest_route}[kind]
        return name if profile == "default" else f"{name}-{profile}"


class OutboxSettings(_Model):
    max_attempts: int = Field(default=8, ge=1)
    base_backoff_seconds: float = Field(default=5, gt=0)
    max_backoff_seconds: float = Field(default=900, gt=0)
    concurrency: int = Field(default=4, ge=1, le=32)


class FallbackSettings(_Model):
    ntfy_topic: str = Field(default="", pattern=r"^$|^[-_A-Za-z0-9]{1,64}$")
    after_attempts: int = Field(default=3, ge=1)


class DigestSettings(_Model):
    schedule: tuple[str, ...] = ("08:00", "18:00")
    max_items_per_part: int = Field(default=100, ge=1)
    item_excerpt_chars: int = Field(default=280, ge=40)

    @field_validator("schedule")
    @classmethod
    def _schedule(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for slot in value:
            if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", slot):
                raise ValueError(f"digest schedule entry {slot!r} must be HH:MM")
        return tuple(sorted(set(value)))


def _validate_categories(value: tuple[str, ...]) -> tuple[str, ...]:
    unknown = set(value) - set(CATEGORIES)
    if unknown:
        raise ValueError(f"unknown categories: {sorted(unknown)}")
    return value


class Thresholds(_Model):
    notify_harm: Prob = 0.80
    review_harm: Prob = 0.40
    notify_category_confidence: Prob = 0.70
    notify_categories: tuple[str, ...] = ("security", "data_integrity")
    drop_routine_noise: Prob = 0.90
    drop_max_harm: Prob = 0.20
    drop_max_digest_value: Prob = 0.35
    drop_max_relevance: Prob = 0.35
    digest_value: Prob = 0.65
    digest_relevance: Prob = 0.65

    @field_validator("notify_categories")
    @classmethod
    def _categories(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _validate_categories(value)


class ThresholdOverrides(_Model):
    notify_harm: Prob | None = None
    review_harm: Prob | None = None
    notify_category_confidence: Prob | None = None
    notify_categories: tuple[str, ...] | None = None
    drop_routine_noise: Prob | None = None
    drop_max_harm: Prob | None = None
    drop_max_digest_value: Prob | None = None
    drop_max_relevance: Prob | None = None
    digest_value: Prob | None = None
    digest_relevance: Prob | None = None

    @field_validator("notify_categories")
    @classmethod
    def _categories(cls, value: tuple[str, ...] | None) -> tuple[str, ...] | None:
        return None if value is None else _validate_categories(value)


class UserPolicy(_Model):
    immediate: tuple[str, ...] = ("security compromise", "data loss risk", "backup failure", "service outage")
    digest: tuple[str, ...] = ("software updates", "routine changes", "completed maintenance")
    noise: tuple[str, ...] = ("healthy heartbeats", "routine success", "duplicate status")


class NotifyRule(_Model):
    source: str
    event_kind: str = ""
    entity: str = ""


class Signature(_Model):
    name: str
    pattern: str
    sources: tuple[str, ...] = ()

    @field_validator("pattern")
    @classmethod
    def _compiles(cls, value: str) -> str:
        re.compile(value)
        return value


class AlwaysNotify(_Model):
    builtin_signatures: bool = True
    signature_exempt_sources: tuple[str, ...] = ("changedetection",)
    urgent_priority_sources: tuple[str, ...] = ()
    rules: tuple[NotifyRule, ...] = ()
    signatures: tuple[Signature, ...] = ()


class AlwaysDrop(_Model):
    fingerprints: tuple[Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")], ...] = ()


class RedactionSettings(_Model):
    redact_emails: bool = True
    patterns: tuple[str, ...] = ()

    @field_validator("patterns")
    @classmethod
    def _compiles(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for pattern in value:
            re.compile(pattern)
        return value


class PolicySettings(_Model):
    version: str = Field(min_length=1)
    echo_tags: tuple[str, ...] = ("hermes-bridge",)
    test_tags: tuple[str, ...] = ()
    fingerprint_fields: tuple[FingerprintField, ...] = ("source", "source_entity", "event_kind", "title", "message")
    stale_after_seconds: int = Field(default=3600, ge=1)
    dedupe_window_seconds: int = Field(default=3600, ge=0)
    cooldown_seconds: int = Field(default=1800, ge=0)
    flap_window_seconds: int = Field(default=3600, ge=0)
    flap_min_transitions: int = Field(default=3, ge=2)
    fallback_route: FallbackRoute = "auto"
    min_labels_for_drop: int = Field(default=200, ge=0)
    min_critical_labels_for_drop: int = Field(default=30, ge=0)
    title_chars: int = Field(default=200, ge=20)
    thresholds: Thresholds = Thresholds()
    user_policy: UserPolicy = UserPolicy()
    always_notify: AlwaysNotify = AlwaysNotify()
    always_drop: AlwaysDrop = AlwaysDrop()
    redaction: RedactionSettings = RedactionSettings()


class SourcePolicy(_Model):
    local_only: bool = False
    ignore_price_only: bool = False
    fallback_route: FallbackRoute | None = None
    thresholds: ThresholdOverrides = ThresholdOverrides()


class HealthSettings(_Model):
    listen: str = Field(default="127.0.0.1:9464", pattern=r"^$|^[^:]+:\d{1,5}$")
    ingest_outage_seconds: int = Field(default=300, ge=10)
    delivery_outage_seconds: int = Field(default=600, ge=10)


class RetentionSettings(_Model):
    days: int = Field(default=90, ge=1)


class NetworkSettings(_Model):
    extra_allowed_hosts: tuple[str, ...] = ()
    ca_file: str = ""  # extra PEM trust anchors for self-signed ntfy/Hermes HTTPS; relative to the config file
    typesafe_hosts: tuple[str, ...] = ("api.typesafe.ai",)


class Config(_Model):
    bridge: BridgeSettings = BridgeSettings()
    ntfy: NtfySettings
    typesafe: TypeSafeSettings = TypeSafeSettings()
    hermes: HermesSettings = HermesSettings()
    outbox: OutboxSettings = OutboxSettings()
    fallback: FallbackSettings = FallbackSettings()
    digest: DigestSettings = DigestSettings()
    policy: PolicySettings
    sources: dict[str, SourcePolicy] = {}
    health: HealthSettings = HealthSettings()
    retention: RetentionSettings = RetentionSettings()
    network: NetworkSettings = NetworkSettings()

    def thresholds_for(self, source: str) -> Thresholds:
        override = self.sources.get(source)
        if override is None:
            return self.policy.thresholds
        return self.policy.thresholds.model_copy(update=override.thresholds.model_dump(exclude_none=True))

    def fallback_route_for(self, source: str) -> str:
        override = self.sources.get(source)
        return (override and override.fallback_route) or self.policy.fallback_route

    def jev_enabled_for(self, source: str) -> bool:
        override = self.sources.get(source)
        return self.typesafe.enabled and not (override and override.local_only)

    def policy_hash(self) -> str:
        material = {
            "policy": self.policy.model_dump(mode="json"),
            "source_profiles": self.hermes.source_profiles,
            "sources": {k: v.model_dump(mode="json") for k, v in sorted(self.sources.items())},
            "typesafe_enabled": self.typesafe.enabled,
            "model": self.typesafe.model,
            "excerpt_chars": self.typesafe.excerpt_chars,
            "question_set": QUESTION_SET_VERSION,
        }
        return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()[:16]

    def restart_scope(self) -> dict:
        """Settings that a hot reload cannot change without restarting the bridge."""
        return {
            "database": self.bridge.database,
            "env_file": self.bridge.env_file,
            "ntfy": self.ntfy.model_dump(mode="json"),
            "health_listen": self.health.listen,
            "network": self.network.model_dump(mode="json"),
            "typesafe": [self.typesafe.enabled, self.typesafe.base_url, self.typesafe.api_key_env],
            "hermes": [self.hermes.base_url, self.hermes.secret_env],
        }

    @model_validator(mode="after")
    def _no_loops(self) -> Config:
        if self.fallback.ntfy_topic:
            if self.fallback.ntfy_topic in {t.name for t in self.ntfy.topics}:
                raise ValueError("fallback.ntfy_topic must not be a subscribed topic (notification loop)")
            if not self.policy.echo_tags:
                raise ValueError("fallback.ntfy_topic requires at least one policy.echo_tags entry")
        return self

    def allowed_hosts(self) -> frozenset[str]:
        hosts = {urlsplit(self.ntfy.base_url).hostname, urlsplit(self.hermes.base_url).hostname}
        if self.typesafe.enabled:
            hosts.add(urlsplit(self.typesafe.base_url).hostname)
        return frozenset(h for h in hosts if h)


LOCAL_SUFFIXES = (".local", ".lan", ".home.arpa", ".internal", ".localdomain")


def _private(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return address.is_private or address.is_loopback or address.is_link_local


def is_local_host(host: str, extra: tuple[str, ...]) -> bool:
    if host in extra or host == "localhost" or "." not in host or host.endswith(LOCAL_SUFFIXES):
        return True
    try:
        return _private(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    addresses = {ipaddress.ip_address(info[4][0].split("%")[0]) for info in infos}
    return bool(addresses) and all(_private(a) for a in addresses)


def _validate_network(config: Config) -> None:
    extra = config.network.extra_allowed_hosts
    for name, url in (("ntfy.base_url", config.ntfy.base_url), ("hermes.base_url", config.hermes.base_url)):
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ConfigError(f"{name} must be an http(s) URL")
        if parts.username or parts.password:
            raise ConfigError(f"{name} must not embed credentials")
        if not is_local_host(parts.hostname, extra):
            raise ConfigError(
                f"{name} host {parts.hostname!r} is not a local/private destination; "
                "add it to network.extra_allowed_hosts to allow it explicitly"
            )
    if config.typesafe.enabled:
        host = urlsplit(config.typesafe.base_url).hostname
        if host not in config.network.typesafe_hosts:
            raise ConfigError(f"typesafe.base_url host {host!r} is not in network.typesafe_hosts")


def load_env_file(path: Path) -> None:
    """Load KEY=VALUE lines into os.environ; refuses files readable by group/other."""
    try:
        mode = path.stat().st_mode
        text = path.read_text()
    except OSError as exc:
        raise ConfigError(f"cannot read env file {path}: {exc}") from exc
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ConfigError(f"env file {path} must not be group/other accessible (chmod 600)")
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.removeprefix("export ").split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        os.environ.setdefault(key.strip(), value)


def load_config(path: str | Path | None) -> Config:
    if path is None:
        source = "NTFY_BRIDGE_CONFIG_JSON"
        try:
            data = json.loads(os.environ[source])
        except (KeyError, json.JSONDecodeError) as exc:
            raise ConfigError(f"invalid {source}: {exc}") from exc
        base_dir = Path.cwd()
    else:
        path = Path(path)
        source = str(path)
        base_dir = path.parent
        try:
            data = tomllib.loads(path.read_text())
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ConfigError(f"cannot read {path}: {exc}") from exc
    try:
        config = Config.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"invalid config {source}:\n{exc}") from exc
    if config.bridge.env_file:
        env_path = Path(config.bridge.env_file)
        if not env_path.is_absolute():
            env_path = base_dir / env_path
        load_env_file(env_path)
    if config.network.ca_file:
        ca_path = Path(config.network.ca_file)
        if not ca_path.is_absolute():
            ca_path = base_dir / ca_path
            config = config.model_copy(update={"network": config.network.model_copy(update={"ca_file": str(ca_path)})})
        try:
            tls_context(config.network)
        except (OSError, ssl.SSLError) as exc:
            raise ConfigError(f"network.ca_file {ca_path}: {exc}") from exc
    _validate_network(config)
    return config


def tls_context(network: NetworkSettings) -> ssl.SSLContext:
    """System roots plus `network.ca_file` (e.g. a self-signed LAN certificate)."""
    context = ssl.create_default_context()
    if network.ca_file:
        context.load_verify_locations(network.ca_file)
    return context


def secret(name: str) -> str:
    return os.environ.get(name, "") if name else ""
