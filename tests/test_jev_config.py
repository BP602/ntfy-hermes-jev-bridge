import httpx
import pytest

from ntfy_hermes_bridge.config import ConfigError, load_config
from ntfy_hermes_bridge.daemon import App
from ntfy_hermes_bridge.jev import JevClient, JevError, parse_response
from ntfy_hermes_bridge.models import Route
from ntfy_hermes_bridge.questions import CATEGORIES

from .conftest import jev_answers, ntfy_line

pytestmark = pytest.mark.anyio


async def _process_one(app: App):
    app.ingest_line("alerts", ntfy_line("M1", "routine status information", priority=2))
    [row] = app.store.claim_received(1)
    return await app.pipeline.process(row)


async def test_contradictory_category_choice_falls_back_instead_of_routing(make_config, services):
    response = jev_answers(category="security", confidence=0.99)
    probabilities = response["answers"]["category"]["probabilities"]
    probabilities["security"], probabilities["availability"] = (
        probabilities["availability"],
        probabilities["security"],
    )
    services.jev_default = response
    app = App(make_config(bridge__mode="full"), transport=services.transport())

    decision = await _process_one(app)

    assert decision.jev is None
    assert "highest probability" in decision.jev_error
    assert decision.proposed is Route.DIGEST
    assert decision.effective is Route.DIGEST
    assert len(services.jev_requests) == 1
    await app.close()


def test_category_probabilities_must_include_every_option():
    response = jev_answers()
    probabilities = response["answers"]["category"]["probabilities"]
    omitted = next(category for category in CATEGORIES if category != "informational")
    probabilities["informational"] += probabilities.pop(omitted)

    with pytest.raises(JevError, match="probabilities do not match options") as raised:
        parse_response(response)

    assert raised.value.retryable is False


def test_tied_highest_category_probability_is_accepted():
    response = jev_answers(category="informational", confidence=0.5)
    probabilities = response["answers"]["category"]["probabilities"]
    probabilities.update(dict.fromkeys(CATEGORIES, 0.0))
    probabilities["informational"] = probabilities["other"] = 0.5

    _, answers, _, _ = parse_response(response)

    assert answers.category == "informational"


async def test_response_model_must_match_requested_model_unless_aliases_allowed(make_config, services):
    services.jev_default = jev_answers()
    services.jev_default["model"] = "jev-1.14.0"
    async with httpx.AsyncClient(transport=services.transport()) as http:
        client = JevClient(http, "test-key")
        settings = make_config().typesafe
        with pytest.raises(JevError, match="does not match requested model") as raised:
            await client.classify({}, settings)

        assert raised.value.retryable is False
        result = await client.classify({}, settings.model_copy(update={"allow_model_alias": True}))

    assert result.model == "jev-1.14.0"
    assert len(services.jev_requests) == 2


def test_source_notify_categories_are_validated_when_loading_config(tmp_path):
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
[ntfy]
base_url = "http://127.0.0.1:2586"

[[ntfy.topics]]
name = "alerts"
source = "homelab"

[policy]
version = "test-1"

[sources.homelab.thresholds]
notify_categories = ["securty"]
""".strip()
    )

    with pytest.raises(ConfigError, match="unknown categories.*securty"):
        load_config(config_path)
