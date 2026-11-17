"""Tests for the Watcher's MiniMax provider configuration."""

from __future__ import annotations

import json

import httpx
import pytest

from clawkeeper_core.watcher import agent
from clawkeeper_core.watcher.providers import (
    MINIMAX_DEFAULT_MODEL,
    MINIMAX_ENDPOINTS,
    MINIMAX_MODELS,
    MiniMaxEndpointDefinition,
    MiniMaxModelDefinition,
    MiniMaxProviderConfig,
    MiniMaxTokenPricing,
    resolve_minimax_provider_config,
)


def test_minimax_endpoint_catalog_matches_declared_regions():
    assert MINIMAX_ENDPOINTS == {
        "global_en": MiniMaxEndpointDefinition(
            openai_base_url="https://api.minimax.io/v1",
            anthropic_base_url="https://api.minimax.io/anthropic",
            docs_root="https://platform.minimax.io/docs",
        ),
        "cn_zh": MiniMaxEndpointDefinition(
            openai_base_url="https://api.minimaxi.com/v1",
            anthropic_base_url="https://api.minimaxi.com/anthropic",
            docs_root="https://platform.minimaxi.com/docs",
        ),
    }


def test_minimax_model_catalog_matches_declared_capabilities():
    assert list(MINIMAX_MODELS) == ["MiniMax-M3.1-Flash", "MiniMax-M3"]
    assert MINIMAX_DEFAULT_MODEL == "MiniMax-M3.1-Flash"
    assert MINIMAX_MODELS[MINIMAX_DEFAULT_MODEL] == MiniMaxModelDefinition(
        model_id="MiniMax-M3.1-Flash",
        context_window=1_000_000,
        pricing_usd_per_million_tokens=MiniMaxTokenPricing(
            input=0.15,
            output=0.6,
            cache_read=0.015,
            cache_write=None,
        ),
        input_modalities=("text", "image", "video"),
        thinking=("adaptive",),
        thinking_always_on=True,
        thinking_defaults_by_api={
            "anthropic_messages": "adaptive",
            "openai_chat_completions": "adaptive",
        },
        reasoning_effort=("low", "medium", "high", "xhigh", "max"),
        reasoning_effort_default="max",
        service_tier_supported=False,
    )
    assert MINIMAX_MODELS["MiniMax-M3"] == MiniMaxModelDefinition(
        model_id="MiniMax-M3",
        context_window=1_000_000,
        pricing_usd_per_million_tokens=MiniMaxTokenPricing(
            input=0.3,
            output=1.2,
            cache_read=0.06,
            cache_write=None,
        ),
        input_modalities=("text", "image", "video"),
        thinking=("adaptive", "disabled"),
        thinking_always_on=False,
        thinking_defaults_by_api={
            "anthropic_messages": "disabled",
            "openai_chat_completions": "adaptive",
        },
        reasoning_effort=(),
        reasoning_effort_default=None,
        service_tier_supported=True,
        pricing_above_512k=MiniMaxTokenPricing(
            input=0.6,
            output=2.4,
            cache_read=0.12,
            cache_write=None,
        ),
        priority_pricing_multiplier=1.5,
    )


def test_minimax_provider_defaults_to_global_endpoint():
    config = resolve_minimax_provider_config(
        {
            "CK_WATCHER_PROVIDER": "MiniMax",
            "MINIMAX_API_KEY": "provider-key",
        }
    )

    assert config is not None
    assert config == MiniMaxProviderConfig(api_key="provider-key")
    assert config.model_id == "MiniMax-M3.1-Flash"
    assert config.resolved_base_url == MINIMAX_ENDPOINTS["global_en"].openai_base_url


def test_minimax_provider_selects_cn_endpoint_and_model():
    config = resolve_minimax_provider_config(
        {
            "CK_WATCHER_PROVIDER": "minimax",
            "CK_WATCHER_REGION": "cn_zh",
            "CK_WATCHER_MODEL": "MiniMax-M3",
            "CK_WATCHER_API_KEY": "watcher-key",
            "MINIMAX_API_KEY": "provider-key",
        }
    )

    assert config == MiniMaxProviderConfig(
        api_key="watcher-key",
        region="cn_zh",
        model_id="MiniMax-M3",
    )
    assert config.resolved_base_url == MINIMAX_ENDPOINTS["cn_zh"].openai_base_url


def test_minimax_provider_rejects_unknown_region():
    with pytest.raises(ValueError, match="Unsupported MiniMax region"):
        resolve_minimax_provider_config(
            {"CK_WATCHER_PROVIDER": "MiniMax", "CK_WATCHER_REGION": "unsupported"}
        )


@pytest.mark.parametrize("model_id", ["", "   "])
def test_minimax_provider_rejects_empty_explicit_model(model_id):
    with pytest.raises(ValueError, match="MiniMax model must not be empty"):
        MiniMaxProviderConfig(api_key="provider-key", model_id=model_id)


@pytest.fixture
def captured_requests(monkeypatch):
    """Use the real SDK serializer while keeping every request offline."""
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(
            200,
            json={
                "id": "watcher-test",
                "object": "chat.completion",
                "created": 0,
                "model": json.loads(request.content)["model"],
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": '{"decision":"allow","reason":"Safe request"}',
                        },
                        "finish_reason": "stop",
                    }
                ],
            },
        )

    original_client = agent._openai_pkg.OpenAI
    clients = []

    def make_client(**kwargs):
        client = original_client(
            **kwargs,
            http_client=httpx.Client(transport=httpx.MockTransport(respond)),
            max_retries=0,
        )
        clients.append(client)
        return client

    monkeypatch.setattr(agent._openai_pkg, "OpenAI", make_client)
    for key in (
        "CK_WATCHER_PROVIDER",
        "CK_WATCHER_REGION",
        "CK_WATCHER_MODEL",
        "CK_WATCHER_API_KEY",
        "CK_WATCHER_BASE_URL",
        "MINIMAX_API_KEY",
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
    ):
        monkeypatch.delenv(key, raising=False)
    yield requests
    for client in clients:
        client.close()


@pytest.mark.parametrize("region", ["global_en", "cn_zh"])
@pytest.mark.parametrize("selection", ["environment", "explicit"])
@pytest.mark.parametrize(
    "model_id", [None, "MiniMax-M3.1-Flash", "MiniMax-M3", "MiniMax-M2.7", "custom-deployment"]
)
def test_watcher_serializes_selected_minimax_model(
    monkeypatch, captured_requests, region, selection, model_id
):
    if selection == "environment":
        monkeypatch.setenv("CK_WATCHER_PROVIDER", "MiniMax")
        monkeypatch.setenv("CK_WATCHER_REGION", region)
        monkeypatch.setenv("MINIMAX_API_KEY", "provider-key")
        if model_id is not None:
            monkeypatch.setenv("CK_WATCHER_MODEL", model_id)
        watcher = agent.Watcher()
    else:
        options = {} if model_id is None else {"model_id": model_id}
        watcher = agent.Watcher(
            provider_config=MiniMaxProviderConfig(api_key="provider-key", region=region, **options)
        )

    decision = watcher.evaluate(session_id="provider-test", tool_name="read_file", args={})

    assert decision.decision == "allow"
    assert len(captured_requests) == 1
    request = captured_requests[0]
    assert str(request.url) == MINIMAX_ENDPOINTS[region].openai_base_url + "/chat/completions"
    assert request.headers["authorization"] == "Bearer provider-key"
    payload = json.loads(request.content)
    assert payload["model"] == (model_id or "MiniMax-M3.1-Flash")
    assert [message["role"] for message in payload["messages"]] == ["system", "user"]
    assert payload["messages"][1]["content"]
    # Keep the API's adaptive thinking and effort defaults. In particular, do
    # not send Flash's unsupported disabled/none/priority settings.
    expected_keys = {"model", "messages", "temperature"}
    if model_id in {"MiniMax-M2.7", "custom-deployment"}:
        expected_keys.add("max_tokens")
        assert {"max_tokens": payload["max_tokens"]} == {"max_tokens": 512}
    assert set(payload) == expected_keys


@pytest.mark.parametrize("selection", ["environment", "explicit"])
def test_watcher_preserves_custom_endpoint_and_multimodal_messages(
    monkeypatch, captured_requests, selection
):
    endpoint = "https://deployment.example.test/v1"
    if selection == "environment":
        monkeypatch.setenv("CK_WATCHER_PROVIDER", "MiniMax")
        monkeypatch.setenv("CK_WATCHER_BASE_URL", endpoint)
        monkeypatch.setenv("CK_WATCHER_MODEL", "saved-deployment")
        monkeypatch.setenv("CK_WATCHER_API_KEY", "watcher-key")
        monkeypatch.setenv("MINIMAX_API_KEY", "provider-key")
        watcher = agent.Watcher()
    else:
        watcher = agent.Watcher(
            provider_config=MiniMaxProviderConfig(
                api_key="watcher-key", model_id="saved-deployment", base_url=endpoint
            )
        )
    messages = [
        {"role": "system", "content": "Evaluate the supplied media."},
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "Check this input."},
                {"type": "image_url", "image_url": {"url": "https://example.test/image.png"}},
                {"type": "video_url", "video_url": {"url": "https://example.test/video.mp4"}},
            ],
        },
    ]
    watcher.model(messages)
    request = captured_requests[0]
    assert str(request.url) == endpoint + "/chat/completions"
    assert request.headers["authorization"] == "Bearer watcher-key"
    payload = json.loads(request.content)
    assert payload["model"] == "saved-deployment"
    assert payload["messages"] == messages


def test_watcher_preserves_unselected_provider_defaults(monkeypatch, captured_requests):
    monkeypatch.setenv("OPENAI_API_KEY", "default-key")
    watcher = agent.Watcher()
    messages = [{"role": "user", "content": "Check this input."}]
    watcher.model(messages)
    request = captured_requests[0]
    assert str(request.url) == "https://api.scode.chat/v1/chat/completions"
    assert json.loads(request.content) == {
        "model": "gpt-5.4-openai-compact",
        "messages": messages,
        "max_tokens": 512,
        "temperature": 0.2,
    }
