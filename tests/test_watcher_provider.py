"""Tests for the Watcher's MiniMax provider configuration."""

from __future__ import annotations

import pytest

from clawkeeper_core.watcher import agent
from clawkeeper_core.watcher.providers import (
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
    assert set(MINIMAX_MODELS) == {"MiniMax-M3", "MiniMax-M2.7"}
    assert MINIMAX_MODELS["MiniMax-M3"] == MiniMaxModelDefinition(
        model_id="MiniMax-M3",
        context_window=1_000_000,
        pricing_usd_per_million_tokens=MiniMaxTokenPricing(
            input=0.6,
            output=2.4,
            cache_read=0.12,
            cache_write=None,
        ),
        input_modalities=("text", "image", "video"),
        thinking=("adaptive", "disabled"),
    )
    assert MINIMAX_MODELS["MiniMax-M2.7"] == MiniMaxModelDefinition(
        model_id="MiniMax-M2.7",
        context_window=204_800,
        pricing_usd_per_million_tokens=MiniMaxTokenPricing(
            input=0.3,
            output=1.2,
            cache_read=0.06,
            cache_write=0.375,
        ),
        input_modalities=("text",),
        thinking=("always_on",),
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
    assert config.resolved_base_url == MINIMAX_ENDPOINTS["global_en"].openai_base_url


def test_minimax_provider_selects_cn_endpoint_and_model():
    config = resolve_minimax_provider_config(
        {
            "CK_WATCHER_PROVIDER": "minimax",
            "CK_WATCHER_REGION": "cn_zh",
            "CK_WATCHER_MODEL": "MiniMax-M2.7",
            "CK_WATCHER_API_KEY": "watcher-key",
            "MINIMAX_API_KEY": "provider-key",
        }
    )

    assert config is not None
    assert config == MiniMaxProviderConfig(
        api_key="watcher-key",
        region="cn_zh",
        model_id="MiniMax-M2.7",
    )
    assert config.resolved_base_url == MINIMAX_ENDPOINTS["cn_zh"].openai_base_url


@pytest.mark.parametrize(
    ("environment", "message"),
    [
        (
            {"CK_WATCHER_PROVIDER": "MiniMax", "CK_WATCHER_REGION": "unsupported"},
            "Unsupported MiniMax region",
        ),
        (
            {"CK_WATCHER_PROVIDER": "MiniMax", "CK_WATCHER_MODEL": "unsupported"},
            "Unsupported MiniMax model",
        ),
    ],
)
def test_minimax_provider_rejects_unknown_configuration(environment, message):
    with pytest.raises(ValueError, match=message):
        resolve_minimax_provider_config(environment)


def test_watcher_uses_explicit_minimax_provider_config(monkeypatch):
    captured = {}

    class _FakeClient:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(agent._openai_pkg, "OpenAI", _FakeClient)
    provider_config = MiniMaxProviderConfig(
        api_key="provider-key",
        region="cn_zh",
        model_id="MiniMax-M2.7",
    )

    watcher = agent.Watcher(provider_config=provider_config)

    assert watcher.model.model_id == "MiniMax-M2.7"
    assert captured["api_key"] == "provider-key"
    assert captured["base_url"] == MINIMAX_ENDPOINTS["cn_zh"].openai_base_url


def test_watcher_resolves_minimax_provider_from_environment(monkeypatch):
    captured = {}

    class _FakeClient:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(agent._openai_pkg, "OpenAI", _FakeClient)
    monkeypatch.setenv("CK_WATCHER_PROVIDER", "MiniMax")
    monkeypatch.setenv("CK_WATCHER_REGION", "global_en")
    monkeypatch.setenv("CK_WATCHER_MODEL", "MiniMax-M3")
    monkeypatch.setenv("MINIMAX_API_KEY", "provider-key")
    monkeypatch.delenv("CK_WATCHER_API_KEY", raising=False)
    monkeypatch.delenv("CK_WATCHER_BASE_URL", raising=False)

    watcher = agent.Watcher()

    assert watcher.model.model_id == "MiniMax-M3"
    assert captured["api_key"] == "provider-key"
    assert captured["base_url"] == MINIMAX_ENDPOINTS["global_en"].openai_base_url
