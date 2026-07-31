"""First-class provider configuration for the Watcher."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Literal, cast

MiniMaxRegion = Literal["global_en", "cn_zh"]

MINIMAX_PROVIDER_NAME = "MiniMax"
MINIMAX_DEFAULT_REGION: MiniMaxRegion = "global_en"
MINIMAX_DEFAULT_MODEL = "MiniMax-M3"
MINIMAX_API_KEY_ENV = "MINIMAX_API_KEY"


@dataclass(frozen=True)
class MiniMaxTokenPricing:
    """Token prices in USD per million tokens."""

    input: float
    output: float
    cache_read: float
    cache_write: float | None


@dataclass(frozen=True)
class MiniMaxModelDefinition:
    """Watcher-relevant capabilities for a MiniMax chat model."""

    model_id: str
    context_window: int
    pricing_usd_per_million_tokens: MiniMaxTokenPricing
    input_modalities: tuple[str, ...]
    thinking: tuple[str, ...]


MINIMAX_MODELS: Mapping[str, MiniMaxModelDefinition] = MappingProxyType(
    {
        "MiniMax-M3": MiniMaxModelDefinition(
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
        ),
        "MiniMax-M2.7": MiniMaxModelDefinition(
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
        ),
    }
)

MINIMAX_ENDPOINTS: Mapping[MiniMaxRegion, str] = MappingProxyType(
    {
        "global_en": "https://api.minimax.io/v1",
        "cn_zh": "https://api.minimaxi.com/v1",
    }
)


def _read_env(environ: Mapping[str, str], key: str) -> str | None:
    value = environ.get(key)
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


@dataclass(frozen=True)
class MiniMaxProviderConfig:
    """Resolved MiniMax settings for the Watcher's chat-completions client."""

    api_key: str = field(repr=False)
    region: MiniMaxRegion = MINIMAX_DEFAULT_REGION
    model_id: str = MINIMAX_DEFAULT_MODEL
    base_url: str | None = None

    def __post_init__(self) -> None:
        if self.region not in MINIMAX_ENDPOINTS:
            raise ValueError(f"Unsupported MiniMax region: {self.region}")
        if self.model_id not in MINIMAX_MODELS:
            raise ValueError(f"Unsupported MiniMax model: {self.model_id}")

    @property
    def resolved_base_url(self) -> str:
        return self.base_url or MINIMAX_ENDPOINTS[self.region]

    @classmethod
    def from_env(cls, environ: Mapping[str, str]) -> MiniMaxProviderConfig:
        region = cast(
            MiniMaxRegion,
            _read_env(environ, "CK_WATCHER_REGION") or MINIMAX_DEFAULT_REGION,
        )
        return cls(
            api_key=(
                _read_env(environ, "CK_WATCHER_API_KEY")
                or _read_env(environ, MINIMAX_API_KEY_ENV)
                or ""
            ),
            region=region,
            model_id=_read_env(environ, "CK_WATCHER_MODEL") or MINIMAX_DEFAULT_MODEL,
            base_url=_read_env(environ, "CK_WATCHER_BASE_URL"),
        )


def resolve_minimax_provider_config(
    environ: Mapping[str, str],
) -> MiniMaxProviderConfig | None:
    """Resolve MiniMax only when it is explicitly selected for the Watcher."""

    provider_name = _read_env(environ, "CK_WATCHER_PROVIDER")
    if provider_name is None:
        return None
    if provider_name.casefold() != MINIMAX_PROVIDER_NAME.casefold():
        raise ValueError(f"CK_WATCHER_PROVIDER must be {MINIMAX_PROVIDER_NAME} when set")
    return MiniMaxProviderConfig.from_env(environ)
