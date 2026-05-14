"""Built-in safety controls — hardening checks + auto-remediation hooks.

Ported from legacy/clawkeeper-watcher/plugins/clawkeeper-watcher/src/core/controls.js.

Each control declares describe (find non-compliance) and remediate (fix it).
Controls operate on a context dict with at minimum:
    {"stateDir": Path, "config": dict, "configPath": Path, "soulPath": Path,
     "strictMode": bool}
"""

from __future__ import annotations

from typing import Any, Awaitable, Callable

from clawkeeper_core.state import ensure_rule_block, read_soul, write_json

_RISKY_SANDBOX_MODES = {"disabled", "off"}
_RISKY_EXEC_SECURITY = {"full"}
_TRUSTED_GATEWAY_BINDS = {"127.0.0.1", "localhost", "loopback"}


def _normalize_lower(value: Any) -> str:
    return value.strip().lower() if isinstance(value, str) else ""


async def _describe_local_gateway(context: dict[str, Any]) -> dict[str, Any] | None:
    bind = _normalize_lower((context.get("config") or {}).get("gateway", {}).get("bind"))
    if not bind or bind in _TRUSTED_GATEWAY_BINDS:
        return None
    return {
        "description": f"gateway.bind is currently {bind}, exposing the gateway to a wider reachable surface.",
        "evidence": {"currentBind": bind, "expected": sorted(_TRUSTED_GATEWAY_BINDS)},
        "remediation": "Restrict gateway.bind to 127.0.0.1",
        "autoFixable": True,
    }


async def _remediate_local_gateway(context: dict[str, Any]) -> str:
    config = context.setdefault("config", {})
    config.setdefault("gateway", {})["bind"] = "loopback"
    await write_json(context["configPath"], config)
    return "gateway.bind -> loopback"


async def _describe_operator_auth(context: dict[str, Any]) -> dict[str, Any] | None:
    gateway = (context.get("config") or {}).get("gateway") or {}
    has_auth = bool(
        gateway.get("authToken")
        or (gateway.get("auth") or {}).get("token")
        or (gateway.get("auth") or {}).get("password")
    )
    if has_auth:
        return None
    return {
        "description": "No gateway token or password authentication detected for operator entry point.",
        "evidence": {
            "hasAuthToken": bool(gateway.get("authToken")),
            "hasNestedToken": bool((gateway.get("auth") or {}).get("token")),
            "hasPassword": bool((gateway.get("auth") or {}).get("password")),
        },
        "remediation": "Configure token or password for gateway before exposing the control interface.",
        "autoFixable": False,
        "severity": "CRITICAL" if context.get("strictMode") else "HIGH",
    }


async def _describe_bounded_filesystem(context: dict[str, Any]) -> dict[str, Any] | None:
    mode = _normalize_lower(
        (((context.get("config") or {}).get("agents") or {}).get("defaults") or {}).get("sandbox", {}).get("mode")
    )
    if not mode or mode not in _RISKY_SANDBOX_MODES:
        return None
    return {
        "description": (
            f"agents.defaults.sandbox.mode={mode}, so filesystem/runtime containment "
            f"is effectively disabled by default."
        ),
        "evidence": {"sandboxMode": mode, "configPath": "agents.defaults.sandbox.mode"},
        "remediation": 'Adjust agents.defaults.sandbox.mode to "all"',
        "autoFixable": True,
    }


async def _remediate_bounded_filesystem(context: dict[str, Any]) -> str:
    config = context.setdefault("config", {})
    config.setdefault("agents", {}).setdefault("defaults", {}).setdefault("sandbox", {})["mode"] = "all"
    await write_json(context["configPath"], config)
    return "agents.defaults.sandbox.mode -> all"


async def _describe_human_checkpoint(context: dict[str, Any]) -> dict[str, Any] | None:
    security = _normalize_lower(
        (((context.get("config") or {}).get("tools") or {}).get("exec") or {}).get("security")
    )
    if not security or security not in _RISKY_EXEC_SECURITY:
        return None
    return {
        "description": f"tools.exec.security={security}, so host exec is not constrained to an allowlist boundary.",
        "evidence": {"security": security, "configPath": "tools.exec.security"},
        "remediation": 'Set tools.exec.security to "allowlist"',
        "autoFixable": True,
    }


async def _remediate_human_checkpoint(context: dict[str, Any]) -> str:
    config = context.setdefault("config", {})
    config.setdefault("tools", {}).setdefault("exec", {})["security"] = "allowlist"
    await write_json(context["configPath"], config)
    return "tools.exec.security -> allowlist"


async def _describe_runtime_constitution(context: dict[str, Any]) -> dict[str, Any] | None:
    content = await read_soul(context["stateDir"])
    if "clawkeeper:rules:start" in content or "clawkeeper-watcher:rules:start" in content:
        return None
    return {
        "description": "AGENTS.md lacks a clear runtime boundary rules section.",
        "evidence": {"soulPath": str(context.get("soulPath", "")), "rulesLoaded": False},
        "remediation": "Inject ClawKeeper runtime constitution into AGENTS.md",
        "autoFixable": True,
    }


async def _remediate_runtime_constitution(context: dict[str, Any]) -> str | None:
    result = await ensure_rule_block(context["stateDir"])
    return "AGENTS.md injected with runtime constitution" if result["changed"] else None


# ── Public catalogue ────────────────────────────────────────────────────────


DescribeFn = Callable[[dict[str, Any]], Awaitable[dict[str, Any] | None]]
RemediateFn = Callable[[dict[str, Any]], Awaitable[str | None]]


def get_controls() -> list[dict[str, Any]]:
    """Return the catalogue of built-in controls. Each entry is metadata +
    `describe` + optional `remediate` async callables.
    """
    return [
        {
            "id": "network.local-gateway",
            "category": "network",
            "severity": "HIGH",
            "threat": "exposure",
            "intent": "shrink-reachable-surface",
            "title": "Shrink gateway exposure surface",
            "describe": _describe_local_gateway,
            "remediate": _remediate_local_gateway,
        },
        {
            "id": "identity.operator-auth",
            "category": "identity",
            "severity": "HIGH",
            "threat": "unauthorized-access",
            "intent": "preserve-operator-boundary",
            "title": "Preserve authentication boundary for operator gateway",
            "describe": _describe_operator_auth,
        },
        {
            "id": "execution.bounded-filesystem",
            "category": "execution",
            "severity": "HIGH",
            "threat": "filesystem-overreach",
            "intent": "restore-execution-boundaries",
            "title": "Keep filesystem boundary protected",
            "describe": _describe_bounded_filesystem,
            "remediate": _remediate_bounded_filesystem,
        },
        {
            "id": "execution.human-checkpoint",
            "category": "execution",
            "severity": "MEDIUM",
            "threat": "unreviewed-side-effects",
            "intent": "require-human-gates-for-risk",
            "title": "Keep human gates for high-risk execution",
            "describe": _describe_human_checkpoint,
            "remediate": _remediate_human_checkpoint,
        },
        {
            "id": "behavior.runtime-constitution",
            "category": "behavior",
            "severity": "MEDIUM",
            "threat": "prompt-injection",
            "intent": "keep-behavioral-guardrails-loaded",
            "title": "Agent requires minimal runtime constitution",
            "describe": _describe_runtime_constitution,
            "remediate": _remediate_runtime_constitution,
        },
    ]
