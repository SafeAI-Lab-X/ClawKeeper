"""Lightweight JSON-schema-subset input validator.
Ported from legacy/clawkeeper-plugin/src/core/input-validator.js.

Supported keywords: type, required, properties, additionalProperties,
minLength, maxLength, pattern, enum.
"""

from __future__ import annotations

import re
from typing import Any

_DEFAULT_FAILURE_POLICY = "fail-open"


def _type_of(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "boolean"
    if isinstance(v, (int, float)):
        return "number"
    if isinstance(v, str):
        return "string"
    if isinstance(v, list):
        return "array"
    if isinstance(v, dict):
        return "object"
    return "unknown"


def _check_schema(schema: dict[str, Any], value: Any, where: str = "$") -> list[str]:
    errors: list[str] = []
    if not isinstance(schema, dict):
        return errors

    expected = schema.get("type")
    actual = _type_of(value)
    if expected and expected != actual:
        # number accepts int or float; otherwise types must match
        ok = (expected == "number" and actual == "number")
        if not ok and expected != actual:
            errors.append(f"{where}: expected {expected}, got {actual}")
            return errors

    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{where}: value not in enum")

    if actual == "string":
        if isinstance(schema.get("minLength"), int) and len(value) < schema["minLength"]:
            errors.append(f"{where}: string shorter than minLength={schema['minLength']}")
        if isinstance(schema.get("maxLength"), int) and len(value) > schema["maxLength"]:
            errors.append(f"{where}: string longer than maxLength={schema['maxLength']} (got {len(value)})")
        if schema.get("pattern"):
            try:
                if not re.search(str(schema["pattern"]), value):
                    errors.append(f"{where}: string does not match pattern")
            except re.error:
                pass

    if actual == "object":
        required = schema.get("required")
        if isinstance(required, list):
            for k in required:
                if k not in value or value[k] is None or value[k] == "":
                    errors.append(f"{where}.{k}: required field missing")
        props = schema.get("properties") or {}
        allow_extra = schema.get("additionalProperties") is not False
        for k, v in value.items():
            if k in props:
                errors.extend(_check_schema(props[k], v, f"{where}.{k}"))
            elif not allow_extra:
                errors.append(f"{where}.{k}: unknown property")

    return errors


_DEFAULT_SCHEMAS: dict[str, dict[str, Any]] = {
    "bash": {
        "tool": "bash",
        "type": "object",
        "required": ["command"],
        "properties": {
            "command": {"type": "string", "minLength": 1, "maxLength": 10000},
            "description": {"type": "string", "maxLength": 500},
            "timeout": {"type": "number"},
        },
        "additionalProperties": True,
    },
    "read_file": {
        "tool": "read_file",
        "aliases": ["read", "fs_read"],
        "type": "object",
        "required": ["path"],
        "properties": {"path": {"type": "string", "minLength": 1, "maxLength": 4096}},
        "additionalProperties": True,
    },
    "write_file": {
        "tool": "write_file",
        "aliases": ["write", "fs_write"],
        "type": "object",
        "required": ["path", "content"],
        "properties": {
            "path": {"type": "string", "minLength": 1, "maxLength": 4096},
            "content": {"type": "string"},
        },
        "additionalProperties": True,
    },
}

_cached: dict[str, Any] | None = None


def load_validator(schemas_override: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    """Return cached validator config. Pass a dict of {tool: schema} to override."""
    global _cached
    if _cached is not None and schemas_override is None:
        return _cached
    src = schemas_override if schemas_override is not None else _DEFAULT_SCHEMAS
    schemas: dict[str, dict[str, Any]] = {}
    for schema in src.values():
        names = [schema.get("tool")] + list(schema.get("aliases") or [])
        for n in names:
            if n:
                schemas[str(n).lower()] = schema
    _cached = {
        "schemas": schemas,
        "config": {"enabled": True, "failurePolicy": _DEFAULT_FAILURE_POLICY, "unknownToolPolicy": "pass"},
    }
    return _cached


def reset_validator_cache() -> None:
    global _cached
    _cached = None


def validate_tool_input(tool_name: Any, params: Any) -> dict[str, Any]:
    loaded = load_validator()
    schemas, cfg = loaded["schemas"], loaded["config"]
    if not cfg["enabled"]:
        return {"block": False}

    key = str(tool_name or "").lower()
    schema = schemas.get(key)
    if not schema:
        if cfg["unknownToolPolicy"] == "block":
            return {"block": True, "unknownTool": True,
                    "reason": f"no schema registered for tool '{tool_name}'"}
        return {"block": False, "unknownTool": True}

    errors = _check_schema(schema, params or {})
    if errors:
        return {"block": True, "reason": f"input validation failed: {errors[0]}", "errors": errors}
    return {"block": False}
