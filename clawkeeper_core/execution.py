"""One command assessment for adapters, scans, learning and explanations.

The cache lives only inside an evaluation scope and keys the extracted inputs,
not event identity. Mutating an event or changing execution mappings cannot
reuse stale facts. This module never invokes a model or executes input code.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict

from clawkeeper_core.command_facts import FACT_VERSION, Analysis, Diagnostic
from clawkeeper_core.guards.credential_redact import scrub_context

_PREVIEW_LENGTH = 500
_MAX_CLI_BYTES = 1024 * 1024

_analyses: ContextVar[dict | None] = ContextVar("clawkeeper_command_analysis", default=None)


@contextmanager
def analysis_scope():
    if _analyses.get() is not None:
        yield
        return
    token = _analyses.set({})
    try:
        yield
    finally:
        _analyses.reset(token)


def analyze_event(event: dict) -> Analysis:
    from clawkeeper_core.guards.command_context import analyze_requests  # noqa: PLC0415
    from clawkeeper_core.guards.exec_gate import _execution_requests, load_exec_gate  # noqa: PLC0415

    try:
        requests = _execution_requests(event.get("toolName"), event.get("params"),
                                       load_exec_gate()["config"]["bashLikeTools"])
        key = tuple(requests)
        cache = _analyses.get()
        if cache is not None and key in cache:
            return cache[key]
        facts = analyze_requests(requests)
        if cache is not None:
            cache[key] = facts
        return facts
    except Exception as exc:
        return Analysis((), (), (), (Diagnostic(f"execution analyzer failed ({type(exc).__name__})", None),))


def evaluate_execution(event: dict, loaded: dict) -> dict:
    from clawkeeper_core.guards.exec_gate import _incomplete  # noqa: PLC0415
    from clawkeeper_core.learned_rules import match_learned, pin_snapshot  # noqa: PLC0415

    if not loaded["config"]["enabled"]:
        return {"block": False}
    with analysis_scope(), pin_snapshot():
        facts = analyze_event(event)
        for rule in loaded["rules"]:
            executables = rule.get("executables")
            candidates = list(facts.invocations)
            if r"\|" in rule["regex"].pattern:
                candidates.extend(facts.pipelines)
            for call in candidates:
                name = call.executable
                if executables is not None and name not in executables and not (name.startswith("mkfs.") and "mkfs" in executables):
                    continue
                if rule["regex"].search(call.text):
                    source_id = call.origin.source
                    while facts.sources[source_id].parent is not None:
                        source_id = facts.sources[source_id].parent.source
                    command = facts.sources[source_id].text
                    return {"block": True, "outcome": "deny", "source": "exec_gate",
                            "matched": rule["id"], "severity": rule.get("severity"), "reason": rule.get("reason"),
                            "analysis": "matched", "command": command[:_PREVIEW_LENGTH] + ("…" if len(command) > _PREVIEW_LENGTH else ""),
                            "evidence": {"origin": asdict(call.origin)}}
        if not facts.complete:
            return _incomplete(list(facts.errors))
        return match_learned("exec_gate", event) or {"block": False}


def explain(event: dict) -> dict:
    """Replay the real pre-tool guard chain with its pinned policy and facts."""
    from clawkeeper_core.adapters.base import run_guard_chain  # noqa: PLC0415
    from clawkeeper_core.guards.exec_gate import guard_execution  # noqa: PLC0415
    from clawkeeper_core.guards.path_guard import guard_before_tool_call  # noqa: PLC0415
    from clawkeeper_core.guards.script_body_scan import script_body_scan_guard  # noqa: PLC0415
    from clawkeeper_core.guards.url_safety import url_safety_guard  # noqa: PLC0415
    from clawkeeper_core.learned_rules import pin_snapshot  # noqa: PLC0415

    with analysis_scope(), pin_snapshot() as snapshot:
        block, findings = run_guard_chain([guard_execution, guard_before_tool_call, script_body_scan_guard, url_safety_guard], event)
        facts = analyze_event(event)
        decision = "allow" if block is None else block.get("outcome", "deny")
        result = {"decision": decision, "fact_version": FACT_VERSION, "rules_version": snapshot.version,
                  "analysis": asdict(facts), "complete": facts.complete, "findings": findings}

        def scrub(value):
            if isinstance(value, str):
                return scrub_context(value, preserve_offsets=True)
            if isinstance(value, dict):
                return {k: scrub(v) for k, v in value.items()}
            if isinstance(value, (tuple, list)):
                return [scrub(v) for v in value]
            return value

        return scrub(result)


def main() -> None:
    import argparse  # noqa: PLC0415
    import json  # noqa: PLC0415
    import sys  # noqa: PLC0415
    from pathlib import Path  # noqa: PLC0415

    from clawkeeper_core.learned_rules import install_snapshot, snapshot_from_wire  # noqa: PLC0415

    parser = argparse.ArgumentParser(description="Explain a proposed call without executing it or calling a model")
    parser.add_argument("command", nargs="?")
    parser.add_argument("--tool", default="terminal")
    parser.add_argument("--event-stdin", action="store_true", help="Read a complete tool event as JSON")
    parser.add_argument("--rules-snapshot", type=Path, help="Read an exported /watcher/rules snapshot (no store migration)")
    args = parser.parse_args()
    if args.rules_snapshot:
        with args.rules_snapshot.open("rb") as stream:
            payload = stream.read(_MAX_CLI_BYTES + 1)
        if len(payload) > _MAX_CLI_BYTES:
            parser.error("snapshot exceeds byte limit")
        install_snapshot(snapshot_from_wire(json.loads(payload)))
    if args.event_stdin or args.command is None:
        payload = sys.stdin.buffer.read(_MAX_CLI_BYTES + 1)
        if len(payload) > _MAX_CLI_BYTES:
            parser.error("input exceeds byte limit")
        try:
            event = json.loads(payload) if args.event_stdin else {"toolName": args.tool, "params": {"command": payload.decode()}}
        except (UnicodeError, ValueError):
            parser.error("invalid input encoding or JSON")
    else:
        event = {"toolName": args.tool, "params": {"command": args.command}}
    if not isinstance(event, dict):
        parser.error("event must be an object")
    print(json.dumps(explain(event), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
