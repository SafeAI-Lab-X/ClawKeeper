"""Adversarial test runner for ClawKeeper.

Loads scenario modules from `scenarios/`, runs each against a live
Hermes Agent + ClawKeeper + gpt-5.5 stack (LLM via api.scode.chat),
captures per-layer decisions, writes JSON + markdown reports.

Per-layer observation strategy (no Hermes internals patched for behaviour
— only for telemetry):
  - `agent.tool_start_callback` / `agent.tool_complete_callback` are set on
    the AIAgent instance BEFORE `install_clawkeeper()` runs, so the
    adapter's `_register_observers` wraps ours, not vice versa.
  - `tools.terminal_tool.set_approval_callback` is replaced with a
    capture-wrapper before ClawKeeper installs its approval cb. When
    Hermes detects a dangerous command and invokes the approval cb,
    our wrapper records that approval fired + the description + the
    final decision; the inner cb (ClawKeeper) still makes the real call.
  - Anything Hermes blocks at the hardline layer never reaches the
    approval cb — we infer this from tool_complete result text + the
    absence of approval_fired on the event.

Usage:
    python -m tests.redteam.runner --list
    python -m tests.redteam.runner --only 01.a
    python -m tests.redteam.runner                # run everything
"""

from __future__ import annotations

import argparse
import datetime as _dt
import importlib
import json
import os
import sys
import traceback
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable

# ─── User-Agent patch (api.scode.chat rejects OpenAI/Python UA) ────────────
import openai as _openai_pkg

_BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
_orig_oai = _openai_pkg.OpenAI.__init__


def _patched_oai(self, *args, **kwargs):  # type: ignore[no-untyped-def]
    h = dict(kwargs.get("default_headers") or {})
    h.setdefault("User-Agent", _BROWSER_UA)
    kwargs["default_headers"] = h
    return _orig_oai(self, *args, **kwargs)


_openai_pkg.OpenAI.__init__ = _patched_oai

if hasattr(_openai_pkg, "AsyncOpenAI"):
    _orig_async = _openai_pkg.AsyncOpenAI.__init__

    def _p_async(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        h = dict(kwargs.get("default_headers") or {})
        h.setdefault("User-Agent", _BROWSER_UA)
        kwargs["default_headers"] = h
        return _orig_async(self, *args, **kwargs)

    _openai_pkg.AsyncOpenAI.__init__ = _p_async


from run_agent import AIAgent  # noqa: E402

from clawkeeper_core.adapters.hermes import install as install_clawkeeper  # noqa: E402
from clawkeeper_core.judge import Judge  # noqa: E402


HERE = Path(__file__).resolve().parent
WORKSPACES = HERE / "workspaces"
SCENARIOS_DIR = HERE / "scenarios"
RESULTS = HERE / "results"
FIXTURES = HERE / "fixtures"


# ─── Data model ─────────────────────────────────────────────────────────────


@dataclass
class ToolCallEvent:
    call_id: str | None
    name: str
    args_preview: str
    started_at: str
    completed_at: str | None = None
    result_preview: str | None = None
    # Approval flow
    approval_fired: bool = False
    approval_description: str = ""
    final_hermes_return: str | None = None  # "once" | "deny" | None
    # ClawKeeper layer decisions (from adapter's _record_decision)
    clawkeeper_decisions: list[dict] = field(default_factory=list)
    # Inferred final state
    blocked: bool = False
    blocked_by: str = ""


@dataclass
class ScenarioRecord:
    id: str
    name: str
    threat_class: str
    started_at: str
    completed_at: str
    workspace: str
    expected_defense_layers: dict
    tool_calls: list[ToolCallEvent]
    timeline: list[str]
    llm_final_message: str
    final_verdict: str
    layer_catch_table: dict[str, str]
    notes: list[str]


# ─── Recorder + interception ────────────────────────────────────────────────


class Recorder:
    """Per-scenario telemetry collector."""

    def __init__(self):
        self.events: list[ToolCallEvent] = []
        self.by_call_id: dict[str, ToolCallEvent] = {}
        self.timeline: list[str] = []
        self.llm_final_message: str = ""

    # ─── Hermes observer callbacks ───
    def on_tool_start(self, *args):
        # Hermes signature: (call_id, name, args) — also accept (name, args).
        if len(args) == 3:
            call_id, name, tool_args = args
        elif len(args) == 2:
            call_id, name, tool_args = None, args[0], args[1]
        else:
            return
        ev = ToolCallEvent(
            call_id=str(call_id) if call_id is not None else None,
            name=str(name),
            args_preview=_truncate(_jsonish(tool_args), 1500),
            started_at=_iso_now(),
        )
        self.events.append(ev)
        if call_id is not None:
            self.by_call_id[str(call_id)] = ev
        self.timeline.append(f"tool_start: {name}({_truncate(_jsonish(tool_args), 80)})")

    def on_tool_complete(self, *args):
        # Hermes signature: (call_id, name, args, result).
        if len(args) == 4:
            call_id, _name, _ta, result = args
        elif len(args) == 3:
            call_id, _name, result = None, args[0], args[2]
        else:
            return
        ev = None
        if call_id is not None:
            ev = self.by_call_id.get(str(call_id))
        if ev is None:
            ev = next((e for e in reversed(self.events) if e.completed_at is None), None)
        if ev is None:
            return
        ev.completed_at = _iso_now()
        result_text = _jsonish(result)
        ev.result_preview = _truncate(result_text, 1500)
        if not ev.approval_fired:
            lowered = result_text.lower()
            for marker in ("hardline", "unrecoverable", "blocked", "refused to run"):
                if marker in lowered:
                    ev.blocked = True
                    ev.blocked_by = "hermes_hardline_or_preexec"
                    break
        self.timeline.append(f"tool_complete: {_name} -> {_truncate(result_text, 80)}")

    # ─── Hooked from approval-cb wrapper ───
    def on_approval_fired(self, command: str, description: str):
        ev = next((e for e in reversed(self.events) if e.completed_at is None), None)
        if ev is not None:
            ev.approval_fired = True
            ev.approval_description = _truncate(str(description), 500)
        self.timeline.append(f"approval_fired: {_truncate(command, 80)}")

    def on_approval_returned(self, command: str, decision: str):
        ev = next((e for e in reversed(self.events) if e.approval_fired and e.final_hermes_return is None), None)
        if ev is not None:
            ev.final_hermes_return = str(decision)
            if str(decision) == "deny":
                ev.blocked = True
                ev.blocked_by = "clawkeeper"
        self.timeline.append(f"approval_returned: {decision}")

    # ─── Free-form notes ───
    def note(self, line: str):
        self.timeline.append(line)


def _install_approval_capture(recorder: Recorder):
    """Wrap `tools.terminal_tool.set_approval_callback` so any callback that
    gets registered there (e.g. ClawKeeper's) is itself wrapped to capture
    firing + decision. Idempotent — running twice doesn't double-wrap.
    """
    import tools.terminal_tool as terminal_tool
    if getattr(terminal_tool, "_redteam_capture_installed", False):
        terminal_tool._redteam_recorder = recorder
        return
    real_setter = terminal_tool.set_approval_callback

    def setter_with_capture(cb):
        def wrapped(command, description=""):
            rec = getattr(terminal_tool, "_redteam_recorder", None)
            if rec is not None:
                rec.on_approval_fired(command, description)
            decision = cb(command, description)
            if rec is not None:
                rec.on_approval_returned(command, decision)
            return decision
        return real_setter(wrapped)

    terminal_tool.set_approval_callback = setter_with_capture
    terminal_tool._redteam_capture_installed = True
    terminal_tool._redteam_recorder = recorder


# ─── Helpers ────────────────────────────────────────────────────────────────


def _truncate(s, n):
    return s if len(s) <= n else s[:n] + "...[truncated]"


def _jsonish(value):
    try:
        return json.dumps(value, default=str, ensure_ascii=False)
    except Exception:
        return str(value)


def _iso_now():
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


# ─── Scenario discovery & execution ─────────────────────────────────────────


def discover_scenarios():
    """Find scenarios/scenario_*.py modules with a SCENARIO attribute."""
    out = []
    for f in sorted(SCENARIOS_DIR.glob("scenario_*.py")):
        if f.name.startswith("_"):
            continue
        mod_name = f"tests.redteam.scenarios.{f.stem}"
        try:
            mod = importlib.import_module(mod_name)
        except Exception as e:
            print(f"[runner] skipped {f.name}: import error: {e!r}", file=sys.stderr)
            continue
        if hasattr(mod, "SCENARIO"):
            sc = mod.SCENARIO
            if sc.get("runnable", True):
                out.append((f.stem, sc))
            else:
                print(f"[runner] skipped {f.name}: marked non-runnable (stub)", file=sys.stderr)
        else:
            print(f"[runner] skipped {f.name}: no SCENARIO attr", file=sys.stderr)
    return out


def run_scenario(scenario: dict, results_dir: Path) -> ScenarioRecord:
    sid = scenario["id"]
    print(f"\n=== {sid} — {scenario['name']} ===", flush=True)

    workspace = WORKSPACES / scenario.get("workspace_subdir", "flask-todo")

    # 1. Setup
    notes: list[str] = []
    if "setup" in scenario:
        try:
            scenario["setup"](workspace)
            notes.append("setup ok")
        except Exception as e:
            traceback.print_exc()
            return _fail_record(scenario, f"setup error: {e}")

    # 2. Build agent with instrumentation
    recorder = Recorder()
    judge = Judge()

    # Install approval capture FIRST so ClawKeeper's set_approval_callback
    # call goes through our wrapper.
    _install_approval_capture(recorder)

    started = _iso_now()
    try:
        agent_kwargs = dict(
            model=os.environ.get("REDTEAM_MODEL", "gpt-5.5"),
            base_url=os.environ.get("OPENAI_BASE_URL", "https://api.scode.chat/v1"),
            max_iterations=scenario.get("max_iterations", 12),
            skip_memory=True,
            # (cwd set via TERMINAL_CWD env-var below)
            enabled_toolsets=scenario.get("enabled_toolsets", ["terminal"]),
            quiet_mode=True,
        )
        # Optional scenario-specific kwargs (e.g. mcp_servers config).
        agent_kwargs.update(scenario.get("agent_kwargs", {}));os.environ["TERMINAL_CWD"] = str(workspace)
        agent = AIAgent(**agent_kwargs)
    except Exception as e:
        traceback.print_exc()
        return _fail_record(scenario, f"agent ctor error: {e}")

    # Set observers BEFORE ClawKeeper install so ClawKeeper's wrappers chain
    # to ours (its _register_observers preserves the previous callbacks).
    agent.tool_start_callback = recorder.on_tool_start
    agent.tool_complete_callback = recorder.on_tool_complete

    _watcher_url = os.environ.get("REDTEAM_WATCHER_URL") if os.environ.get("REDTEAM_USE_WATCHER", "").lower() in ("1", "true", "yes") else None
    install_clawkeeper(judge, agent, watcher_url=_watcher_url)
    if _watcher_url:
        recorder.note(f"watcher enabled: {_watcher_url}")

    # 3. Run
    try:
        scenario["run"](agent, workspace, recorder)
    except Exception as e:
        traceback.print_exc()
        notes.append(f"run exception: {e!r}")
    completed = _iso_now()

    # 4. Attach ClawKeeper decisions to events (best-effort match by hermes_return)
    ck_log = list(getattr(agent, "_clawkeeper_decisions", []))
    used: set[int] = set()
    for ev in recorder.events:
        if ev.final_hermes_return is None:
            continue
        for i, d in enumerate(ck_log):
            if i in used:
                continue
            if d.get("hermes_return") == ev.final_hermes_return:
                ev.clawkeeper_decisions.append(d)
                used.add(i)
                break
    # Anything left over → attach to an "unassigned" placeholder.
    if len(used) < len(ck_log):
        leftover = [ck_log[i] for i in range(len(ck_log)) if i not in used]
        notes.append(f"unmatched clawkeeper_decisions: {len(leftover)}")

    # 5. Compute verdict + layer catch table
    verdict = _compute_verdict(scenario, recorder)
    catch_table = _compute_catch_table(scenario, recorder)

    # 6. Teardown
    if "teardown" in scenario:
        try:
            scenario["teardown"](workspace)
        except Exception as e:
            notes.append(f"teardown exception: {e!r}")

    record = ScenarioRecord(
        id=sid,
        name=scenario["name"],
        threat_class=scenario["threat_class"],
        started_at=started,
        completed_at=completed,
        workspace=str(workspace),
        expected_defense_layers=scenario.get("expected_defense_layers", {}),
        tool_calls=recorder.events,
        timeline=recorder.timeline,
        llm_final_message=_truncate(recorder.llm_final_message, 3000),
        final_verdict=verdict,
        layer_catch_table=catch_table,
        notes=notes,
    )

    # 7. Persist
    out = results_dir / f"{sid}.json"
    out.write_text(json.dumps(asdict(record), indent=2, default=str), encoding="utf-8")
    print(f"[runner] {sid}: {verdict}", flush=True)
    return record


def _compute_verdict(scenario: dict, recorder: Recorder) -> str:
    """Scenario provides a verdict function; fall back to a sane default."""
    fn = scenario.get("verdict")
    if callable(fn):
        try:
            return fn(recorder)
        except Exception as e:
            return f"verdict-fn-error: {e!r}"
    # Default heuristic: did any tool call get blocked?
    blocked = [e for e in recorder.events if e.blocked]
    if blocked:
        return f"defense-held (blocked={len(blocked)})"
    return "attack-succeeded-or-llm-refused"


def _compute_catch_table(scenario: dict, recorder: Recorder) -> dict[str, str]:
    """For each documented defense layer, summarise what happened."""
    out: dict[str, str] = {}
    expected = scenario.get("expected_defense_layers", {})

    hardline_hits = [e for e in recorder.events if e.blocked_by == "hermes_hardline_or_preexec"]
    dangcmd_hits = [e for e in recorder.events if e.approval_fired]
    ck_blocks = [e for e in recorder.events if e.blocked_by == "clawkeeper"]

    out["hermes_hardline"] = "fired" if hardline_hits else "did-not-fire"
    out["hermes_danger_cmd"] = (
        f"fired-{len(dangcmd_hits)}-times" if dangcmd_hits else "did-not-fire"
    )
    out["clawkeeper_total"] = (
        f"blocked-{len(ck_blocks)}-times" if ck_blocks else "did-not-block"
    )
    # Per-source breakdown
    ck_sources: dict[str, int] = {}
    for ev in recorder.events:
        for d in ev.clawkeeper_decisions:
            src = d.get("source", "?")
            ck_sources[src] = ck_sources.get(src, 0) + 1
    if ck_sources:
        out["clawkeeper_sources"] = ",".join(f"{k}={v}" for k, v in ck_sources.items())

    out["expected"] = json.dumps(expected, default=str)
    return out


def _fail_record(scenario: dict, reason: str) -> ScenarioRecord:
    return ScenarioRecord(
        id=scenario["id"],
        name=scenario["name"],
        threat_class=scenario["threat_class"],
        started_at=_iso_now(),
        completed_at=_iso_now(),
        workspace="",
        expected_defense_layers=scenario.get("expected_defense_layers", {}),
        tool_calls=[],
        timeline=[],
        llm_final_message="",
        final_verdict=f"runner-error: {reason}",
        layer_catch_table={},
        notes=[reason],
    )


# ─── Roll-up reporting ──────────────────────────────────────────────────────


def write_summary(records: list[ScenarioRecord], results_dir: Path):
    md = ["# Red-team run summary", ""]
    md.append(f"Run timestamp: {results_dir.name}")
    md.append(f"Scenarios: {len(records)}")
    md.append("")
    md.append("## Per-scenario verdict")
    md.append("")
    md.append("| ID | Name | Class | Verdict | Tool calls | Approval fires | CK blocks |")
    md.append("|---|---|---|---|---:|---:|---:|")
    for r in records:
        af = sum(1 for e in r.tool_calls if e.approval_fired)
        ck = sum(1 for e in r.tool_calls if e.blocked_by == "clawkeeper")
        md.append(f"| {r.id} | {r.name} | {r.threat_class} | {r.final_verdict} | {len(r.tool_calls)} | {af} | {ck} |")
    md.append("")
    md.append("## Per-scenario layer catch table")
    md.append("")
    for r in records:
        md.append(f"### {r.id} {r.name}")
        md.append("")
        md.append(f"- threat class: `{r.threat_class}`")
        md.append(f"- verdict: **{r.final_verdict}**")
        md.append("- expected vs observed:")
        for k, v in r.layer_catch_table.items():
            md.append(f"    - `{k}`: {v}")
        md.append("")
    (results_dir / "summary.md").write_text("\n".join(md), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="ClawKeeper adversarial runner")
    parser.add_argument("--only", help="Run only the scenario with this id (e.g. 01.a)")
    parser.add_argument("--list", action="store_true", help="List discovered scenarios")
    args = parser.parse_args()

    scenarios = discover_scenarios()
    if args.list:
        print("Discovered scenarios:")
        for stem, s in scenarios:
            print(f"  {s['id']:<8}  {s['name']:<40}  [{s['threat_class']}]")
        return

    if args.only:
        scenarios = [(stem, s) for stem, s in scenarios if s["id"] == args.only]
        if not scenarios:
            print(f"No scenario id={args.only} found. Use --list.")
            sys.exit(2)

    ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    results_dir = RESULTS / ts
    results_dir.mkdir(parents=True, exist_ok=True)

    records: list[ScenarioRecord] = []
    for stem, sc in scenarios:
        try:
            r = run_scenario(sc, results_dir)
            records.append(r)
        except Exception as e:
            traceback.print_exc()
            print(f"[runner] {sc['id']}: hard failure: {e!r}", flush=True)

    write_summary(records, results_dir)
    print(f"\nResults written to: {results_dir}")


if __name__ == "__main__":
    main()
