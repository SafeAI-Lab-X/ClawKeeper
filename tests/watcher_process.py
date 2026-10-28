"""Subprocess fixtures. Every command is an inert string, never executed."""

# Import optional Watcher dependencies only in fixtures that need them.
# ruff: noqa: PLC0415

import json
import sys
from types import ModuleType, SimpleNamespace


def fake_hermes_modules(set_module):
    """Provide the public callback/hook surfaces without a Hermes installation."""
    terminal = ModuleType("tools.terminal_tool")
    computer = ModuleType("tools.computer_use.tool")
    terminal.set_approval_callback = lambda cb: setattr(terminal, "callback", cb)
    computer.set_approval_callback = lambda cb: setattr(computer, "callback", cb)
    tools = ModuleType("tools")
    tools.__path__ = []
    tools.terminal_tool = terminal
    computer_use = ModuleType("tools.computer_use")
    computer_use.tool = computer
    tools.computer_use = computer_use
    hermes = ModuleType("hermes_cli")
    hermes.__path__ = []
    plugins = ModuleType("hermes_cli.plugins")
    manager = SimpleNamespace(_hooks={})
    plugins._ensure_plugins_discovered = lambda: manager
    hermes.plugins = plugins
    for name, module in {
        "tools": tools,
        "tools.terminal_tool": terminal,
        "tools.computer_use": computer_use,
        "tools.computer_use.tool": computer,
        "hermes_cli": hermes,
        "hermes_cli.plugins": plugins,
    }.items():
        set_module(name, module)
    return terminal, computer, manager


def run_server(store_path, descriptor):
    from pathlib import Path

    import uvicorn

    from clawkeeper_core.watcher import agent, daemon, learner, reload
    from clawkeeper_core.watcher.tools import SessionHistory

    store = learner.LearnedPatternStore(Path(store_path))
    for module in (agent, daemon, learner, reload):
        module.STORE = store

    class Model:
        def __call__(self, messages):
            if len(messages) == 1:
                module = "python -m CK_CANARY_" in messages[0]["content"]
                payload = {
                    "pattern": r"python\s+-m\s+CK_CANARY_\d+" if module else r"CK_CANARY_\d+",
                    "guard_target": "exec_gate",
                    "confidence": 0.99,
                }
                if "CK_FIELD_" in messages[0]["content"]:
                    payload.update(pattern=r"CK_FIELD_\d+", subject=(
                        "python.module" if "python -m CK_FIELD_" in messages[0]["content"] else "program.name"))
            else:
                payload = {
                    "decision": "deny" if any(marker in messages[-1]["content"] for marker in ("CK_CANARY", "CK_FIELD")) else "allow",
                    "reason": "synthetic",
                    "confidence": 0.99,
                    "severity": "high",
                    "signals": [],
                }
            return SimpleNamespace(content=json.dumps(payload))

    app = daemon.build_app(agent.Watcher(model=Model(), history=SessionHistory()))
    uvicorn.run(app, fd=int(descriptor), log_level="error")


def run_adapter(base_url):
    from clawkeeper_core.adapters.base import make_event
    from clawkeeper_core.adapters.hermes import install
    from clawkeeper_core.guards.exec_gate import guard_execution
    from clawkeeper_core.judge import Judge
    from clawkeeper_core.learned_rules import current_snapshot

    terminal, _, manager = fake_hermes_modules(sys.modules.__setitem__)
    agent = SimpleNamespace(
        session_id="subprocess",
        conversation_history=[],
        tool_start_callback=None,
        tool_complete_callback=None,
    )
    install(Judge(), agent, watcher_url=base_url)
    hook = manager._hooks["pre_tool_call"][0]
    for line in sys.stdin:
        request = json.loads(line)
        command = request.get("command", "ls -la")
        action = request["action"]
        if action == "pre":
            result = hook(tool_name="terminal", args={"command": command})
        elif action == "approval":
            result = terminal.callback(command)
        else:
            result = guard_execution(make_event(tool_name="terminal", command=command))
        print(json.dumps({"result": result, "version": current_snapshot().version}), flush=True)


if __name__ == "__main__":
    if sys.argv[1] == "server":
        run_server(sys.argv[2], sys.argv[3])
    else:
        run_adapter(sys.argv[2])
