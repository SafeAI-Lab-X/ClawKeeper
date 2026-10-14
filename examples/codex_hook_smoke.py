"""Exercise the real Codex CLI against a deterministic local Responses fixture.

No external model, account credentials, global config changes, or real secret
reads. Uses temporary files and invocation-only hook configuration. Run with
the project's Python interpreter; a local Codex CLI with hooks is required.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOOK = Path(__file__).with_name("codex_pre_tool_use.py").resolve()
LAUNCHER = Path(__file__).with_name("start_codex_guarded.sh").resolve()


def run_case(root: Path, *, guarded: bool, trusted: bool = True, launcher: bool = False) -> dict:
    case = "guarded" if trusted else "untrusted"
    work = root / (case if guarded else "control")
    work.mkdir()
    commands = [
        "printf CLAWKEEPER_SAFE > allowed.txt",
        # Only prints a path. Even the unguarded control never reads secrets.
        "printf '%s\\n' ~/.aws/credentials > blocked.txt",
    ]
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            data = json.dumps({"models": []}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            if self.headers.get("Authorization"):
                self.send_error(400, "fixture must not receive credentials")
                return
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            index = len(requests)
            requests.append(body)
            if index < len(commands):
                names = {tool.get("name") for tool in body.get("tools", [])}
                if "exec_command" in names:
                    name, args = "exec_command", {"cmd": commands[index], "workdir": str(work)}
                elif "shell_command" in names:
                    name, args = "shell_command", {"command": commands[index], "workdir": str(work)}
                elif "shell" in names:
                    name, args = "shell", {"command": ["bash", "-lc", commands[index]], "workdir": str(work)}
                else:
                    self.send_error(400, "fixture needs a native shell tool")
                    return
                item = {
                    "type": "function_call", "id": f"fc_{index}",
                    "call_id": f"call_{index}", "name": name,
                    "arguments": json.dumps(args), "status": "completed",
                }
            else:
                item = {
                    "type": "message", "id": "msg_done", "role": "assistant",
                    "status": "completed", "content": [
                        {"type": "output_text", "text": "Local fixture completed.", "annotations": []}
                    ],
                }
            response = {"id": f"resp_{index}", "object": "response", "status": "completed", "output": [item]}
            events = [
                {"type": "response.created", "response": {**response, "status": "in_progress", "output": []}},
                {"type": "response.output_item.done", "output_index": 0, "item": item},
                {"type": "response.completed", "response": response},
            ]
            data = "".join(f"event: {event['type']}\ndata: {json.dumps(event)}\n\n" for event in events).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    hook_command = shlex.join([sys.executable, str(HOOK)])
    config = [
        'model="clawkeeper-local-fixture"',
        'model_provider="clawkeeper_fixture"',
        f'model_providers.clawkeeper_fixture={{name="Local fixture",base_url="http://127.0.0.1:{port}/v1",wire_api="responses",requires_openai_auth=false}}',
        'web_search="disabled"',
        'features.code_mode=false',
        'features.unified_exec=true',
        'analytics.enabled=false',
        f'log_dir={json.dumps(str(work / "logs"))}',
    ]
    if guarded and not launcher:
        config.append(
            'hooks.PreToolUse=[{matcher="^Bash$",hooks=[{type="command",'
            f'command={json.dumps(hook_command)},timeout=10' + '}]}]'
        )
    # Keep the user's home and Codex home untouched. Environment credentials,
    # provider URLs and proxy settings are not forwarded to the fixture.
    env = {key: os.environ[key] for key in ("PATH", "HOME", "USER", "LANG") if key in os.environ}
    prefix = ["bash", str(LAUNCHER)] if guarded and launcher else [shutil.which("codex") or "codex", "--no-daemon"]
    argv = [*prefix, "exec", "--ignore-user-config",
            "--ephemeral", "--skip-git-repo-check", "--json"]
    if not (guarded and launcher):
        argv.extend(["--sandbox", "workspace-write", "-C", str(work)])
    if guarded and trusted:
        # Only this reviewed test invocation skips persisted hook trust.
        # Real installations must use the CLI's /hooks review flow.
        argv.append("--dangerously-bypass-hook-trust")
    for value in config:
        argv.extend(["-c", value])
    argv.append("Run the local deterministic hook test fixture.")
    try:
        proc = subprocess.run(
            argv, env=env, text=True, input="", capture_output=True, timeout=45, check=False,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    (work / "codex.stdout.jsonl").write_text(proc.stdout)
    (work / "codex.stderr.txt").write_text(proc.stderr)
    tool_outputs = [
        item.get("output", "") for request in requests
        for item in request.get("input", [])
        if item.get("type") == "function_call_output"
    ]
    result = {
        "guarded": guarded, "trusted_for_test": guarded and trusted,
        "prepared_launcher": guarded and launcher, "returncode": proc.returncode,
        "requests": len(requests),
        "safe_command_executed": (work / "allowed.txt").exists(),
        "protected_path_command_executed": (work / "blocked.txt").exists(),
        "clawkeeper_feedback_seen": any("[ClawKeeper]" in str(out) for out in tool_outputs),
    }
    print(json.dumps(result), flush=True)
    if proc.returncode != 0 or len(requests) != len(commands) + 1:
        raise RuntimeError(f"Codex fixture did not complete; inspect {work}")
    assert result["safe_command_executed"], result
    assert result["protected_path_command_executed"] is (not (guarded and trusted)), result
    assert result["clawkeeper_feedback_seen"] is (guarded and trusted), result
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--launcher", action="store_true", help="Test the interactive launcher with its runtime-generated hook configuration.")
    args = parser.parse_args()
    root = Path(tempfile.mkdtemp(prefix="clawkeeper-codex-smoke-"))
    print(f"Test artifacts: {root}", flush=True)
    results = [
        run_case(root, guarded=False),
        run_case(root, guarded=True, trusted=False, launcher=args.launcher),
        run_case(root, guarded=True, launcher=args.launcher),
    ]
    (root / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("PASS: native Codex shell allowed/blocked correctly; active configuration untouched.")


if __name__ == "__main__":
    main()
