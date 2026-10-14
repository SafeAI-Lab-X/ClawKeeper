#!/usr/bin/env bash
# Add ClawKeeper only to this invocation; keep global/project config untouched.
set -euo pipefail

example_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$example_dir/.." && pwd)"
hook_python="$repo_root/.venv/bin/python"

if ! command -v codex >/dev/null 2>&1; then
  echo "Codex CLI is not on PATH." >&2
  exit 1
fi
if [[ ! -x "$hook_python" ]]; then
  echo "Missing project Python. Run: uv sync --python 3.12 --extra dev" >&2
  exit 1
fi
# Quote the hook's shell arguments, then encode the command as a TOML string.
hook_override="$("$hook_python" - "$hook_python" "$example_dir/codex_pre_tool_use.py" <<'PY'
import json
import shlex
import sys

command = json.dumps(shlex.join(sys.argv[1:]), ensure_ascii=False)
print('hooks.PreToolUse=[{matcher="^Bash$",hooks=[{type="command",'
      f'command={command},timeout=10,statusMessage="ClawKeeper: checking shell command"'
      '}]}]')
PY
)"

# Pass invocation settings to the selected subcommand as well as new chats.
# exec needs its own overrides when using --ignore-user-config in fixtures.
cli_command=()
if [[ "${1:-}" == "exec" || "${1:-}" == "resume" ]]; then
  cli_command=("$1")
  shift
fi

exec codex \
  --no-daemon \
  --ask-for-approval on-request \
  "${cli_command[@]}" \
  --enable hooks \
  --sandbox workspace-write \
  --cd "$repo_root" \
  --config "$hook_override" \
  "$@"
