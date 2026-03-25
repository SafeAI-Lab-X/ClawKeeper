#!/usr/bin/env bash
set -euo pipefail

detect_state_dir() {
  if [[ -n "${OPENCLAW_HOME:-}" && -d "${OPENCLAW_HOME}" ]]; then
    printf '%s\n' "${OPENCLAW_HOME}"
    return
  fi

  for candidate in "${HOME}/.openclaw" "${HOME}/.moltbot" "${HOME}/.clawdbot" "${HOME}/clawd"; do
    if [[ -d "${candidate}" ]]; then
      printf '%s\n' "${candidate}"
      return
    fi
  done

  printf '%s\n' "${HOME}/.openclaw"
}

STATE_DIR="$(detect_state_dir)"
TARGET_DIR="${STATE_DIR}/skills/feishu-safety-guide"

rm -rf "${TARGET_DIR}"
printf 'feishu-safety-guide skill removed from %s\n' "${TARGET_DIR}"
