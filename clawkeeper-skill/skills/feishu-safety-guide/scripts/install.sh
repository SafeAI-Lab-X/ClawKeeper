#!/usr/bin/env bash
set -euo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

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

mkdir -p "${TARGET_DIR}"
cp -R "${SOURCE_DIR}/." "${TARGET_DIR}/"
find "${TARGET_DIR}/scripts" -type f -name '*.sh' -exec chmod +x {} \;

printf 'feishu-safety-guide skill installed to %s\n' "${TARGET_DIR}"
