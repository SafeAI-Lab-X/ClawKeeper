#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v npx >/dev/null 2>&1; then
  printf 'npx is required to install Clawkeeper into OpenClaw\n' >&2
  exit 1
fi

cd "${PROJECT_DIR}"

printf 'Installing Clawkeeper plugin into OpenClaw...\n'
npx openclaw plugins install -l .


printf '\nClawkeeper is ready.\n'
printf 'Try:\n'
printf '  npx openclaw clawkeeper audit\n'
printf '  npx openclaw clawkeeper harden\n'
printf '  npx openclaw clawkeeper monitor\n'
