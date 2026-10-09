#!/usr/bin/env bash
# Runs the eval suite against this checkout's skills. Extra args go to
# `claude plugin eval`; a leading `--` (pnpm forwards it verbatim) is dropped,
# because claude would otherwise stop parsing options there and silently ignore
# flags such as --max-cost-usd.
#
#   pnpm eval                              # both arms: with-plugin score and Δ vs no plugin
#   pnpm eval --case 'create-*' --runs 1
#   pnpm eval --max-cost-usd 0             # load and validate every case, spend nothing
set -euo pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
[ "${1:-}" = "--" ] && shift

exec claude plugin eval "$repo" --trust-plugin --scaffold --allow-tools Write Edit --no-publish "$@"
