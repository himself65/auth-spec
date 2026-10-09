#!/usr/bin/env bash
# Did my skill change help? Runs the current evals/ suite against the skills at
# a base ref and against the working tree, then diffs the two results.
#
#   evals/scripts/compare-branch.sh [base-ref] [-- extra claude plugin eval flags]
#
#   evals/scripts/compare-branch.sh                         # vs origin/main, 2 runs per case
#   RUNS=3 evals/scripts/compare-branch.sh main
#   evals/scripts/compare-branch.sh origin/main -- --case 'audit-*'
#
# Env: RUNS (default 2), MODEL (pin it when comparing across days),
# JUDGE_MODEL, MAX_COST (per side, default 20), TOLERANCE (default 0.1).
# Results land in evals/results/compare-<timestamp>/.
set -euo pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
# pnpm forwards a literal `--`; accept `[--] [base-ref] [--] [flags...]`.
[ "${1:-}" = "--" ] && shift
base_ref="origin/main"
if [ "$#" -gt 0 ] && [ "${1#-}" = "$1" ]; then
  base_ref="$1"
  shift
fi
[ "${1:-}" = "--" ] && shift
extra=("$@")

out="$repo/evals/results/compare-$(date +%Y%m%dT%H%M%S)"
base_dir="$(mktemp -d)/base"
mkdir -p "$out"
trap 'git -C "$repo" worktree remove --force "$base_dir" >/dev/null 2>&1 || true' EXIT

git -C "$repo" worktree add --detach "$base_dir" "$base_ref" >/dev/null
# Same questions on both sides: the base gets this tree's evals/, so the only
# variable is the skill text.
rm -rf "$base_dir/evals"
cp -R "$repo/evals" "$base_dir/evals"
rm -rf "$base_dir/evals/results"

flags=(--trust-plugin --scaffold --allow-tools Write Edit --ablation none
  --runs "${RUNS:-2}" -j 4 --threshold 0 --max-cost-usd "${MAX_COST:-20}" --no-publish)
[ -n "${MODEL:-}" ] && flags+=(--model "$MODEL")
[ -n "${JUDGE_MODEL:-}" ] && flags+=(--judge-model "$JUDGE_MODEL")

echo "== base ($base_ref)"
claude plugin eval "$base_dir" "${flags[@]}" ${extra[@]+"${extra[@]}"} --json "$out/base.json" --report "$out/base.html"
echo "== head (working tree)"
claude plugin eval "$repo" "${flags[@]}" ${extra[@]+"${extra[@]}"} --json "$out/head.json" --report "$out/head.html"

node "$repo/evals/scripts/compare.mjs" "$out/base.json" "$out/head.json" \
  --tolerance "${TOLERANCE:-0.1}" --markdown "$out/summary.md"
