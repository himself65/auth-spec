# Skill evals

Behavioral suite for [`claude plugin eval`](https://code.claude.com/docs/en/plugin-evals) (Claude Code 2.1.269+). It measures whether an edit to `skills/` makes Claude better or worse at the two jobs these skills exist for — finding auth vulnerabilities and writing auth code that avoids them — instead of judging the edit by eye.

## Cases

| Case | Skill | What it checks |
|---|---|---|
| `audit-token-flows` | security-best-practice | Finds the planted bugs in an Express+Prisma app: OAuth `state` redeemable as a magic link through a shared `Verification` table, `/two-factor/enable` overwriting an active authenticator, pre-account hijack, Host-header reset links, plaintext tokens, reset enumeration |
| `audit-federation` | security-best-practice | Finds issuer squatting by a user-registered SSO provider (GHSA-mx9r shape) and the state-cookie encryption oracle feeding a proxy callback (GHSA-r4xp shape) |
| `audit-clean-control` | security-best-practice | False-positive control: a correct reset flow must not get a critical/high finding |
| `create-email-password` | create-auth | Scaffolds sign-up/in, verification and reset: slow password hash, hashed tokens with a `purpose`, atomic consumption, links not built from `Host` |
| `create-magic-link-shared-table` | create-auth | Adds magic link to an app whose `Verification` table already holds OAuth state, with the user asking to reuse it — tokens must stay unredeemable as state |
| `no-trigger-unrelated` | — | Control: a debounce request loads neither skill |

Each sweep that adds a lesson to the spec should add (or extend) a case that fails without it. Tag it with the sweep (`sweep-2026-10`) so `--tag` reruns just those.

## Run it

Everything runs locally, on your own Claude Code login — there is no CI job. From the repo root:

```bash
pnpm eval:check      # free: regex graders hit written code and never the skill's own text
pnpm eval:compare    # did my change help? base (origin/main) vs working tree, per-case table
pnpm eval            # full suite with the no-plugin baseline arm: how much the skills are worth (Δ)
```

**Before committing a change to `skills/`, run `pnpm eval:compare`.** It checks out the base ref in a temporary worktree, gives it this tree's `evals/` (same questions on both sides, so the only variable is the skill text), runs the with-plugin arm on each, and prints:

```
Overall: 0.80 → 0.87 (+0.07)
| Case | Base | Head | Δ | |
```

It exits 1 when the overall score drops by more than `TOLERANCE` (0.1) or any case drops by more than twice that. Results and both HTML reports go to `evals/results/compare-<timestamp>/` (gitignored).

```bash
pnpm eval:compare main                               # another base ref
RUNS=3 MODEL=claude-opus-5-5 pnpm eval:compare       # more runs, pinned model
pnpm eval:compare origin/main -- --case 'audit-*'    # extra flags go to claude plugin eval
pnpm eval -- --case 'create-*' --runs 1              # iterate on one family cheaply
pnpm eval -- --max-cost-usd 0                        # load and validate every case, spend nothing
```

- Cost: the whole suite is ≈ $1.9 per side per run (≈ $3.7 for one two-arm run); `pnpm eval:compare` at the default `RUNS=2` is ≈ $8. `MAX_COST` caps each side (default $20).
- One run per case is noisy (agents vary, the judge votes 2 of 3). Use `RUNS=2`+ before trusting a small Δ, and pin `MODEL` when comparing results from different days.
- `--scaffold` copies each case's fixture from `_fixtures/` into the run workspace; `--allow-tools Write Edit` lets the `create-*` cases write code inside it. Both scripts pass them.
- `--case` takes one glob (a second `--case` replaces the first); `--tag sweep-2026-10` reruns a sweep's cases.
- Never put a bare `--` in front of flags when calling `claude plugin eval` directly: it stops option parsing, so `--max-cost-usd 0` is silently ignored and the suite runs for real. The `pnpm` scripts strip the `--` that pnpm forwards, so `pnpm eval -- --flag` and `pnpm eval --flag` are both safe.

## Authoring

Layout per case: `prompt.md` (frontmatter = limits and tools, body = the user turn), `graders/*.md` (one check each), and `case.yaml` + `scaffold.sh` when the case needs a fixture. Fixtures live in `_fixtures/` (no `prompt.md` there, so the runner never treats one as a case); the agent under test cannot read `evals/`.

- **Write prompts the way a user types them.** Never name the skill. Both skills open with `AskUserQuestion`; the eval child cannot answer it (it is not in `allowed_tools`), so prompts say "full scope, don't ask me".
- **Fixtures must not hint.** No comment may say a line is a bug. A comment that states the code's *intent* ("clients may attach `additionalData`") is fine — that is what real code says.
- **Audit graders are `llm` rubrics on the final reply.** Put everything the judge needs into the rubric (the judge sees only the rubric and the reply), and write one rubric per planted bug so the score reads as recall. Weight takeover-class bugs 3, the rest 1–2.
- **Generation graders are `regex` over the trace, anchored on a `Write`/`Edit` input** (`"file_path": "….ts", "content": "…"` or `… "new_string": "…"`). An unanchored pattern matches the skill's own reference text when Claude `Read`s it, and passes without the code ever containing it. `check-regex.mjs` guards this: it runs every regex grader against a synthetic trace of good writes, bad writes, and a `Read` of skill text. Add cases to it when you add a grader.
- **An `llm` judge with `focus: trace` sees only the first and last 12 lines** — never use it for code written mid-run.
- **Controls keep the score honest — and fail for interesting reasons.** The clean-code control caught its own fixture twice: the first "correct" reset flow awaited `sendMail` only for existing accounts (a timing oracle), and the second set `emailVerified` without binding the address the link was mailed to — which the with-skill arm flagged from the spec's own value-binding rule and the no-plugin arm missed. When a control fails, read the reply before blaming the skill. State facts the reviewer could have verified (what the schema contains, which flows exist) in the rubric, so a "High, if the schema has X" is judged against the repo, and a medium with "upgrade if something outside the repo exists" stays medium.
- `Skill` graders are indicators only in two-arm runs; `eval:compare` uses `--ablation none`, so a skill that stops triggering shows up as a score drop.

## Baseline (2026-10-09, one run per arm, default model)

| Case | With skills | Without | Δ | Notes |
|---|---|---|---|---|
| `create-email-password` | 1.00 | 0.56 | **+0.44** | Without the skill: no `purpose` column, non-atomic consumption |
| `create-magic-link-shared-table` | 1.00 | 0.71 | **+0.29** | Without: non-atomic consumption. `create-auth` did **not** fire on "add magic link to this project" |
| `audit-token-flows` | 0.80 | 0.80 | 0 | Both arms "missed" pre-account hijack — correctly: the fixture had no password sign-up, so nothing could be planted. Fixed by adding `src/password.ts`; now 1.00 / 1.00 |
| `audit-federation` | 1.00 | 1.00 | 0 | The base model already finds both — ceiling |
| `audit-clean-control` | 0.50 | 1.00 | −0.5 | Re-measured with 2 runs per arm after the fixture/rubric fixes ($0.81). The failing with-skill run rated pre-account hijack "High (conditional)" because "the schema isn't visible in `src/`" — it never opened `prisma/schema.prisma` |
| `no-trigger-unrelated` | 1.00 | 1.00 | 0 | |

Improvement targets these numbers pointed at, and what happened:

| Target | Result |
|---|---|
| `security-best-practice` rates conditional findings "High" without reading the schema that refutes them | Fixed (Step 1 reads the whole repo; Step 3 rates severity from verified preconditions). Clean control, all runs since the fixture fixes: old skill 2 false-High in 9 runs, new skill 0 in 7. Costs ~1.5× per audit run because rule files are now read |
| `security-best-practice` misses pre-account hijack | Not a skill gap — a fixture bug (see the table). The new skill said so explicitly: "no password sign-up route, so nothing can be pre-registered" |
| `create-auth` does not trigger on adding a feature to existing auth | Open |

When a skill "misses" a planted bug in every arm, check the bug's precondition actually holds in the fixture before blaming the skill.
