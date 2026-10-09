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

From the repo root:

```bash
# Validate every case (schemas, graders, scaffolds) without spending anything
claude plugin eval . --trust-plugin --scaffold --allow-tools Write Edit --max-cost-usd 0 --no-publish

# Free: regex graders hit written code and ignore skill text
node evals/scripts/check-regex.mjs evals

# Full suite, with-plugin arm only (what CI gates on)
claude plugin eval . --trust-plugin --scaffold --allow-tools Write Edit --ablation none --runs 2 -j 4 --no-publish

# Add the no-plugin baseline arm to see how much the skills are worth (Δ)
claude plugin eval . --trust-plugin --scaffold --allow-tools Write Edit --runs 2 -j 4 --no-publish
```

- `--scaffold` copies each case's fixture from `_fixtures/` into the run workspace. Without it the audit cases have no code to read.
- `--allow-tools Write Edit` lets the `create-*` cases write code. Writes stay inside each run's workspace.
- Iterate on one case with `--case 'create-*' --runs 1` (pass `--case` once; a glob selects several), or `--tag sweep-2026-10`.
- Pin `--model` when comparing over time. The default judge is Haiku; use `--judge-model sonnet` when one verdict matters.

### Did my change improve the skills?

Run the same suite against the old and new skill text and diff the results:

```bash
git worktree add ../auth-spec-base origin/main
rm -rf ../auth-spec-base/evals && cp -R evals ../auth-spec-base/evals   # same questions on both sides
claude plugin eval ../auth-spec-base --trust-plugin --scaffold --allow-tools Write Edit --ablation none --runs 3 --no-publish --json base.json
claude plugin eval .                 --trust-plugin --scaffold --allow-tools Write Edit --ablation none --runs 3 --no-publish --json head.json
node evals/scripts/compare.mjs base.json head.json
```

`compare.mjs` prints a per-case table and exits 1 if the overall score drops by more than the tolerance (default 0.1) or any case drops by more than twice it. The `Skill Eval` workflow does exactly this on every PR that touches `skills/`, `evals/` or the manifest, posts the table as a PR comment, and uploads both HTML reports. It needs an `ANTHROPIC_API_KEY` repository secret, and is skipped on fork PRs.

## Authoring

Layout per case: `prompt.md` (frontmatter = limits and tools, body = the user turn), `graders/*.md` (one check each), and `case.yaml` + `scaffold.sh` when the case needs a fixture. Fixtures live in `_fixtures/` (no `prompt.md` there, so the runner never treats one as a case); the agent under test cannot read `evals/`.

- **Write prompts the way a user types them.** Never name the skill. Both skills open with `AskUserQuestion`; the eval child cannot answer it (it is not in `allowed_tools`), so prompts say "full scope, don't ask me".
- **Fixtures must not hint.** No comment may say a line is a bug. A comment that states the code's *intent* ("clients may attach `additionalData`") is fine — that is what real code says.
- **Audit graders are `llm` rubrics on the final reply.** Put everything the judge needs into the rubric (the judge sees only the rubric and the reply), and write one rubric per planted bug so the score reads as recall. Weight takeover-class bugs 3, the rest 1–2.
- **Generation graders are `regex` over the trace, anchored on a `Write`/`Edit` input** (`"file_path": "….ts", "content": "…"` or `… "new_string": "…"`). An unanchored pattern matches the skill's own reference text when Claude `Read`s it, and passes without the code ever containing it. `check-regex.mjs` guards this: it runs every regex grader against a synthetic trace of good writes, bad writes, and a `Read` of skill text. Add cases to it when you add a grader.
- **An `llm` judge with `focus: trace` sees only the first and last 12 lines** — never use it for code written mid-run.
- **Controls keep the score honest — and fail for interesting reasons.** The clean-code control caught its own fixture twice: the first "correct" reset flow awaited `sendMail` only for existing accounts (a timing oracle), and the second set `emailVerified` without binding the address the link was mailed to — which the with-skill arm flagged from the spec's own value-binding rule and the no-plugin arm missed. When a control fails, read the reply before blaming the skill. State facts the reviewer could have verified (what the schema contains, which flows exist) in the rubric, so a "High, if the schema has X" is judged against the repo, and a medium with "upgrade if something outside the repo exists" stays medium.

## Baseline (2026-10-09, one run per arm, default model)

| Case | With skills | Without | Δ | Notes |
|---|---|---|---|---|
| `create-email-password` | 1.00 | 0.56 | **+0.44** | Without the skill: no `purpose` column, non-atomic consumption |
| `create-magic-link-shared-table` | 1.00 | 0.71 | **+0.29** | Without: non-atomic consumption. `create-auth` did **not** fire on "add magic link to this project" |
| `audit-token-flows` | 0.80 | 0.80 | 0 | Both arms miss pre-account hijack on magic-link sign-in |
| `audit-federation` | 1.00 | 1.00 | 0 | The base model already finds both — ceiling |
| `audit-clean-control` | 0.00 | 1.00 | −1 | With-skill reply rated pre-account hijack "High (depends on schema)" without reading `prisma/schema.prisma` |
| `no-trigger-unrelated` | 1.00 | 1.00 | 0 | |

Improvement targets these numbers point at: `create-auth`'s description does not trigger on adding a feature to existing auth; `security-best-practice` does not carry the pre-account-hijack check for passwordless/OAuth sign-in, and should verify a finding's precondition in the repo (read the schema) before assigning its severity. Fix one, rerun, and the table should move.
- `Skill` graders are indicators only in two-arm runs; CI uses `--ablation none` so a skill that stops triggering fails the gate.
