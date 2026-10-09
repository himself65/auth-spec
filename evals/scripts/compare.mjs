// Compare two `claude plugin eval --json` results (base vs head) case by case.
//
//   node evals/scripts/compare.mjs base.json head.json [--tolerance 0.1] [--markdown out.md]
//
// Exits 1 when the head's overall score drops by more than the tolerance, or
// when any single case drops by more than twice the tolerance. A case that is
// new in head is reported but never fails the comparison. Runs are noisy (an
// LLM judge votes 2 of 3, agents vary run to run), so the tolerance absorbs
// ordinary jitter; tighten it as `--runs` goes up.
import fs from "node:fs";

const args = process.argv.slice(2);
const opt = (name, fallback) => {
  const i = args.indexOf(name);
  return i === -1 ? fallback : args.splice(i, 2)[1];
};
const tolerance = Number(opt("--tolerance", "0.1"));
const markdownOut = opt("--markdown", null);
const [basePath, headPath] = args;
if (!basePath || !headPath) {
  console.error("usage: compare.mjs base.json head.json [--tolerance 0.1] [--markdown out.md]");
  process.exit(2);
}

const load = (p) => {
  const r = JSON.parse(fs.readFileSync(p, "utf8"));
  if (r.partial) console.warn(`warning: ${p} is partial (${r.partialReason ?? "unknown reason"})`);
  const cases = new Map((r.cases ?? []).map((c) => [c.name, c.aggregates?.score ?? null]));
  return { overall: r.aggregates?.overallScore ?? null, cases, cost: r.costUsd ?? 0 };
};
const base = load(basePath);
const head = load(headPath);

const fmt = (v) => (v == null ? "—" : v.toFixed(2));
const sign = (d) => (d == null ? "" : d > 0 ? `+${d.toFixed(2)}` : d.toFixed(2));

const rows = [];
let failed = false;
for (const name of new Set([...base.cases.keys(), ...head.cases.keys()])) {
  const b = base.cases.get(name) ?? null;
  const h = head.cases.get(name) ?? null;
  const d = b != null && h != null ? h - b : null;
  let verdict = "";
  if (b == null) verdict = "new";
  else if (h == null) verdict = "removed";
  else if (d < -2 * tolerance) {
    verdict = "REGRESSED";
    failed = true;
  } else if (d > tolerance) verdict = "improved";
  rows.push({ name, b, h, d, verdict });
}

const overallDelta = base.overall != null && head.overall != null ? head.overall - base.overall : null;
if (overallDelta != null && overallDelta < -tolerance) failed = true;

const lines = [
  `### Skill eval: head vs base`,
  ``,
  `Overall: **${fmt(base.overall)} → ${fmt(head.overall)}** (${sign(overallDelta)})${failed ? " — regression" : ""}`,
  ``,
  `| Case | Base | Head | Δ | |`,
  `|---|---|---|---|---|`,
  ...rows.map((r) => `| ${r.name} | ${fmt(r.b)} | ${fmt(r.h)} | ${sign(r.d)} | ${r.verdict} |`),
  ``,
  `Tolerance ${tolerance} (overall) / ${2 * tolerance} (per case). Cost: base $${base.cost.toFixed(2)}, head $${head.cost.toFixed(2)}.`,
];
const md = lines.join("\n");
console.log(md);
if (markdownOut) fs.writeFileSync(markdownOut, md + "\n");
process.exit(failed ? 1 : 0);
