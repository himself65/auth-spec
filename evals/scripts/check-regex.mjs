// Check each regex grader against hand-built JSON trace lines.
import fs from "node:fs";
import path from "node:path";

const root = process.argv[2];
const w = (fp, content) => JSON.stringify({ type: "tool_use", name: "Write", input: { file_path: fp, content } });
const e = (fp, o, n) => JSON.stringify({ type: "tool_use", name: "Edit", input: { file_path: fp, old_string: o, new_string: n } });
const read = (c) => JSON.stringify({ type: "tool_result", content: c });

const good = [
  w("/w/src/auth.ts", 'import argon2 from "argon2";\nconst h = createHash("sha256").update(t).digest("hex");\nconst r = await db.verificationToken.updateMany({ where: { id, consumedAt: null }, data: {} });\nif (r.count !== 1) return bad();\nconst link = `${process.env.APP_URL}/reset`;'),
  w("/w/prisma/schema.prisma", "model VerificationToken {\n  purpose String\n}"),
  e("/w/prisma/schema.prisma", "model Verification {", "model Verification {\n  purpose String"),
].join("\n");

const bad = [
  read('skill text: argon2 sha256 purpose deleteMany(...).count magic-link: RETURNING req.get("host")'),
  w("/w/src/auth.ts", 'const link = `${req.protocol}://${req.get("host")}/reset`; const x = await db.v.delete({ where: { id } });'),
].join("\n");

let failed = 0;
for (const c of fs.readdirSync(root)) {
  const g = path.join(root, c, "graders");
  if (!fs.existsSync(g)) continue;
  for (const f of fs.readdirSync(g)) {
    const t = fs.readFileSync(path.join(g, f), "utf8");
    if (!/type: regex/.test(t)) continue;
    const pat = t.match(/^pattern: '(.*)'$/m)[1].replace(/''/g, "'");
    const re = new RegExp(pat, "i");
    const nc = /match: not_contains/.test(t);
    const pg = re.test(good), pb = re.test(bad);
    const ok = nc ? !pg && pb : pg && !pb;
    if (!ok) failed++;
    console.log(ok ? "OK  " : "FAIL", `${c}/${f}`, { good: pg, bad: pb, notContains: nc });
  }
}
process.exit(failed ? 1 : 0);
