import { Router } from "express";
import { createHash, randomBytes } from "node:crypto";
import argon2 from "argon2";
import { db, mailer, canonicalEmail, rateLimit } from "./lib.js";

export const passwordReset = Router();

const APP_URL = process.env.APP_URL!; // configured public origin, never derived from the request
const RESET_TTL_MS = 30 * 60 * 1000;
const sha256 = (v: string) => createHash("sha256").update(v).digest("hex");

passwordReset.post(
  "/api/auth/forgot-password",
  rateLimit({ key: (req) => `rl:forgot:${req.ip}`, max: 5, windowSeconds: 900 }),
  (req, res) => {
    const email = canonicalEmail(req.body?.email);
    // Respond before doing any per-account work, so status, body and timing are
    // identical whether or not the account exists; failures are only logged.
    res.set("Cache-Control", "no-store").json({ ok: true });
    if (email) {
      issueResetLink(email).catch((err) => console.error("forgot-password", err));
    }
  },
);

async function issueResetLink(email: string): Promise<void> {
  const user = await db.user.findUnique({ where: { email } });
  if (!user) return;
  const token = randomBytes(32).toString("base64url");
  await db.$transaction([
    db.verificationToken.deleteMany({ where: { userId: user.id, purpose: "password-reset" } }),
    db.verificationToken.create({
      data: {
        userId: user.id,
        purpose: "password-reset",
        email: user.email,
        tokenHash: sha256(token),
        expiresAt: new Date(Date.now() + RESET_TTL_MS),
      },
    }),
  ]);
  await mailer.sendMail({
    to: user.email,
    subject: "Reset your password",
    text: `${APP_URL}/reset-password?token=${encodeURIComponent(token)}`,
  });
}

passwordReset.post(
  "/api/auth/reset-password",
  rateLimit({ key: (req) => `rl:reset:${req.ip}`, max: 10, windowSeconds: 900 }),
  async (req, res) => {
    const token = typeof req.body?.token === "string" ? req.body.token : "";
    const password = typeof req.body?.password === "string" ? req.body.password : "";
    if (password.length < 8 || password.length > 128) {
      return res.status(400).json({ error: "Password must be 8-128 characters" });
    }
    // Cheap existence check first, so an invented token never costs an argon2 hash.
    const live = await db.verificationToken.findFirst({
      where: { tokenHash: sha256(token), purpose: "password-reset", consumedAt: null, expiresAt: { gt: new Date() } },
      select: { id: true },
    });
    if (!live) return res.status(400).json({ error: "Invalid or expired link" });
    const passwordHash = await argon2.hash(password, { type: argon2.argon2id });

    const ok = await db.$transaction(async (tx) => {
      const row = await tx.verificationToken.findUnique({ where: { id: live.id } });
      if (!row) return false;
      const consumed = await tx.verificationToken.updateMany({
        where: { id: row.id, consumedAt: null, expiresAt: { gt: new Date() } },
        data: { consumedAt: new Date() },
      });
      if (consumed.count !== 1) return false;
      // The link proves control of the address it was mailed to, so only that
      // address may be marked verified; if the account's email changed since,
      // the (now spent) link does nothing.
      const updated = await tx.user.updateMany({
        where: { id: row.userId, email: row.email },
        data: { passwordHash, emailVerified: true },
      });
      if (updated.count !== 1) return false;
      await tx.session.deleteMany({ where: { userId: row.userId } });
      return true;
    });

    if (!ok) return res.status(400).json({ error: "Invalid or expired link" });
    res.set("Cache-Control", "no-store").json({ ok: true });
  },
);
