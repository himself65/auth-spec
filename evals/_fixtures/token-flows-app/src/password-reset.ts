import { Router } from "express";
import argon2 from "argon2";
import { db, mailer, randomToken } from "./lib.js";

export const passwordReset = Router();

passwordReset.post("/api/auth/forgot-password", async (req, res) => {
  const email = String(req.body.email ?? "").trim().toLowerCase();
  const user = await db.user.findUnique({ where: { email } });
  if (!user) return res.status(404).json({ error: "No account with that email" });

  const token = randomToken();
  await db.verification.create({
    data: { identifier: `reset:${user.id}`, value: token, expiresAt: new Date(Date.now() + 3600 * 1000) },
  });
  const link = `${req.protocol}://${req.get("host")}/reset-password?token=${token}`;
  await mailer.sendMail({ to: email, subject: "Reset your password", text: link });
  res.json({ ok: true });
});

passwordReset.post("/api/auth/reset-password", async (req, res) => {
  const { token, password } = req.body as { token: string; password: string };
  const row = await db.verification.findUnique({ where: { value: token } });
  if (!row || row.expiresAt < new Date() || !row.identifier.startsWith("reset:")) {
    return res.status(400).json({ error: "invalid token" });
  }
  const userId = row.identifier.slice("reset:".length);
  await db.user.update({
    where: { id: userId },
    data: { passwordHash: await argon2.hash(password) },
  });
  await db.verification.delete({ where: { id: row.id } });
  res.json({ ok: true });
});
