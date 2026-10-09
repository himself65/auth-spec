import { Router } from "express";
import { db, mailer, randomToken, createSession } from "./lib.js";

export const magicLink = Router();

magicLink.post("/api/auth/magic-link/send", async (req, res) => {
  const email = String(req.body.email ?? "").trim().toLowerCase();
  const token = randomToken();
  await db.verification.create({
    data: { identifier: email, value: token, expiresAt: new Date(Date.now() + 15 * 60 * 1000) },
  });
  await mailer.sendMail({
    to: email,
    subject: "Your sign-in link",
    text: `${process.env.APP_URL}/magic?token=${token}`,
  });
  res.json({ ok: true });
});

magicLink.post("/api/auth/magic-link/verify", async (req, res) => {
  const token = String(req.body.token ?? "");
  const row = await db.verification.findUnique({ where: { value: token } });
  if (!row || row.expiresAt < new Date()) return res.status(401).json({ error: "invalid" });
  await db.verification.delete({ where: { id: row.id } });

  let user = await db.user.findUnique({ where: { email: row.identifier } });
  if (!user) {
    user = await db.user.create({ data: { email: row.identifier, emailVerified: true } });
  }
  const session = await createSession(user.id);
  res.json({ token: session, user: { id: user.id, email: user.email } });
});
