import { Router } from "express";
import argon2 from "argon2";
import { db, createSession } from "./lib.js";

export const password = Router();

// Same response whether or not the email is taken, so sign-up can't be used
// to enumerate accounts. Verification mail is sent by a background job.
password.post("/api/auth/sign-up", async (req, res) => {
  const email = String(req.body.email ?? "").trim().toLowerCase();
  const pw = String(req.body.password ?? "");
  if (!email.includes("@") || pw.length < 8) return res.status(400).json({ error: "invalid input" });
  const existing = await db.user.findUnique({ where: { email } });
  if (!existing) {
    await db.user.create({ data: { email, passwordHash: await argon2.hash(pw) } });
  }
  res.status(202).json({ ok: true, message: "Check your inbox to confirm your email." });
});

password.post("/api/auth/sign-in", async (req, res) => {
  const email = String(req.body.email ?? "").trim().toLowerCase();
  const pw = String(req.body.password ?? "");
  const user = await db.user.findUnique({ where: { email } });
  if (!user?.passwordHash || !(await argon2.verify(user.passwordHash, pw))) {
    return res.status(401).json({ error: "invalid credentials" });
  }
  res.json({ token: await createSession(user.id) });
});
