import { Router } from "express";
import { authenticator } from "otplib";
import argon2 from "argon2";
import { db, randomToken, requireSession } from "./lib.js";

export const twoFactor = Router();

twoFactor.post("/api/auth/two-factor/enable", requireSession, async (_req, res) => {
  const userId = res.locals.userId as string;
  const secret = authenticator.generateSecret(20);
  const backupCodes = Array.from({ length: 10 }, () => randomToken(6));
  const hashed = await Promise.all(backupCodes.map((c) => argon2.hash(c)));

  await db.twoFactor.upsert({
    where: { userId },
    create: { userId, secret, backupCodes: JSON.stringify(hashed) },
    update: { secret, backupCodes: JSON.stringify(hashed) },
  });

  const user = await db.user.findUniqueOrThrow({ where: { id: userId } });
  res.json({ secret, uri: authenticator.keyuri(user.email, "Acme", secret), backupCodes });
});

twoFactor.post("/api/auth/two-factor/verify", requireSession, async (req, res) => {
  const userId = res.locals.userId as string;
  const tf = await db.twoFactor.findUnique({ where: { userId } });
  if (!tf || !authenticator.check(String(req.body.code), tf.secret)) {
    return res.status(401).json({ error: "invalid code" });
  }
  await db.twoFactor.update({ where: { userId }, data: { enabled: true } });
  res.json({ ok: true });
});
