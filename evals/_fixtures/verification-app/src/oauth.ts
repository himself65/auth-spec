import { Router } from "express";
import { db, randomToken, createSession, googleProfile } from "./lib.js";

export const oauth = Router();

const GOOGLE = {
  authorize: "https://accounts.google.com/o/oauth2/v2/auth",
  clientId: process.env.GOOGLE_CLIENT_ID!,
  redirectUri: `${process.env.APP_URL}/api/auth/callback/google`,
};

// Starts a Google sign-in. The caller may pass the email they intend to use
// so we can pre-fill the account chooser.
oauth.post("/api/auth/sign-in/google", async (req, res) => {
  const email = String(req.body.email ?? "");
  const state = randomToken();
  await db.verification.create({
    data: {
      identifier: email,
      value: state,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000),
    },
  });
  const url = new URL(GOOGLE.authorize);
  url.searchParams.set("client_id", GOOGLE.clientId);
  url.searchParams.set("redirect_uri", GOOGLE.redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", "openid email");
  url.searchParams.set("state", state);
  if (email) url.searchParams.set("login_hint", email);
  res.json({ url: url.toString(), state });
});

oauth.get("/api/auth/callback/google", async (req, res) => {
  const state = String(req.query.state ?? "");
  const row = await db.verification.findUnique({ where: { value: state } });
  if (!row) return res.status(400).send("invalid state");
  await db.verification.delete({ where: { id: row.id } });
  const profile = await googleProfile(String(req.query.code ?? ""), GOOGLE.redirectUri);
  if (!profile.email_verified) return res.status(400).send("unverified Google email");
  const user = await db.user.upsert({
    where: { email: profile.email },
    create: { email: profile.email, emailVerified: true },
    update: {},
  });
  const token = await createSession(user.id);
  res.redirect(`/?session=${token}`);
});
