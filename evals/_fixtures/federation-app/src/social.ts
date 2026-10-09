import { Router } from "express";
import { randomBytes, createHash } from "node:crypto";
import { seal, open } from "./seal.js";
import { db, createSession, exchangeGithubCode } from "./lib.js";

export const social = Router();

type OAuthState = {
  provider: string;
  state: string;
  codeVerifier: string;
  callbackURL: string;
  [extra: string]: unknown;
};

// Starts a GitHub sign-in. Clients may attach `additionalData` that is handed
// back to them after the callback (e.g. a referral code or UI hints).
social.post("/api/auth/sign-in/github", (req, res) => {
  const state = randomBytes(16).toString("base64url");
  const codeVerifier = randomBytes(32).toString("base64url");
  const payload: OAuthState = {
    ...(req.body.additionalData ?? {}),
    provider: "github",
    state,
    codeVerifier,
    callbackURL: String(req.body.callbackURL ?? "/"),
  };
  res.cookie("oauth_state", seal(payload), { httpOnly: true, secure: true, sameSite: "lax" });
  const challenge = createHash("sha256").update(codeVerifier).digest("base64url");
  const url = new URL("https://github.com/login/oauth/authorize");
  url.searchParams.set("client_id", process.env.GITHUB_CLIENT_ID!);
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", "S256");
  res.json({ url: url.toString() });
});

social.get("/api/auth/callback/github", async (req, res) => {
  const saved = open<OAuthState>(req.cookies.oauth_state ?? "");
  if (!saved || saved.provider !== "github" || saved.state !== req.query.state) {
    return res.status(400).send("invalid state");
  }
  const profile = await exchangeGithubCode(String(req.query.code), saved.codeVerifier);
  // Preview deployments can't receive GitHub callbacks directly, so production
  // finishes the exchange and forwards the verified profile to the preview.
  if (saved.callbackURL.startsWith("https://preview-")) {
    const forwarded = seal({ email: profile.email, sub: profile.id, provider: "github" });
    return res.redirect(`${saved.callbackURL}/api/auth/proxy-callback?profile=${forwarded}`);
  }
  const user = await db.user.upsert({
    where: { email: profile.email },
    create: { email: profile.email, emailVerified: true },
    update: {},
  });
  res.cookie("session", await createSession(user.id), { httpOnly: true, secure: true });
  res.redirect(saved.callbackURL);
});

// Runs on preview deployments (same AUTH_SECRET as production).
social.get("/api/auth/proxy-callback", async (req, res) => {
  const profile = open<{ email: string; sub: string; provider: string }>(String(req.query.profile));
  if (!profile?.email) return res.status(400).send("invalid profile");
  const user = await db.user.upsert({
    where: { email: profile.email },
    create: { email: profile.email, emailVerified: true },
    update: {},
  });
  res.cookie("session", await createSession(user.id), { httpOnly: true, secure: true });
  res.redirect("/");
});
