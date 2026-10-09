import { Router } from "express";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { db, createSession, requireSession } from "./lib.js";

export const sso = Router();

// Any signed-in user can connect their company's OIDC identity provider.
sso.post("/api/sso/providers", requireSession, async (req, res) => {
  const { issuer, clientId, jwksUri } = req.body as {
    issuer: string;
    clientId: string;
    jwksUri: string;
  };
  if (!/^https:\/\//.test(issuer) || !/^https:\/\//.test(jwksUri)) {
    return res.status(400).json({ error: "issuer and jwksUri must be https" });
  }
  const provider = await db.ssoProvider.create({
    data: { issuer, clientId, jwksUri, ownerId: res.locals.userId },
  });
  res.status(201).json({ id: provider.id });
});

// Sign in with an ID token from a registered provider.
sso.post("/api/sso/:providerId/sign-in", async (req, res) => {
  const provider = await db.ssoProvider.findUnique({ where: { id: req.params.providerId } });
  if (!provider) return res.status(404).json({ error: "unknown provider" });

  const { payload } = await jwtVerify(
    String(req.body.idToken),
    createRemoteJWKSet(new URL(provider.jwksUri)),
    { issuer: provider.issuer, audience: provider.clientId },
  );
  if (!payload.sub) return res.status(400).json({ error: "missing sub" });

  const account = await db.account.findUnique({
    where: { providerId_accountId: { providerId: provider.issuer, accountId: payload.sub } },
  });
  if (!account) return res.status(404).json({ error: "no linked account" });
  res.json({ token: await createSession(account.userId) });
});
