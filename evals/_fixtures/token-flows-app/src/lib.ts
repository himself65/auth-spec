import { randomBytes } from "node:crypto";
import { PrismaClient } from "@prisma/client";
import type { Request, Response, NextFunction } from "express";
import nodemailer from "nodemailer";

export const db = new PrismaClient();
export const mailer = nodemailer.createTransport(process.env.SMTP_URL);

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

export async function createSession(userId: string): Promise<string> {
  const token = randomToken();
  await db.session.create({
    data: { token, userId, expiresAt: new Date(Date.now() + 7 * 24 * 3600 * 1000) },
  });
  return token;
}

export async function requireSession(req: Request, res: Response, next: NextFunction) {
  const token = req.headers.authorization?.replace(/^Bearer /, "");
  if (!token) return res.status(401).json({ error: "unauthorized" });
  const session = await db.session.findUnique({ where: { token } });
  if (!session || session.expiresAt < new Date()) {
    return res.status(401).json({ error: "unauthorized" });
  }
  res.locals.userId = session.userId;
  next();
}

// Exchanges an authorization code with Google and returns the verified ID-token claims.
export async function googleProfile(
  code: string,
  redirectUri: string,
): Promise<{ sub: string; email: string; email_verified: boolean }> {
  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    body: new URLSearchParams({
      code,
      redirect_uri: redirectUri,
      client_id: process.env.GOOGLE_CLIENT_ID!,
      client_secret: process.env.GOOGLE_CLIENT_SECRET!,
      grant_type: "authorization_code",
    }),
  });
  const { id_token } = (await res.json()) as { id_token: string };
  return verifyGoogleIdToken(id_token);
}

declare function verifyGoogleIdToken(
  idToken: string,
): Promise<{ sub: string; email: string; email_verified: boolean }>;
