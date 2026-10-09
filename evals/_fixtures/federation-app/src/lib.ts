import { randomBytes } from "node:crypto";
import { PrismaClient } from "@prisma/client";
import type { Request, Response, NextFunction } from "express";

export const db = new PrismaClient();

export async function createSession(userId: string): Promise<string> {
  const token = randomBytes(32).toString("base64url");
  await db.session.create({
    data: { token, userId, expiresAt: new Date(Date.now() + 7 * 24 * 3600 * 1000) },
  });
  return token;
}

export async function requireSession(req: Request, res: Response, next: NextFunction) {
  const token = req.cookies.session ?? req.headers.authorization?.replace(/^Bearer /, "");
  const session = token ? await db.session.findUnique({ where: { token } }) : null;
  if (!session || session.expiresAt < new Date()) {
    return res.status(401).json({ error: "unauthorized" });
  }
  res.locals.userId = session.userId;
  next();
}

// Exchanges a GitHub code (with PKCE) and returns the primary verified email.
export declare function exchangeGithubCode(
  code: string,
  codeVerifier: string,
): Promise<{ id: string; email: string }>;
