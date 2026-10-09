import { PrismaClient } from "@prisma/client";
import type { Request, RequestHandler } from "express";
import nodemailer from "nodemailer";
import { Redis } from "ioredis";

export const db = new PrismaClient();
export const mailer = nodemailer.createTransport(process.env.SMTP_URL);
const redis = new Redis(process.env.REDIS_URL!);

const EMAIL_RE = /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)+$/;

// NFKC -> trim -> lowercase, then validate the canonical string.
export function canonicalEmail(input: unknown): string | null {
  if (typeof input !== "string") return null;
  const email = input.normalize("NFKC").trim().toLowerCase();
  return email.length <= 254 && EMAIL_RE.test(email) ? email : null;
}

const INCR = `local v = redis.call("INCR", KEYS[1])
if v == 1 then redis.call("EXPIRE", KEYS[1], ARGV[1]) end
return v`;

// Fixed-window limiter with an atomic check-and-increment.
export function rateLimit(opts: {
  key: (req: Request) => string;
  max: number;
  windowSeconds: number;
}): RequestHandler {
  return async (req, res, next) => {
    const window = Math.floor(Date.now() / 1000 / opts.windowSeconds);
    try {
      const count = (await redis.eval(INCR, 1, `${opts.key(req)}:${window}`, opts.windowSeconds)) as number;
      if (count > opts.max) return res.status(429).json({ error: "Too many requests" });
    } catch {
      // limiter store unavailable: fail open
    }
    next();
  };
}
