// Reference: Express + Prisma + PostgreSQL
// This shows the complete auth implementation pattern for Express.

// --- prisma/schema.prisma ---
// model User {
//   id            String    @id @default(uuid())
//   email         String    @unique
//   name          String?
//   image         String?
//   emailVerified Boolean   @default(false)
//   createdAt     DateTime  @default(now())
//   updatedAt     DateTime  @updatedAt
//   accounts      Account[]
//   sessions      Session[]
//   verificationTokens VerificationToken[]
// }
//
// model Session {
//   id        String   @id @default(uuid())
//   userId    String
//   token     String   @unique
//   expiresAt DateTime
//   ipAddress String?
//   userAgent String?
//   createdAt DateTime @default(now())
//   user      User     @relation(fields: [userId], references: [id])
// }
//
// model Account {
//   id           String   @id @default(uuid())
//   userId       String
//   providerId   String
//   accountId    String
//   passwordHash String?
//   createdAt    DateTime @default(now())
//   updatedAt    DateTime @updatedAt
//   user         User     @relation(fields: [userId], references: [id])
//
//   @@unique([providerId, accountId])
// }
//
// model VerificationToken {
//   id         String    @id @default(uuid())
//   userId     String
//   purpose    String
//   email      String
//   tokenHash  String    @unique
//   expiresAt  DateTime
//   consumedAt DateTime?
//   createdAt  DateTime  @default(now())
//   user       User      @relation(fields: [userId], references: [id])
//
//   @@index([userId, purpose])
// }

// --- src/routes/auth.ts ---
import { Router, Request, Response } from "express";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";
import crypto from "node:crypto";

const prisma = new PrismaClient();
const router = Router();

// One table serves both link flows; `purpose` keeps them apart so a reset link can
// never be redeemed as an email confirmation.
type TokenPurpose = "verify-email" | "password-reset";

const VERIFY_EMAIL_TTL_MS = 24 * 60 * 60 * 1000;
const PASSWORD_RESET_TTL_MS = 30 * 60 * 1000;
// Origin the emailed links point at — read it from your config/env in a real app
const APP_URL = "https://app.example.com";

// Request bodies for the link flows
interface EmailBody {
  email?: string;
}

interface VerifyEmailConfirmBody {
  token?: string;
}

interface PasswordResetConfirmBody {
  token?: string;
  password?: string;
}

// Both /verify-email/send and /password-reset/request answer with exactly this,
// whether or not the address has an account — the shape is the enumeration defence.
interface SuccessResponse {
  success: true;
}

const OK: SuccessResponse = { success: true };

// This reference ships no mail transport. Point these at your provider (SES, Resend,
// Postmark, ...) before using any of this: the raw token is never persisted, so a link
// that is not delivered cannot be recovered from the database.
async function sendVerifyEmailLink(to: string, link: string): Promise<void> {}
async function sendPasswordResetLink(to: string, link: string): Promise<void> {}

// Only the hash is stored; the raw token lives solely inside the emailed link
function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

// Issues a fresh link token and returns the raw value for the email. Outstanding tokens
// for the same user and purpose are dropped so only the newest link works.
async function issueVerificationToken(
  userId: string,
  email: string,
  purpose: TokenPurpose,
  ttlMs: number,
): Promise<string> {
  const token = crypto.randomBytes(32).toString("base64url");

  await prisma.verificationToken.deleteMany({ where: { userId, purpose } });
  await prisma.verificationToken.create({
    data: {
      userId,
      purpose,
      email,
      tokenHash: hashToken(token),
      expiresAt: new Date(Date.now() + ttlMs),
    },
  });

  return token;
}

router.post("/sign-up", async (req: Request, res: Response) => {
  const { email: rawEmail, password, name } = req.body;
  // Normalize email so lookups and the unique constraint are case-insensitive
  const email = rawEmail?.trim().toLowerCase();

  if (!email || !password || password.length < 8) {
    return res.status(400).json({ error: "Invalid email or password (min 8 chars)" });
  }

  // Always hash the password to prevent timing-based email enumeration
  const passwordHash = await bcrypt.hash(password, 12);
  const sessionToken = crypto.randomUUID();
  // Generate the user id up front so the credential account can reference it
  const userId = crypto.randomUUID();

  let user: { id: string; email: string; name: string | null };
  try {
    user = await prisma.user.create({
      data: {
        id: userId,
        email,
        name,
        accounts: {
          create: { providerId: "credential", accountId: userId, passwordHash },
        },
        sessions: {
          create: {
            token: sessionToken,
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
            ipAddress: req.ip ?? null,
            userAgent: req.headers["user-agent"] ?? null,
          },
        },
      },
      select: { id: true, email: true, name: true },
    });

  } catch (err: unknown) {
    // Unique constraint violation (duplicate email) — return fake success
    // to prevent email enumeration. The dummy token won't resolve to a session.
    if (
      err instanceof Error &&
      (err.message.includes("Unique constraint") || err.message.includes("duplicate"))
    ) {
      return res.status(200).json({
        user: { id: crypto.randomUUID(), email, name: name ?? null },
        token: crypto.randomUUID(),
      });
    }
    throw err;
  }

  // Sent after the account is committed and outside the catch above: a mail outage must
  // neither roll the sign-up back nor be mistaken for a duplicate email. A failure here is
  // not fatal — /verify-email/send reissues, and the account already exists.
  try {
    const verifyToken = await issueVerificationToken(
      user.id,
      email,
      "verify-email",
      VERIFY_EMAIL_TTL_MS,
    );
    await sendVerifyEmailLink(email, `${APP_URL}/verify-email?token=${verifyToken}`);
  } catch {
    // Transport failure only. The user can request a fresh link.
  }

  return res.status(200).json({ user, token: sessionToken });
});

router.post("/sign-in", async (req: Request, res: Response) => {
  const { email: rawEmail, password } = req.body;
  // Normalize email the same way sign-up does before the lookup
  const email = rawEmail?.trim().toLowerCase();

  const user = await prisma.user.findUnique({
    where: { email },
    include: { accounts: { where: { providerId: "credential" } } },
  });

  if (!user || !user.accounts[0]?.passwordHash) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const valid = await bcrypt.compare(password, user.accounts[0].passwordHash);
  if (!valid) {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  const sessionToken = crypto.randomUUID();
  await prisma.session.create({
    data: {
      userId: user.id,
      token: sessionToken,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      ipAddress: req.ip ?? null,
      userAgent: req.headers["user-agent"] ?? null,
    },
  });

  return res.json({
    user: { id: user.id, email: user.email, name: user.name },
    token: sessionToken,
  });
});

router.get("/session", async (req: Request, res: Response) => {
  // Set once, before any branch: this GET must never be disk-cached, or the browser
  // keeps replaying "signed in" with a stale profile after the session has expired.
  res.set("Cache-Control", "no-store");

  const token = req.headers.authorization?.replace("Bearer ", "");
  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const session = await prisma.session.findUnique({
    where: { token },
    include: { user: { select: { id: true, email: true, name: true } } },
  });

  if (!session || session.expiresAt < new Date()) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  return res.json({ user: session.user, expiresAt: session.expiresAt });
});

router.post("/sign-out", async (req: Request, res: Response) => {
  const token = req.headers.authorization?.replace("Bearer ", "");
  if (token) {
    await prisma.session.deleteMany({ where: { token } });
  }
  return res.json({ success: true });
});

// Sign-up calls this internally on success; the route itself exists for resends.
// Rate limit it per address and per IP (3/hour is reasonable) — it sends mail on demand.
router.post("/verify-email/send", async (req: Request, res: Response) => {
  const { email: rawEmail } = req.body as EmailBody;
  // Normalize the email the same way sign-up does before the lookup
  const email = rawEmail?.trim().toLowerCase();

  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  const user = await prisma.user.findUnique({ where: { email }, select: { id: true } });
  if (user) {
    const token = await issueVerificationToken(user.id, email, "verify-email", VERIFY_EMAIL_TTL_MS);
    await sendVerifyEmailLink(email, `${APP_URL}/verify-email?token=${token}`);
  }

  // Always the same 200 — an unknown address must be indistinguishable from a known one
  return res.json(OK);
});

router.post("/verify-email/confirm", async (req: Request, res: Response) => {
  const { token } = req.body as VerifyEmailConfirmBody;

  if (!token) {
    return res.status(400).json({ error: "Invalid or expired token" });
  }

  // Look up by the hash — the raw token only ever existed inside the emailed link
  const row = await prisma.verificationToken.findUnique({
    where: { tokenHash: hashToken(token) },
  });

  // Match the purpose, or a password-reset link is redeemable as an email confirmation
  if (!row || row.purpose !== "verify-email") {
    return res.status(400).json({ error: "Invalid or expired token" });
  }

  // Consume with one conditional write and check the affected-row count. Find-then-update
  // lets two concurrent requests both redeem the same link.
  const consumed = await prisma.verificationToken.updateMany({
    where: { id: row.id, consumedAt: null, expiresAt: { gt: new Date() } },
    data: { consumedAt: new Date() },
  });

  if (consumed.count !== 1) {
    return res.status(400).json({ error: "Invalid or expired token" });
  }

  // Bind the proof to the address it was issued for, and keep emailVerified itself out
  // of the guard — this write records a proof and authorizes nothing destructive. Zero
  // rows means the address changed after the link went out: discard the proof.
  const proved = await prisma.user.updateMany({
    where: { id: row.userId, email: row.email },
    data: { emailVerified: true },
  });

  if (proved.count !== 1) {
    return res.status(400).json({ error: "Invalid or expired token" });
  }

  // No credential strip here: this link was issued by the very sign-up that set the
  // password, so it confirms that password instead of adopting a stranger's.
  return res.json(OK);
});

// Same contract as /verify-email/send, on a 30-minute token. Rate limit it the same way.
router.post("/password-reset/request", async (req: Request, res: Response) => {
  const { email: rawEmail } = req.body as EmailBody;
  const email = rawEmail?.trim().toLowerCase();

  if (!email) {
    return res.status(400).json({ error: "Email is required" });
  }

  const user = await prisma.user.findUnique({ where: { email }, select: { id: true } });
  if (user) {
    const token = await issueVerificationToken(
      user.id,
      email,
      "password-reset",
      PASSWORD_RESET_TTL_MS,
    );
    await sendPasswordResetLink(email, `${APP_URL}/reset-password?token=${token}`);
  }

  return res.json(OK);
});

// Outcome of the reset transaction — a rolled-back throw would also lose the consume,
// so the branches report back instead of throwing
type ResetOutcome = "ok" | "invalid-token" | "user-changed";

router.post("/password-reset/confirm", async (req: Request, res: Response) => {
  const { token, password } = req.body as PasswordResetConfirmBody;

  // Validate the new password *before* touching the token — a rejected password must
  // not burn the link, or the user needs a whole new email to try again
  if (!token || !password || password.length < 8) {
    return res.status(400).json({ error: "Invalid token or password (min 8 chars)" });
  }

  const row = await prisma.verificationToken.findUnique({
    where: { tokenHash: hashToken(token) },
  });

  if (!row || row.purpose !== "password-reset") {
    return res.status(400).json({ error: "Invalid or expired token" });
  }

  // Hash before the consume as well: everything fallible belongs on this side of it
  const passwordHash = await bcrypt.hash(password, 12);

  const outcome: ResetOutcome = await prisma.$transaction(async (tx) => {
    const consumed = await tx.verificationToken.updateMany({
      where: { id: row.id, consumedAt: null, expiresAt: { gt: new Date() } },
      data: { consumedAt: new Date() },
    });

    if (consumed.count !== 1) {
      return "invalid-token";
    }

    // The verified flip is the gate here, so the flag belongs in the guard alongside the
    // proven address: winning it is what authorizes the strip, and an already-verified
    // row must never be stripped — its credentials belong to the owner who proved it.
    const claimed = await tx.user.updateMany({
      where: { id: row.userId, email: row.email, emailVerified: false },
      data: { emailVerified: true },
    });

    if (claimed.count === 1) {
      // This reset is the first proof of mailbox control the row has ever had, so
      // nothing it carries was proven by anyone — drop every credential Account and
      // write the new password into a fresh one.
      await tx.account.deleteMany({ where: { userId: row.userId } });
      await tx.account.create({
        data: {
          userId: row.userId,
          providerId: "credential",
          accountId: row.userId,
          passwordHash,
        },
      });
    } else {
      const user = await tx.user.findUnique({
        where: { id: row.userId },
        select: { email: true },
      });

      // Row gone, or re-addressed while the link sat in the mailbox: the proof says
      // nothing about it. The consume stands so the stale link cannot be retried.
      if (!user || user.email !== row.email) {
        return "user-changed";
      }

      // Already verified — update the credential in place, keyed on the full
      // (providerId, accountId) tuple so no other provider's ID space can collide
      await tx.account.upsert({
        where: { providerId_accountId: { providerId: "credential", accountId: row.userId } },
        update: { passwordHash },
        create: {
          userId: row.userId,
          providerId: "credential",
          accountId: row.userId,
          passwordHash,
        },
      });
    }

    // A reset is the remedy for a compromised account, so the attacker's session must
    // not survive it. Every session dies and none is minted — the user signs in again.
    await tx.session.deleteMany({ where: { userId: row.userId } });

    return "ok";
  });

  if (outcome !== "ok") {
    return res.status(400).json({ error: "Invalid or expired token" });
  }

  return res.json(OK);
});

export default router;
