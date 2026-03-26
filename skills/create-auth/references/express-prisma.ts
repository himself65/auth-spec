// Reference: Express + Prisma + PostgreSQL
// This shows the complete auth implementation pattern for Express.

// --- prisma/schema.prisma ---
// model User {
//   id            String    @id @default(uuid())
//   email         String    @unique
//   name          String?
//   emailVerified Boolean   @default(false)
//   createdAt     DateTime  @default(now())
//   updatedAt     DateTime  @updatedAt
//   accounts      Account[]
//   sessions      Session[]
// }
//
// model Session {
//   id        String   @id @default(uuid())
//   userId    String
//   token     String   @unique
//   expiresAt DateTime
//   createdAt DateTime @default(now())
//   user      User     @relation(fields: [userId], references: [id])
// }
//
// model Account {
//   id           String   @id @default(uuid())
//   userId       String
//   providerId   String
//   passwordHash String?
//   createdAt    DateTime @default(now())
//   updatedAt    DateTime @updatedAt
//   user         User     @relation(fields: [userId], references: [id])
// }

// --- src/routes/auth.ts ---
import { Router, Request, Response } from "express";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";
import crypto from "node:crypto";

const prisma = new PrismaClient();
const router = Router();

router.post("/sign-up", async (req: Request, res: Response) => {
  const { email, password, name } = req.body;

  if (!email || !password || password.length < 8) {
    return res.status(400).json({ error: "Invalid email or password (min 8 chars)" });
  }

  // Always hash the password to prevent timing-based email enumeration
  const passwordHash = await bcrypt.hash(password, 12);
  const sessionToken = crypto.randomUUID();

  try {
    const user = await prisma.user.create({
      data: {
        email,
        name,
        accounts: {
          create: { providerId: "credential", passwordHash },
        },
        sessions: {
          create: {
            token: sessionToken,
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
          },
        },
      },
      select: { id: true, email: true, name: true },
    });

    return res.status(200).json({ user, token: sessionToken });
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
});

router.post("/sign-in", async (req: Request, res: Response) => {
  const { email, password } = req.body;

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
    },
  });

  return res.json({
    user: { id: user.id, email: user.email, name: user.name },
    token: sessionToken,
  });
});

router.get("/session", async (req: Request, res: Response) => {
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

export default router;
