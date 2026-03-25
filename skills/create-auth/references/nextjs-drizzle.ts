// Reference: Next.js App Router + Drizzle ORM + PostgreSQL
// This shows the complete auth implementation pattern for Next.js.

// --- schema.ts ---
import { pgTable, text, boolean, timestamp } from "drizzle-orm/pg-core";

export const users = pgTable("users", {
  id: text("id").primaryKey(),
  email: text("email").unique().notNull(),
  name: text("name"),
  emailVerified: boolean("email_verified").default(false).notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

export const sessions = pgTable("sessions", {
  id: text("id").primaryKey(),
  userId: text("user_id")
    .references(() => users.id)
    .notNull(),
  token: text("token").unique().notNull(),
  expiresAt: timestamp("expires_at").notNull(),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const accounts = pgTable("accounts", {
  id: text("id").primaryKey(),
  userId: text("user_id")
    .references(() => users.id)
    .notNull(),
  providerId: text("provider_id").notNull(),
  passwordHash: text("password_hash"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

// --- app/api/auth/sign-up/route.ts ---
import { db } from "@/lib/db";
import { users, accounts, sessions } from "@/lib/schema";
import { eq } from "drizzle-orm";
import { hash } from "bcryptjs";
import { NextResponse } from "next/server";

export async function POST(request: Request) {
  const { email, password, name } = await request.json();

  if (!email || !password || password.length < 8) {
    return NextResponse.json(
      { error: "Invalid email or password (min 8 chars)" },
      { status: 400 }
    );
  }

  const existing = await db
    .select()
    .from(users)
    .where(eq(users.email, email))
    .limit(1);
  if (existing.length > 0) {
    return NextResponse.json(
      { error: "Email already registered" },
      { status: 409 }
    );
  }

  const userId = crypto.randomUUID();
  const sessionToken = crypto.randomUUID();
  const passwordHash = await hash(password, 12);

  await db.transaction(async (tx) => {
    await tx.insert(users).values({
      id: userId,
      email,
      name: name ?? null,
    });
    await tx.insert(accounts).values({
      id: crypto.randomUUID(),
      userId,
      providerId: "credential",
      passwordHash,
    });
    await tx.insert(sessions).values({
      id: crypto.randomUUID(),
      userId,
      token: sessionToken,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    });
  });

  return NextResponse.json({
    user: { id: userId, email, name: name ?? null },
    token: sessionToken,
  });
}

// --- app/api/auth/sign-in/route.ts ---
import { compare } from "bcryptjs";

export async function POST(request: Request) {
  const { email, password } = await request.json();

  const user = await db
    .select()
    .from(users)
    .where(eq(users.email, email))
    .limit(1);

  if (user.length === 0) {
    return NextResponse.json(
      { error: "Invalid credentials" },
      { status: 401 }
    );
  }

  const account = await db
    .select()
    .from(accounts)
    .where(eq(accounts.userId, user[0].id))
    .limit(1);

  if (!account[0]?.passwordHash) {
    return NextResponse.json(
      { error: "Invalid credentials" },
      { status: 401 }
    );
  }

  const valid = await compare(password, account[0].passwordHash);
  if (!valid) {
    return NextResponse.json(
      { error: "Invalid credentials" },
      { status: 401 }
    );
  }

  const sessionToken = crypto.randomUUID();
  await db.insert(sessions).values({
    id: crypto.randomUUID(),
    userId: user[0].id,
    token: sessionToken,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  });

  return NextResponse.json({
    user: { id: user[0].id, email: user[0].email, name: user[0].name },
    token: sessionToken,
  });
}

// --- app/api/auth/session/route.ts ---
export async function GET(request: Request) {
  const token =
    request.headers.get("authorization")?.replace("Bearer ", "") ?? null;
  if (!token) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const session = await db
    .select()
    .from(sessions)
    .where(eq(sessions.token, token))
    .limit(1);

  if (session.length === 0 || session[0].expiresAt < new Date()) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const user = await db
    .select()
    .from(users)
    .where(eq(users.id, session[0].userId))
    .limit(1);

  return NextResponse.json({
    user: { id: user[0].id, email: user[0].email, name: user[0].name },
    expiresAt: session[0].expiresAt,
  });
}

// --- app/api/auth/sign-out/route.ts ---
export async function POST(request: Request) {
  const token =
    request.headers.get("authorization")?.replace("Bearer ", "") ?? null;
  if (token) {
    await db.delete(sessions).where(eq(sessions.token, token));
  }
  return NextResponse.json({ success: true });
}
