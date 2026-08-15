// Reference: Next.js App Router + Drizzle ORM + PostgreSQL
// This shows the complete auth implementation pattern for Next.js.

// --- schema.ts ---
import { pgTable, text, boolean, timestamp, unique } from "drizzle-orm/pg-core";

export const users = pgTable("users", {
  id: text("id").primaryKey(),
  email: text("email").unique().notNull(),
  name: text("name"),
  image: text("image"),
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
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const accounts = pgTable("accounts", {
  id: text("id").primaryKey(),
  userId: text("user_id")
    .references(() => users.id)
    .notNull(),
  providerId: text("provider_id").notNull(),
  accountId: text("account_id").notNull(),
  passwordHash: text("password_hash"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
}, (table) => [unique().on(table.providerId, table.accountId)]);

// One table serves both the verify-email and password-reset flows; `purpose`
// keeps them apart and is matched again at redemption, so a reset link cannot be
// redeemed as an email confirmation. Only the hash is stored — the raw token
// exists solely inside the emailed link. `email` records what the token proves,
// so a later address change cannot inherit the proof.
export const verificationTokens = pgTable("verification_tokens", {
  id: text("id").primaryKey(),
  userId: text("user_id")
    .references(() => users.id)
    .notNull(),
  purpose: text("purpose").notNull(),
  email: text("email").notNull(),
  tokenHash: text("token_hash").unique().notNull(),
  expiresAt: timestamp("expires_at").notNull(),
  consumedAt: timestamp("consumed_at"),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

// --- lib/verification.ts ---
import { and, eq, gt, isNull } from "drizzle-orm";
import { db } from "@/lib/db";
import { verificationTokens } from "@/lib/schema";

export type VerificationPurpose = "verify-email" | "password-reset";

const VERIFY_EMAIL_TTL_MS = 24 * 60 * 60 * 1000;
const PASSWORD_RESET_TTL_MS = 30 * 60 * 1000;

// Public origin the emailed links point at — read it from the environment in a
// real app; a constant here keeps this reference free of a config layer.
const APP_ORIGIN = "https://app.example.com";

// Either `db` or the handle `db.transaction()` passes its callback. They are
// distinct types in drizzle, so accept both — sign-up issues a token inside its
// own transaction, while the standalone routes call these helpers on `db`.
type Executor = typeof db | Parameters<Parameters<typeof db.transaction>[0]>[0];

export interface VerificationEmail {
  to: string;
  subject: string;
  link: string;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

// Only this hash is ever written to the database.
export async function hashVerificationToken(token: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(token)
  );
  return toHex(new Uint8Array(digest));
}

// Drops the user's outstanding tokens of this purpose, then mints one 32-byte
// token. Returns the raw token — the caller puts it in the link and nowhere else.
export async function issueVerificationToken(
  tx: Executor,
  purpose: VerificationPurpose,
  userId: string,
  email: string
): Promise<string> {
  const token = toHex(crypto.getRandomValues(new Uint8Array(32)));
  const ttlMs =
    purpose === "verify-email" ? VERIFY_EMAIL_TTL_MS : PASSWORD_RESET_TTL_MS;

  await tx
    .delete(verificationTokens)
    .where(
      and(
        eq(verificationTokens.userId, userId),
        eq(verificationTokens.purpose, purpose)
      )
    );
  await tx.insert(verificationTokens).values({
    id: crypto.randomUUID(),
    userId,
    purpose,
    email,
    tokenHash: await hashVerificationToken(token),
    expiresAt: new Date(Date.now() + ttlMs),
  });

  return token;
}

// Consumes the token with a single conditional write gated on `consumed_at IS
// NULL` — never find-then-update, or two concurrent requests both redeem it.
// The row that comes back is the proof: whose it is, and which address it was
// issued for. Unknown, expired, already-consumed and wrong-`purpose` tokens are
// all the same answer, so callers can only return the one generic error.
export async function consumeVerificationToken(
  tx: Executor,
  purpose: VerificationPurpose,
  tokenHash: string
): Promise<{ userId: string; email: string } | null> {
  const consumed = await tx
    .update(verificationTokens)
    .set({ consumedAt: new Date() })
    .where(
      and(
        eq(verificationTokens.tokenHash, tokenHash),
        eq(verificationTokens.purpose, purpose),
        isNull(verificationTokens.consumedAt),
        gt(verificationTokens.expiresAt, new Date())
      )
    )
    .returning({
      userId: verificationTokens.userId,
      email: verificationTokens.email,
    });

  return consumed.length === 1 ? consumed[0] : null;
}

// This reference ships no mail transport: compose the message here and hand it
// to your provider's SDK (Resend, SES, Postmark, …) at the marked line. The raw
// token travels in this link and nowhere else — never log it, never return it in
// a response. Delivery failures must not propagate: both send endpoints answer
// 200 whether or not the address has an account. The composed message is
// returned so a test can assert on exactly what would go out.
export async function sendVerificationLink(
  purpose: VerificationPurpose,
  email: string,
  token: string
): Promise<VerificationEmail> {
  const path = purpose === "verify-email" ? "/verify-email" : "/reset-password";
  const message: VerificationEmail = {
    to: email,
    subject:
      purpose === "verify-email"
        ? "Confirm your email address"
        : "Reset your password",
    link: `${APP_ORIGIN}${path}?token=${token}`,
  };

  // Send `message` with your provider here.

  return message;
}

// --- app/api/auth/sign-up/route.ts ---
// `db` and `eq` are imported by the lib/verification.ts section above; in a real
// project each file repeats the imports it uses.
import { users, accounts, sessions } from "@/lib/schema";
import { hash } from "bcryptjs";
import { NextResponse } from "next/server";

export async function POST(request: Request) {
  const { email: rawEmail, password, name } = await request.json();
  // Normalize email so lookups and the unique constraint are case-insensitive
  const email = rawEmail?.trim().toLowerCase();

  if (!email || !password || password.length < 8) {
    return NextResponse.json(
      { error: "Invalid email or password (min 8 chars)" },
      { status: 400 }
    );
  }

  // Always hash the password to prevent timing-based email enumeration
  const userId = crypto.randomUUID();
  const sessionToken = crypto.randomUUID();
  const passwordHash = await hash(password, 12);
  const userAgent = request.headers.get("user-agent");
  // x-forwarded-for is only trustworthy behind a proxy you control
  const ipAddress =
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? null;

  let verifyToken = "";

  try {
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
        accountId: userId,
        passwordHash,
      });
      await tx.insert(sessions).values({
        id: crypto.randomUUID(),
        userId,
        token: sessionToken,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
        ipAddress,
        userAgent,
      });
      // Issue the confirmation token alongside the row it proves. Nothing else
      // in a password-only build ever sets emailVerified, and a row that never
      // proves an identifier is reaped.
      verifyToken = await issueVerificationToken(
        tx,
        "verify-email",
        userId,
        email
      );
    });
  } catch (err: unknown) {
    // Unique constraint violation (duplicate email) — return fake success
    // to prevent email enumeration. The dummy token won't resolve to a session.
    if (
      err instanceof Error &&
      (err.message.includes("unique") || err.message.includes("duplicate"))
    ) {
      return NextResponse.json({
        user: { id: crypto.randomUUID(), email, name: name ?? null },
        token: crypto.randomUUID(),
      });
    }
    throw err;
  }

  // Sent after the commit, so a mail failure cannot roll back the new account.
  // The duplicate-email path returns above without reaching this — a fake
  // success has no token to send.
  await sendVerificationLink("verify-email", email, verifyToken);

  return NextResponse.json({
    user: { id: userId, email, name: name ?? null },
    token: sessionToken,
  });
}

// --- app/api/auth/sign-in/route.ts ---
import { compare } from "bcryptjs";

export async function POST(request: Request) {
  const { email: rawEmail, password } = await request.json();
  // Normalize email the same way sign-up does before the lookup
  const email = rawEmail?.trim().toLowerCase();

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
  const userAgent = request.headers.get("user-agent");
  // x-forwarded-for is only trustworthy behind a proxy you control
  const ipAddress =
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? null;
  await db.insert(sessions).values({
    id: crypto.randomUUID(),
    userId: user[0].id,
    token: sessionToken,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    ipAddress,
    userAgent,
  });

  return NextResponse.json({
    user: { id: user[0].id, email: user[0].email, name: user[0].name },
    token: sessionToken,
  });
}

// --- app/api/auth/session/route.ts ---
// A route handler builds a fresh response on every branch, so the header goes on
// whatever comes back rather than being repeated at each return — that way the 401
// carries it too. Without it the browser disk-caches this GET and keeps replaying
// "signed in" with a stale profile after the session has expired server-side.
export async function GET(request: Request) {
  const res = await readSession(request);
  res.headers.set("Cache-Control", "no-store");
  return res;
}

async function readSession(request: Request) {
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

// --- app/api/auth/verify-email/send/route.ts ---
// Sign-up calls issueVerificationToken + sendVerificationLink directly; this
// route exists for resends. Rate limit it per address and per IP (3 per hour is
// reasonable) — it sends mail on demand.
type VerifyEmailSendBody = { email?: string };

export async function POST(request: Request) {
  const { email: rawEmail } = (await request.json()) as VerifyEmailSendBody;
  // Normalize the email the same way sign-up does before the lookup
  const email = rawEmail?.trim().toLowerCase();

  if (!email) {
    return NextResponse.json({ error: "Invalid email" }, { status: 400 });
  }

  const user = await db
    .select()
    .from(users)
    .where(eq(users.email, email))
    .limit(1);

  if (user.length > 0) {
    const token = await issueVerificationToken(
      db,
      "verify-email",
      user[0].id,
      email
    );
    await sendVerificationLink("verify-email", email, token);
  }

  // Same 200 whether or not the address has an account — this endpoint must not
  // reveal which addresses are registered.
  return NextResponse.json({ success: true });
}

// --- app/api/auth/verify-email/confirm/route.ts ---
type VerifyEmailConfirmBody = { token?: string };

export async function POST(request: Request) {
  const { token } = (await request.json()) as VerifyEmailConfirmBody;

  if (!token) {
    return NextResponse.json(
      { error: "Invalid or expired token" },
      { status: 400 }
    );
  }

  const tokenHash = await hashVerificationToken(token);

  const verified = await db.transaction(async (tx) => {
    const proof = await consumeVerificationToken(tx, "verify-email", tokenHash);
    if (!proof) {
      return false;
    }

    // This write records a proof and authorizes nothing, so emailVerified stays
    // out of the guard — two honest confirmations of the same address must not
    // conflict. The address itself is bound: zero rows means the row was
    // re-addressed after the link went out, and the proof says nothing about
    // the address it holds now, so discard it. The token stays consumed either
    // way — the link is spent.
    const proved = await tx
      .update(users)
      .set({ emailVerified: true, updatedAt: new Date() })
      .where(and(eq(users.id, proof.userId), eq(users.email, proof.email)))
      .returning({ id: users.id });

    // No credential strip here: this link was issued by the very sign-up that
    // set the password, so it confirms that password rather than adopting a
    // stranger's — unlike a magic link, which anyone may request for any address.
    return proved.length === 1;
  });

  if (!verified) {
    return NextResponse.json(
      { error: "Invalid or expired token" },
      { status: 400 }
    );
  }

  return NextResponse.json({ success: true });
}

// --- app/api/auth/password-reset/request/route.ts ---
// Same contract as verify-email/send, including the rate limit.
type PasswordResetRequestBody = { email?: string };

export async function POST(request: Request) {
  const { email: rawEmail } = (await request.json()) as PasswordResetRequestBody;
  const email = rawEmail?.trim().toLowerCase();

  if (!email) {
    return NextResponse.json({ error: "Invalid email" }, { status: 400 });
  }

  const user = await db
    .select()
    .from(users)
    .where(eq(users.email, email))
    .limit(1);

  if (user.length > 0) {
    const token = await issueVerificationToken(
      db,
      "password-reset",
      user[0].id,
      email
    );
    await sendVerificationLink("password-reset", email, token);
  }

  return NextResponse.json({ success: true });
}

// --- app/api/auth/password-reset/confirm/route.ts ---
type PasswordResetConfirmBody = { token?: string; password?: string };

export async function POST(request: Request) {
  const { token, password } = (await request.json()) as PasswordResetConfirmBody;

  // Validate the new password before the token is touched — a rejected password
  // must not burn the link, and only failures after the consume are unrecoverable
  if (!token || !password || password.length < 8) {
    return NextResponse.json(
      { error: "Invalid token or password (min 8 chars)" },
      { status: 400 }
    );
  }

  const tokenHash = await hashVerificationToken(token);
  const passwordHash = await hash(password, 12);

  const reset = await db.transaction(async (tx) => {
    const proof = await consumeVerificationToken(
      tx,
      "password-reset",
      tokenHash
    );
    if (!proof) {
      return false;
    }

    // A never-verified row has had no proof of mailbox control until now, so
    // everything it carries predates the proof and is unproven — a planted
    // password, a planted passkey, a planted OAuth link. emailVerified belongs
    // in *this* guard, alongside the address: winning the flip is what
    // authorizes the strip, and it serializes concurrent proofs to one stripper.
    const claimed = await tx
      .update(users)
      .set({ emailVerified: true, updatedAt: new Date() })
      .where(
        and(
          eq(users.id, proof.userId),
          eq(users.email, proof.email),
          eq(users.emailVerified, false)
        )
      )
      .returning({ id: users.id });

    let freshCredential = claimed.length === 1;

    if (claimed.length === 1) {
      await tx.delete(accounts).where(eq(accounts.userId, proof.userId));
    } else {
      const user = await tx
        .select()
        .from(users)
        .where(eq(users.id, proof.userId))
        .limit(1);

      // Nothing flipped for one of three reasons, and they are not the same
      // outcome: the row is gone, or it now holds a different address — the
      // proof is not about it, so mint nothing — or it was already verified,
      // in which case its credentials belong to the owner who proved it and
      // the password is replaced in place.
      if (user.length === 0 || user[0].email !== proof.email) {
        return false;
      }

      const updated = await tx
        .update(accounts)
        .set({ passwordHash, updatedAt: new Date() })
        .where(
          and(
            eq(accounts.providerId, "credential"),
            eq(accounts.accountId, proof.userId)
          )
        )
        .returning({ id: accounts.id });

      // A verified row that never held a credential (OAuth-only) gets one now.
      freshCredential = updated.length === 0;
    }

    if (freshCredential) {
      await tx.insert(accounts).values({
        id: crypto.randomUUID(),
        userId: proof.userId,
        providerId: "credential",
        accountId: proof.userId,
        passwordHash,
      });
    }

    // A reset is the remedy for a compromised account, so the attacker's session
    // must not survive it. Mint none — require a fresh sign-in.
    await tx.delete(sessions).where(eq(sessions.userId, proof.userId));

    return true;
  });

  if (!reset) {
    return NextResponse.json(
      { error: "Invalid or expired token" },
      { status: 400 }
    );
  }

  return NextResponse.json({ success: true });
}
