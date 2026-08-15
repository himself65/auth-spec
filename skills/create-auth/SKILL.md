---
name: create-auth
description: Scaffold signin and signup authentication endpoints for a project. Use when the user wants to add authentication, create login/register flows, or set up auth from scratch.
---

# Create Auth

You are scaffolding authentication (signin + signup) for the user's project.

## Step 1: Detect Existing Project Context

Before asking any questions, scan the user's project to detect their stack:

1. Look for framework config files (e.g., `next.config.*`, `package.json`, `go.mod`, `Cargo.toml`, `pyproject.toml`, `build.gradle*`, `pom.xml`)
2. Look for existing database/ORM setup (e.g., `prisma/schema.prisma`, `drizzle.config.*`, `alembic/`, `diesel.toml`, `ormconfig.*`)
3. Look for existing auth code or dependencies

Use what you find to pre-select the best options in the questions below. If the project clearly uses a specific stack, set that as the recommended option.

## Step 2: Gather Context with Interactive Questions

Use the `AskUserQuestion` tool to ask the user to make selections. Ask up to 3 questions in a **single** `AskUserQuestion` call so the user can answer everything at once.

### Question 1: Language/Framework

Ask "Which language and framework are you using?" with header "Framework".

Pick the top 4 most relevant options based on what you detected in the project. If you detected the framework, put it first and mark it "(Recommended)". If you could not detect it, use these defaults:

- **Next.js** — "TypeScript, App Router, API routes"
- **Express** — "TypeScript/JavaScript, minimal and flexible"
- **FastAPI** — "Python, async-first with type hints"
- **Go + Chi** — "Go, lightweight and idiomatic"

The user can always pick "Other" to specify a different stack.

### Question 2: Database/ORM

Ask "Which database and ORM/query layer?" with header "Database".

Again, pick the top 4 most relevant options based on the project. If detected, mark it "(Recommended)". Defaults:

- **PostgreSQL + Prisma** — "Type-safe ORM with migrations (JS/TS)"
- **PostgreSQL + Drizzle** — "Lightweight TypeScript ORM, SQL-like syntax"
- **PostgreSQL + SQLAlchemy** — "Full-featured Python ORM"
- **SQLite + raw queries** — "Simple, no server needed, good for prototyping"

### Question 3: Session Strategy

Ask "How should sessions be managed?" with header "Sessions".

- **Database sessions (Recommended)** — "Server-side sessions stored in your database. More secure — sessions can be revoked instantly"
- **JWT tokens** — "Stateless tokens signed by the server. Simpler to scale, but harder to revoke"

## Step 3: Ask Which Features to Add

After the user answers the stack questions, use `AskUserQuestion` again to ask which additional auth features they want. Use **multiSelect: true** so they can pick multiple features at once.

### Question 1: Authentication Methods

Ask "Which authentication methods do you want to add?" with header "Auth methods". Set multiSelect to true.

- **Email OTP** — "Passwordless sign-in via one-time codes sent to email"
- **Magic Link** — "Passwordless sign-in via emailed links"
- **Phone Number** — "SMS-based OTP authentication"
- **Passkey** — "WebAuthn/FIDO2 passwordless authentication"

### Question 2: Security Features

Ask "Which security features do you want?" with header "Security". Set multiSelect to true.

- **Two-Factor Auth (Recommended)** — "TOTP-based second factor with backup codes"
- **Captcha** — "Bot protection on sign-up and sign-in (reCAPTCHA, hCaptcha, Turnstile)"
- **Password Breach Check** — "Check passwords against the Have I Been Pwned database"
- **Rate Limiting** — "Throttle auth endpoints to prevent brute-force attacks (includes KV cache)"

### Question 3: Additional Capabilities

Ask "Any additional capabilities?" with header "Extras". Set multiSelect to true.

- **Multi-Session** — "Allow multiple concurrent sessions per user"
- **Username Auth** — "Sign in with username instead of (or in addition to) email"
- **Organization / Teams** — "Multi-tenant support with roles, invitations, and RBAC"
- **API Keys** — "Generate API keys for programmatic access"
- **MCP Server** — "OAuth 2.1 + discovery endpoints so Model Context Protocol clients (Claude Desktop, mcp-inspector, Cursor) can authenticate. If selected, ask a follow-up: Resource Server only (delegate to an existing IdP) vs Self-hosted Authorization Server (issue your own tokens). See `references/features/mcp-server.md` for the two modes."

## Step 4: Wait for All Answers

**Do not write any code until the user has answered all questions.** Once you have their selections, proceed to Step 5.

## Step 5: Generate Auth

Generate the core auth (schema + endpoints below) **plus** any selected features. For each selected feature, read the matching reference file from `references/features/` to get the schema additions, endpoint specs, and implementation details.

**Dependencies:**

- If the user selects **Rate Limiting**, also read `references/features/kv-cache.md` and generate the KV cache module first — rate limiting depends on it. The KV cache is a general-purpose utility that other features can also use, so generate it as a standalone module.
- If the user selects **MCP Server** in Mode B (Self-hosted Authorization Server), strongly recommend turning on **Rate Limiting** as well — the public `/oauth/register`, `/oauth/authorize`, and `/oauth/token` endpoints need it. Confirm with the user before generating; if they decline, leave a TODO comment at each endpoint pointing at the rate-limiting feature.

| Feature            | Reference file                           |
| ------------------ | ---------------------------------------- |
| Email OTP          | `references/features/email-otp.md`       |
| Magic Link         | `references/features/magic-link.md`      |
| Phone Number       | `references/features/phone-number.md`    |
| Passkey            | `references/features/passkey.md`         |
| Two-Factor Auth    | `references/features/two-factor.md`      |
| Captcha            | `references/features/captcha.md`         |
| Password Breach    | `references/features/password-breach.md` |
| Rate Limiting      | `references/features/rate-limiting.md`   |
| KV Cache           | `references/features/kv-cache.md`        |
| Multi-Session      | `references/features/multi-session.md`   |
| Username Auth      | `references/features/username.md`        |
| Organization/Teams | `references/features/organization.md`    |
| API Keys           | `references/features/api-key.md`         |
| MCP Server         | `references/features/mcp-server.md`      |

### Core Schema and Endpoints

Generate the following core auth using the schema and endpoint specs below.

**Adapt everything to the user's language/framework idioms:**

- Naming: `email_verified` (snake_case) in Python/Go/Rust, `emailVerified` (camelCase) in JS/TS, `EmailVerified` (PascalCase) in C#
- Types: use the language's native types (e.g. `std::string` in C++, `String` in Rust/Java, `string` in Go/TS)
- IDs: use idiomatic generation — `uuid.New()` (Go), `Uuid::new_v4()` (Rust), `crypto.randomUUID()` (JS), `uuid4()` (Python), `boost::uuids::random_generator()` (C++), etc.
- Password hashing: use the idiomatic library — `bcrypt` (Go/JS/Python), `argon2` (Rust), `libsodium` (C/C++), etc.
- Error handling: use the language's conventions (Result types in Rust, error returns in Go, exceptions in Python/Java, etc.)
- File structure: follow the project's existing layout and conventions

### Schema

Create these tables/models:

**User**
| Field | Type | Constraints |
|----------------|----------|----------------------|
| id | string | primary key |
| email | string | unique, not null (store lowercased) |
| name | string | nullable |
| image | string | nullable |
| emailVerified | boolean | default false |
| createdAt | datetime | default now |
| updatedAt | datetime | auto-update |

**Session**
| Field | Type | Constraints |
|-----------|----------|--------------------------|
| id | string | primary key |
| userId | string | foreign key -> User, not null |
| token | string | unique, not null |
| expiresAt | datetime | not null |
| ipAddress | string | nullable |
| userAgent | string | nullable |
| createdAt | datetime | default now |

`ipAddress` and `userAgent` power the "signed-in devices" list (see the Multi-Session feature) and security-notification emails.

**Account**
| Field | Type | Constraints |
|--------------|----------|--------------------------|
| id | string | primary key |
| userId | string | foreign key -> User, not null |
| providerId | string | not null (e.g. "credential") |
| accountId | string | not null (provider-side user id; = userId for "credential") |
| passwordHash | string | nullable |
| createdAt | datetime | default now |
| updatedAt | datetime | auto-update |

Add a unique constraint on `(providerId, accountId)`. Account lookups must always filter by that full tuple — never by `accountId` alone — so that OAuth providers added later cannot collide across ID spaces (see `references/pitfalls/oauth-account-linking.md`).

**VerificationToken**
| Field | Type | Constraints |
|------------|----------|--------------------------|
| id | string | primary key |
| userId | string | foreign key -> User, not null |
| purpose | string | not null (`"verify-email"` or `"password-reset"`) |
| email | string | not null (the address the token was issued for, lowercased) |
| tokenHash | string | unique, not null (SHA-256 of the raw token) |
| expiresAt | datetime | not null |
| consumedAt | datetime | nullable (set atomically on use) |
| createdAt | datetime | default now |

One table serves both flows; `purpose` keeps them apart and MUST be matched at redemption, or a reset link is redeemable as an email confirmation. Store only the hash — the raw token exists solely inside the emailed link. `email` records what the token proves, so a later address change cannot inherit the proof.

### Endpoints

**POST /api/auth/sign-up**

- Body: `{ email, password, name? }`
- Normalize the email (trim + lowercase) before validation and any lookup — see `references/pitfalls/email-case-normalization.md`
- Validate email format and password length (min 8 chars)
- Hash password with a strong algorithm (bcrypt, argon2, or scrypt — use whichever is idiomatic for the language)
- Create User + Account (providerId: "credential", accountId: the new user's id) + Session
- Record `ipAddress` and `userAgent` on the session (`User-Agent` header; client IP from the trusted proxy header when deployed behind one, otherwise the socket address)
- **Only when the insert actually created a user**, issue a `"verify-email"` token and send the confirmation link (see `POST /api/auth/verify-email/send`) — nothing else in a password-only build ever sets `emailVerified`, and an account that never proves an identifier is reaped. The duplicate-email path below creates no user, so it sends nothing and leaks nothing
- Return session token and user (without password)
- **Email enumeration protection:** If the email already exists, return the same `200 OK` status and same response shape as a successful sign-up — do not return 409 or any error that reveals the email is taken. The response should be indistinguishable from a real sign-up. Implementation: attempt the insert, catch the unique constraint violation, hash the password anyway (to keep timing consistent), and return a fake success with a dummy user ID and token (that won't actually work as a session). This prevents attackers from discovering which emails are registered via the sign-up endpoint.

**POST /api/auth/sign-in**

- Body: `{ email, password }`
- Normalize the email (trim + lowercase) before lookup
- Look up user by email, verify password hash
- Create new Session (record `ipAddress` and `userAgent` as in sign-up)
- Return session token and user (without password)
- Return 401 on invalid credentials (generic message, no user enumeration)

**GET /api/auth/session**

- Read session token from Authorization header (Bearer) or cookie
- Look up session, verify not expired
- Return user info if valid, 401 if not
- Set `Cache-Control: no-store` once at the top of the handler — not at each `return`, and on the 401 as well as the 200. Otherwise the browser disk-caches this GET and keeps replaying "signed in" with the cached profile after the session has expired server-side.

**POST /api/auth/sign-out**

- Read session token
- Delete session from database
- Return 200

**POST /api/auth/verify-email/send**

- Body: `{ email }` (normalize before lookup). Sign-up calls this internally on success; the route itself exists for resends
- Delete the user's outstanding `"verify-email"` tokens, then issue one: ≥32 bytes crypto-random, store only its SHA-256, `expiresAt` ≤ 24 h
- Email the link. Return 200 **always**, whether or not the address has an account — this endpoint must not reveal which addresses are registered
- Rate limit per address and per IP (3 per hour is reasonable) — it sends mail on demand

**POST /api/auth/verify-email/confirm**

- Body: `{ token }`
- Hash the presented token, look up by `tokenHash`, and require `purpose = "verify-email"`, unexpired and unconsumed
- **Consume atomically** — one conditional write gated on `consumedAt IS NULL`, affected-rows checked (see `references/pitfalls/single-use-token-race.md`)
- Flip `emailVerified` with a conditional write naming the token's `email`: `UPDATE users SET email_verified = true WHERE id = $1 AND email = $2`. Bind the address, and keep the flag itself **out** of this guard — this write records a proof and authorizes nothing destructive (see `references/pitfalls/async-proof-value-binding.md`). Zero rows means the address changed after the link was issued: discard the proof
- **Exempt from the credential strip.** This link was issued by the very sign-up that set the password, so it confirms that password rather than adopting a stranger's — unlike a magic link, which anyone may request for any address (see `references/pitfalls/pre-account-hijack-strip.md`)
- Return 200 (generic error on an invalid, expired, consumed, or wrong-`purpose` token)

**POST /api/auth/password-reset/request**

- Body: `{ email }` (normalize before lookup)
- Same contract as `verify-email/send`: delete outstanding `"password-reset"` tokens, issue one with `expiresAt` ≤ 30 min, return 200 **always**, rate limit per address and per IP

**POST /api/auth/password-reset/confirm**

- Body: `{ token, password }`
- **Validate the new password before touching the token.** A rejected password must not burn the link — only failures that happen after the consume are unrecoverable (see `references/pitfalls/single-use-token-race.md`)
- Hash the presented token, look up by `tokenHash`, require `purpose = "password-reset"`, unexpired and unconsumed, then consume it atomically
- If the row's `emailVerified` is still false, this reset is the first proof of mailbox control it has ever had: claim and strip it in the same transaction (see `references/pitfalls/pre-account-hijack-strip.md`) — everything on a never-verified row is unproven, including a planted passkey. Then write the new password into a freshly created credential Account, since the strip deleted the old one
- Otherwise update the existing credential Account's `passwordHash` in place
- **Revoke every session for that user** — a reset is the remedy for a compromised account, so the attacker's session must not survive it. Do not mint a new one; require a fresh sign-in
- Return 200

### Implementation Rules

- **Write all auth code by hand.** Do NOT use auth libraries (better-auth, next-auth, Auth.js, lucia, passport, etc.). The only external dependencies allowed are: the web framework itself, the database/ORM layer, and a password hashing library (bcrypt, argon2, scrypt). Everything else — session management, token generation, route handlers — must be written directly. Keep it minimal.
- Use crypto-random IDs for all primary keys and session tokens — use the idiomatic method for the language (`crypto.randomUUID()`, `uuid.New()`, `Uuid::new_v4()`, `secrets.token_hex()`, etc.)
- Hash passwords with a strong algorithm — use what's standard for the ecosystem (bcrypt, argon2, scrypt, libsodium, etc.)
- Never log or expose password hashes
- Use constant-time comparison for password verification (the hashing library handles this)
- Set session expiry to 7 days by default
- Return generic "Invalid credentials" on sign-in failure — do not reveal whether the email exists
- **Normalize emails at the boundary**: trim + lowercase every email arriving in any request (core endpoints and feature endpoints alike) before validation, lookup, or insert, and store only the normalized form. Never compensate at query time with `LOWER()`/`ILIKE`
- **Never synthesize a routable email**: if a sign-up path has no email (Phone Number), prefer making the `email` column nullable. If it must stay non-null, mint the placeholder under the RFC 6761 reserved `.invalid` TLD, namespaced by source — `<stable-identifier>@<source>.placeholder.invalid` — never a domain anyone can receive mail at. A placeholder is never itself a proven identifier: leave `emailVerified` false permanently, never send mail to it, and let `phoneVerified` carry that account's proof. **A row is _phone-only_ — the qualifier the reaper and the enrolment gate below both hinge on — exactly when its `email` is NULL or such a `*.placeholder.invalid` placeholder; on a row holding a real address only `emailVerified` counts as proof.** The `create or find User` step in Magic Link and Email OTP must skip placeholder rows — otherwise a magic link requested for a guessed placeholder address signs the attacker in as that user. Trading a placeholder for a real address requires a full verification cycle.
- **Consume single-use tokens atomically**: any single-use credential a feature adds (OTP codes, magic-link/reset tokens, 2FA challenges, invitations) must be consumed with a single conditional write, not find-then-update — see `references/pitfalls/single-use-token-race.md`
- **Reap the rows that never prove an identifier**: `emailVerified` is read as an authorization input (`references/features/organization.md` gates invitation acceptance on it, and the enrolment gate below turns on it), so it is set at exactly one kind of moment — proven control of the mailbox: the core `verify-email/confirm` endpoint, a completed password reset, or a successful magic-link / email-OTP verification. Never set it from an unverified IdP claim. Then, via a scheduled job, delete the accounts that have proven **no** primary identifier at all — no `emailVerified`, and `phoneVerified` rescues a row only when that row is phone-only — on a short TTL (24–72 hours, and never shorter than the verification link's own expiry). A row holding a real, unverified address is reaped even if `phoneVerified` is true, or the job stops clearing exactly what it exists to clear: an unverified row holding an address is a reservation an attacker can make against any address, and it is what makes pre-account hijacking practical.
- **An unverified account may hold nothing but a password**: sign-up mints a session on a user whose `emailVerified` is still false, and that session proves possession of a password, not of the mailbox. Every endpoint that enrolls a durable authenticator — passkey registration, 2FA enable, API-key creation — must additionally require a proven primary identifier: `emailVerified = true`, or `phoneVerified = true` on a phone-only row as defined above. Otherwise whoever plants an account at an address its owner has not yet claimed leaves behind persistence that outlives the password.
- **Route every session-minting path through one sign-up gate**: password sign-up/sign-in, magic-link verify, email/phone OTP verify, and any OAuth or embedded one-tap callback all end with "a session now exists for this identity". They must reach the User row through a single shared function that decides whether this identity may register at all, whether its email domain is permitted, and whether it may attach to an existing User. Each feature's "create or find User" step is a call into that function, never its own reimplementation — otherwise the newest passwordless endpoint becomes a back door around the rules sign-up enforces. Where a per-feature setting overlaps the global one the more restrictive value wins: a feature toggle may tighten policy, never loosen it
- **Prevent email enumeration on sign-up:** When a duplicate email is submitted, return the same status code and response shape as a successful sign-up. Always hash the password (even for duplicates) to prevent timing-based detection. Return a plausible but non-functional fake token and user ID so the response is indistinguishable from a real sign-up.
- Follow the project's existing code style, file structure, and patterns
- If the language has a strong type system (Rust, Go, C++, etc.), define proper types/structs for request/response bodies — do not use untyped maps

## Step 6: Run the Migration

After generating all code, **run the database migration automatically** so the user doesn't hit "table does not exist" errors. Use the project's existing database driver/connection to execute the migration SQL.

For JS/TS projects using `@neondatabase/serverless`, the tagged-template `sql` function cannot run plain SQL strings. Use `sql.query(statement)` instead when executing migration statements programmatically.

## Common Pitfalls

Before generating code, read **all** files in `references/pitfalls/` and follow their rules strictly. These are real bugs encountered in production.

| Pitfall                                 | Reference file                                      |
| --------------------------------------- | --------------------------------------------------- |
| API routes must catch DB errors         | `references/pitfalls/api-error-handling.md`         |
| Sign-up catch must not re-throw         | `references/pitfalls/signup-rethrow.md`             |
| Auth helpers must not throw             | `references/pitfalls/auth-helpers-no-throw.md`      |
| Client must handle non-JSON             | `references/pitfalls/client-json-parsing.md`        |
| OAuth redirect must not use request.url | `references/pitfalls/oauth-redirect-request-url.md` |
| API key hash/gen must not be duplicated | `references/pitfalls/api-key-shared-utils.md`       |
| MCP tokens must be audience-bound       | `references/pitfalls/mcp-token-audience.md`         |
| MCP must not pass tokens upstream       | `references/pitfalls/mcp-token-passthrough.md`      |
| MCP 401 / recoverable 403 need `resource_metadata` | `references/pitfalls/mcp-www-authenticate.md` |
| MCP `.well-known` must mount at root    | `references/pitfalls/mcp-discovery-mounting.md`     |
| Single-use tokens consume atomically    | `references/pitfalls/single-use-token-race.md`      |
| Emails normalize at the boundary        | `references/pitfalls/email-case-normalization.md`   |
| Set-Cookie must survive error paths     | `references/pitfalls/set-cookie-on-error.md`        |
| OAuth links key on provider+account id  | `references/pitfalls/oauth-account-linking.md`      |
| Passwordless sign-in strips credentials | `references/pitfalls/pre-account-hijack-strip.md`   |
| Async proofs bind to the value proven   | `references/pitfalls/async-proof-value-binding.md`  |
| NULL owner must deny, not skip the gate | `references/pitfalls/nullable-owner-gate.md`        |

## Reference Implementations

Full working examples are in the `references/` directory alongside this skill. Use the matching reference as a starting point and adapt to the user's specific setup:

| File                    | Stack                                     |
| ----------------------- | ----------------------------------------- |
| `nextjs-drizzle.ts`     | Next.js App Router + Drizzle + PostgreSQL |
| `express-prisma.ts`     | Express + Prisma + PostgreSQL             |
| `go-chi.go`             | Go + Chi + database/sql + PostgreSQL      |
| `fastapi-sqlalchemy.py` | FastAPI + SQLAlchemy + PostgreSQL         |
| `axum-sqlx.rs`          | Rust + Axum + sqlx + PostgreSQL           |
| `spring-boot.kt`        | Kotlin + Spring Boot + JPA + PostgreSQL   |

If the user's stack doesn't match any reference, use the closest one as a structural guide and adapt idioms accordingly.
