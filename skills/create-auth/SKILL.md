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
- **Rate Limiting** — "Throttle auth endpoints to prevent brute-force attacks"

### Question 3: Additional Capabilities

Ask "Any additional capabilities?" with header "Extras". Set multiSelect to true.

- **Multi-Session** — "Allow multiple concurrent sessions per user"
- **Username Auth** — "Sign in with username instead of (or in addition to) email"
- **Organization / Teams** — "Multi-tenant support with roles, invitations, and RBAC"
- **API Keys** — "Generate API keys for programmatic access"

## Step 4: Wait for All Answers

**Do not write any code until the user has answered all questions.** Once you have their selections, proceed to Step 5.

## Step 5: Generate Auth

Generate the core auth (schema + endpoints below) **plus** any selected features. For each selected feature, read the matching reference file from `references/features/` to get the schema additions, endpoint specs, and implementation details.

| Feature             | Reference file                          |
|---------------------|-----------------------------------------|
| Email OTP           | `references/features/email-otp.md`      |
| Magic Link          | `references/features/magic-link.md`     |
| Phone Number        | `references/features/phone-number.md`   |
| Passkey             | `references/features/passkey.md`        |
| Two-Factor Auth     | `references/features/two-factor.md`     |
| Captcha             | `references/features/captcha.md`        |
| Password Breach     | `references/features/password-breach.md` |
| Rate Limiting       | `references/features/rate-limiting.md`  |
| Multi-Session       | `references/features/multi-session.md`  |
| Username Auth       | `references/features/username.md`       |
| Organization/Teams  | `references/features/organization.md`   |
| API Keys            | `references/features/api-key.md`        |

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
| Field          | Type     | Constraints          |
|----------------|----------|----------------------|
| id             | string   | primary key          |
| email          | string   | unique, not null     |
| name           | string   | nullable             |
| emailVerified  | boolean  | default false        |
| createdAt      | datetime | default now          |
| updatedAt      | datetime | auto-update          |

**Session**
| Field     | Type     | Constraints              |
|-----------|----------|--------------------------|
| id        | string   | primary key              |
| userId    | string   | foreign key -> User, not null |
| token     | string   | unique, not null         |
| expiresAt | datetime | not null                 |
| createdAt | datetime | default now              |

**Account**
| Field        | Type     | Constraints              |
|--------------|----------|--------------------------|
| id           | string   | primary key              |
| userId       | string   | foreign key -> User, not null |
| providerId   | string   | not null (e.g. "credential") |
| passwordHash | string   | nullable                 |
| createdAt    | datetime | default now              |
| updatedAt    | datetime | auto-update              |

### Endpoints

**POST /api/auth/sign-up**
- Body: `{ email, password, name? }`
- Validate email format and password length (min 8 chars)
- Hash password with a strong algorithm (bcrypt, argon2, or scrypt — use whichever is idiomatic for the language)
- Create User + Account (providerId: "credential") + Session
- Return session token and user (without password)
- **Email enumeration protection:** If the email already exists, return the same `200 OK` status and same response shape as a successful sign-up — do not return 409 or any error that reveals the email is taken. The response should be indistinguishable from a real sign-up. Implementation: attempt the insert, catch the unique constraint violation, hash the password anyway (to keep timing consistent), and return a fake success with a dummy user ID and token (that won't actually work as a session). This prevents attackers from discovering which emails are registered via the sign-up endpoint.

**POST /api/auth/sign-in**
- Body: `{ email, password }`
- Look up user by email, verify password hash
- Create new Session
- Return session token and user (without password)
- Return 401 on invalid credentials (generic message, no user enumeration)

**GET /api/auth/session**
- Read session token from Authorization header (Bearer) or cookie
- Look up session, verify not expired
- Return user info if valid, 401 if not

**POST /api/auth/sign-out**
- Read session token
- Delete session from database
- Return 200

### Implementation Rules

- **Write all auth code by hand.** Do NOT use auth libraries (better-auth, next-auth, Auth.js, lucia, passport, etc.). The only external dependencies allowed are: the web framework itself, the database/ORM layer, and a password hashing library (bcrypt, argon2, scrypt). Everything else — session management, token generation, route handlers — must be written directly. Keep it minimal.
- Use crypto-random IDs for all primary keys and session tokens — use the idiomatic method for the language (`crypto.randomUUID()`, `uuid.New()`, `Uuid::new_v4()`, `secrets.token_hex()`, etc.)
- Hash passwords with a strong algorithm — use what's standard for the ecosystem (bcrypt, argon2, scrypt, libsodium, etc.)
- Never log or expose password hashes
- Use constant-time comparison for password verification (the hashing library handles this)
- Set session expiry to 7 days by default
- Return generic "Invalid credentials" on sign-in failure — do not reveal whether the email exists
- **Prevent email enumeration on sign-up:** When a duplicate email is submitted, return the same status code and response shape as a successful sign-up. Always hash the password (even for duplicates) to prevent timing-based detection. Return a plausible but non-functional fake token and user ID so the response is indistinguishable from a real sign-up.
- Follow the project's existing code style, file structure, and patterns
- If the language has a strong type system (Rust, Go, C++, etc.), define proper types/structs for request/response bodies — do not use untyped maps

## Step 6: Run the Migration

After generating all code, **run the database migration automatically** so the user doesn't hit "table does not exist" errors. Use the project's existing database driver/connection to execute the migration SQL.

For JS/TS projects using `@neondatabase/serverless`, the tagged-template `sql` function cannot run plain SQL strings. Use `sql.query(statement)` instead when executing migration statements programmatically.

## Common Pitfalls

Before generating code, read **all** files in `references/pitfalls/` and follow their rules strictly. These are real bugs encountered in production.

| Pitfall | Reference file |
|---------|---------------|
| API routes must catch DB errors | `references/pitfalls/api-error-handling.md` |
| Sign-up catch must not re-throw | `references/pitfalls/signup-rethrow.md` |
| Auth helpers must not throw | `references/pitfalls/auth-helpers-no-throw.md` |
| Client must handle non-JSON | `references/pitfalls/client-json-parsing.md` |
| OAuth redirect must not use request.url | `references/pitfalls/oauth-redirect-request-url.md` |

## Reference Implementations

Full working examples are in the `references/` directory alongside this skill. Use the matching reference as a starting point and adapt to the user's specific setup:

| File                   | Stack                                    |
|------------------------|------------------------------------------|
| `nextjs-drizzle.ts`    | Next.js App Router + Drizzle + PostgreSQL |
| `express-prisma.ts`    | Express + Prisma + PostgreSQL            |
| `go-chi.go`            | Go + Chi + database/sql + PostgreSQL     |
| `fastapi-sqlalchemy.py`| FastAPI + SQLAlchemy + PostgreSQL         |
| `axum-sqlx.rs`         | Rust + Axum + sqlx + PostgreSQL          |
| `spring-boot.kt`       | Kotlin + Spring Boot + JPA + PostgreSQL  |

If the user's stack doesn't match any reference, use the closest one as a structural guide and adapt idioms accordingly.
