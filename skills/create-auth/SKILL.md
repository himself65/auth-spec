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

## Step 3: Wait for Answers

**Do not write any code until the user has answered all questions.** Once you have their selections, proceed to Step 4.

## Step 4: Generate Auth

Once you have the context, generate the following using the schema and endpoint specs below.

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
- Return 409 if email already exists

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

- Use crypto-random IDs for all primary keys and session tokens — use the idiomatic method for the language
- Hash passwords with a strong algorithm — use what's standard for the ecosystem (bcrypt, argon2, scrypt, libsodium, etc.)
- Never log or expose password hashes
- Use constant-time comparison for password verification (the hashing library handles this)
- Set session expiry to 7 days by default
- Return generic "Invalid credentials" on sign-in failure — do not reveal whether the email exists
- Follow the project's existing code style, file structure, and patterns
- If the language has a strong type system (Rust, Go, C++, etc.), define proper types/structs for request/response bodies — do not use untyped maps

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
