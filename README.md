# auth-spec

A toolkit that helps you **build authentication from scratch**, following the [Agent Skills](https://agentskills.io) open standard.

## Quick Start

### Claude Code — Plugin (recommended)

```bash
npx plugins add himself65/auth-spec
```

### Claude Code — Individual Skills

```bash
npx skills add himself65/auth-spec
```

### Other Agents

```bash
npx skills add himself65/auth-spec -a <agent-name>
```

## What is this?

When you build a web app, users need to sign up, sign in, and sign out. This project provides **Claude Code skills** that can generate auth code for you as a starting point. It works with **any language or framework** — TypeScript, Python, Go, Rust, Kotlin, and more.

## Why build auth from scratch?

This project follows a simple rule: **write your own auth code**. No plug-and-play auth libraries like NextAuth, Passport, or Lucia. You only need three things:

- A **web framework** (Express, Next.js, FastAPI, etc.)
- A **database library** (Prisma, Drizzle, SQLAlchemy, etc.)
- A **password hashing library** (bcrypt, argon2, etc.)

Writing auth yourself helps you understand how it actually works — password hashing, sessions, cookies, and security best practices.

## Available Skills

| Skill | Description | Platform |
|---|---|---|
| [create-auth](skills/create-auth/) | Scaffold sign-up, sign-in, session, and sign-out endpoints with security best practices | All |
| [security-best-practice](skills/security-best-practice/) | Audit and harden your auth code against OWASP top 10 and common security pitfalls | All |

## License

MIT
