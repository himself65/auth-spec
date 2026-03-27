# auth-spec

A toolkit that helps you **build authentication from scratch** and **test that it works correctly**.

## Installation

### As a Claude Code plugin

Add the marketplace and install the plugin:

```shell
/plugin marketplace add himself65/auth-spec
/plugin install auth@himself65-auth-spec
```

Or test it locally by cloning the repo:

```bash
git clone https://github.com/himself65/auth-spec.git
claude --plugin-dir ./auth-spec
```

After installing, run `/reload-plugins` to activate. Skills are namespaced under `auth:`, e.g. `/auth:create-auth`.

## What is this?

When you build a web app, users need to sign up, sign in, and sign out. This project gives you two things:

1. **A testing tool** that checks if your auth endpoints (sign-up, sign-in, session, sign-out) work correctly by sending real HTTP requests to your server
2. **Claude Code skills** that can generate auth code for you as a starting point

## Why build auth from scratch?

This project follows a simple rule: **write your own auth code**. No plug-and-play auth libraries like NextAuth, Passport, or Lucia. You only need three things:

- A **web framework** (Express, Next.js, FastAPI, etc.)
- A **database library** (Prisma, Drizzle, SQLAlchemy, etc.)
- A **password hashing library** (bcrypt, argon2, etc.)

Writing auth yourself helps you understand how it actually works — password hashing, sessions, cookies, and security best practices.

## Project Structure

```
auth-spec/
├── packages/
│   └── auth-testing-library/        # The testing tool (npm package)
└── skills/
    ├── create-auth/                 # Generates auth code for your project
    └── security-best-practice/      # Audits & hardens your auth security
```

## Getting Started

### Prerequisites

- **Node.js** version 18 or higher (we recommend version 22 — see `.nvmrc`)
- **pnpm** package manager — if you don't have it, install with `npm install -g pnpm`

### Setup

```bash
# 1. Clone the repo
git clone <repo-url>
cd auth-spec

# 2. Install dependencies
pnpm install

# 3. Build everything
pnpm run build
```

### Using the Testing Tool

The testing library sends HTTP requests to your auth server and checks the responses. Point it at your running server to validate your auth endpoints:

```bash
# Run all tests against your server
npx auth-testing-library --base-url http://localhost:3000
```

## Available Commands

| Command | What it does |
|---|---|
| `pnpm run build` | Compiles all the code |
| `pnpm run test` | Runs the test suite |
| `pnpm run lint` | Checks for code errors |

## License

MIT
