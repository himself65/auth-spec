---
name: security-best-practice
description: Audit and harden authentication code for security best practices. Use when the user wants to check their auth implementation for vulnerabilities, harden session handling, fix credential storage, or apply OWASP-recommended security patterns.
---

# Security Best Practice

You are auditing and hardening authentication code for security best practices.

## Rules

Individual security rules are in the `rules/` directory, organized by impact priority. Read `rules/_sections.md` for the full taxonomy, and read individual rule files for checklists and fix patterns.

**Critical Impact:**
- `rules/credential-storage.md` — Password hashing, secret management, key handling
- `rules/error-handling.md` — User enumeration, timing attacks, stack trace leaks

**High Impact:**
- `rules/session-security.md` — Token generation, cookie flags, session lifecycle
- `rules/input-validation.md` — SQL injection, XSS, header injection, body validation

**Medium Impact:**
- `rules/rate-limiting.md` — Login throttling, account lockout, CAPTCHA triggers
- `rules/csrf-protection.md` — CSRF prevention for cookie-based auth

**Lower Priority:**
- `rules/http-security-headers.md` — HSTS, CSP, X-Frame-Options, Referrer-Policy

## Step 1: Detect Project Context

Before starting, scan the user's project to understand their stack:

1. Look for framework config files (`next.config.*`, `package.json`, `go.mod`, `Cargo.toml`, `pyproject.toml`, `build.gradle*`, `pom.xml`)
2. Look for existing auth code — route handlers for sign-up, sign-in, session, sign-out
3. Look for database/ORM setup and session storage
4. Look for existing security measures (rate limiting, CSRF tokens, CSP headers)

## Step 2: Choose Audit Scope

Use the `AskUserQuestion` tool to ask the user what they want to harden. Use **multiSelect: true** so they can pick multiple areas at once.

Ask "Which security areas do you want to audit and harden?" with header "Security audit scope".

- **Credential storage** — "Password hashing, secret management, key rotation"
- **Session security** — "Token generation, expiry, cookie flags, session fixation"
- **Input validation** — "SQL injection, XSS, header injection, request body validation"
- **Rate limiting & brute-force protection** — "Login throttling, account lockout, CAPTCHA triggers"
- **HTTP security headers** — "CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy"
- **CSRF protection** — "Cross-site request forgery prevention for cookie-based auth"
- **Error handling & information leakage** — "Generic errors, no stack traces, no user enumeration"
- **Full audit (all of the above)** — "Comprehensive security review"

## Step 3: Run the Audit

For each selected area, read the corresponding rule file from `rules/` and review the user's code against its checklist. Report findings as:

- **PASS** — implementation is correct
- **FAIL** — vulnerability or misconfiguration found (include file path, line number, and fix)
- **MISSING** — security control is absent (include where to add it and sample code)

After the audit, apply fixes directly to the code. For each fix, explain what was wrong and why the fix is necessary.

## Step 4: Generate Report

After applying fixes, produce a summary table:

| Area | Status | Issues Found | Fixed |
|------|--------|-------------|-------|
| Credential storage | PASS/FAIL | description | Yes/No |
| Session security | PASS/FAIL | description | Yes/No |
| ... | ... | ... | ... |

For any issues that cannot be auto-fixed (e.g., require infrastructure changes like adding Redis for rate limiting), list them as **manual action items** with clear instructions.

## Step 5: Verify Fixes

After applying fixes:
1. If the project has tests, run them to ensure nothing broke
2. If the project has a linter, run it to verify code style
3. If the project has a build step, run it to check for compilation errors

## Implementation Rules

- **Never weaken existing security.** If the code already uses argon2, do not downgrade to bcrypt. If cookies already have `SameSite=Strict`, do not change to `Lax`.
- **Follow the project's existing patterns.** If they use middleware for other concerns, add security middleware the same way. Match naming conventions, file structure, and error handling style.
- **Do not add dependencies without asking.** If a fix requires a new library (e.g., `helmet` for Express, `csurf` for CSRF), ask the user before adding it.
- **Adapt to the language/framework idioms.** Use the canonical approach for each ecosystem (e.g., `helmet` middleware in Express, `SecurityFilterChain` in Spring Boot, middleware in Go/Chi).
- **Be conservative with CSP.** A too-strict Content-Security-Policy can break the application. Start with `default-src 'self'` and add exceptions based on what the app actually loads.
- **Respect the auth-spec project rules.** All auth code must be hand-written — no auth libraries (better-auth, next-auth, Auth.js, lucia, passport, etc.). Only allowed deps: web framework, ORM, password hashing lib, and security-header/CSRF utility libs.

## Sources

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/)
- [NIST SP 800-63B — Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [MDN HTTP Security Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#security)
