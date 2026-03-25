---
name: auth-review
description: Reviews authentication and authorization code for security issues, best practices, and spec compliance. Use when reviewing auth-related code, checking login flows, token handling, session management, or access control.
---

When reviewing authentication and authorization code, check for:

1. **Credential handling** — passwords hashed with strong algorithms (bcrypt, argon2), no plaintext storage, no logging of secrets
2. **Token security** — proper expiration, secure generation (crypto-random), safe storage (httpOnly cookies, not localStorage for sensitive tokens)
3. **Session management** — session fixation prevention, proper invalidation on logout, idle timeouts
4. **Access control** — authorization checks on every protected endpoint, no reliance on client-side checks alone, principle of least privilege
5. **OAuth/OIDC flows** — state parameter for CSRF protection, PKCE for public clients, proper redirect URI validation
6. **Input validation** — protection against injection in auth queries, rate limiting on login endpoints, account lockout policies
7. **Error handling** — generic error messages (no user enumeration), consistent timing to prevent timing attacks
