---
title: Session Security
impact: HIGH
tags: token, cookie, session-fixation, expiry, httponly
---

## Session Security

**Impact: HIGH**

Session tokens are bearer credentials — if an attacker obtains one, they have full access to the account. Weak generation, missing cookie flags, or improper lifecycle management are common attack vectors.

### Checklist

| Check | Requirement |
|-------|------------|
| Token generation | Must use cryptographically secure random generator (`crypto.randomUUID()`, `secrets.token_hex()`, `crypto/rand`). Never `Math.random()` or `rand()`. |
| Token length | Session tokens must be at least 128 bits of entropy (32 hex chars / 16 bytes minimum). |
| Session expiry | Sessions must have an expiration time (recommended: 7 days for persistent, 24 hours for sensitive apps). |
| Idle timeout | Consider expiring sessions after inactivity (e.g., 30 minutes for banking, optional for general apps). |
| Cookie flags | If using cookies: `HttpOnly` (always), `Secure` (always in production), `SameSite=Lax` or `Strict`, proper `Path` and `Domain`. |
| Session invalidation | Sign-out must delete the session from the server, not just clear the cookie. |
| Session fixation | Sign-in must create a new session, never reuse a pre-authentication session ID. |
| Token storage (client) | Sensitive tokens should be in HttpOnly cookies, not localStorage or sessionStorage (XSS-accessible). |

### Incorrect

```typescript
// BAD: predictable token
const token = Date.now().toString(36) + Math.random().toString(36);
```

```typescript
// BAD: cookie missing security flags
res.setHeader('Set-Cookie', `session=${token}`);
```

### Correct

```typescript
// GOOD: crypto-random token
const token = crypto.randomUUID();
```

```typescript
// GOOD: all security flags set
res.setHeader('Set-Cookie',
  `session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${7 * 24 * 60 * 60}`
);
```

### References

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
