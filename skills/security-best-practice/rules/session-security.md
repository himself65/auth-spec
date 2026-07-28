---
title: Session Security
impact: HIGH
tags: token, cookie, session-fixation, expiry, httponly, host-prefix, partitioned, rotation
---

## Session Security

**Impact: HIGH**

Session tokens are bearer credentials — if an attacker obtains one, they have full access to the account. Weak generation, missing cookie flags, or improper lifecycle management are common attack vectors.

### Checklist

| Check | Requirement |
|-------|------------|
| Token generation | Cryptographically secure RNG (`crypto.randomBytes(32)`, `secrets.token_hex(32)`, `crypto/rand`). Never `Math.random()` / `rand()` / `uuid v1/v4` alone if the value is used as a long-lived secret (v4 is acceptable; v1 leaks MAC + time). |
| Token length | ≥ 128 bits of entropy (32 hex chars / 16 random bytes). Prefer 256 bits (64 hex / 32 bytes). |
| Stored form | Store a **hash** of the session token server-side (SHA-256 is fine — tokens are already high-entropy). An attacker with a DB dump should not be able to reuse tokens. |
| Session expiry (absolute) | Hard max lifetime: 7–30 days for general apps, ≤ 12–24 h for sensitive apps. Enforce server-side — a JWT whose `exp` has passed must be rejected even if the cookie is presented. |
| Idle timeout | Expire after inactivity (e.g. 30 min for banking, 24 h for general). Sliding window is OK but capped by the absolute expiry. |
| Cookie flags | `HttpOnly` (always). `Secure` (always in prod, including localhost over HTTPS). `SameSite=Lax` minimum, `Strict` for privileged session cookies. Explicit `Path=/` and, if cross-subdomain is not needed, **no** `Domain` attribute. |
| Cookie prefixes (`__Host-` / `__Secure-`) | Use `__Host-session` for the session cookie. Enforces `Secure`, `Path=/`, and no `Domain` — blocks subdomain cookie-injection attacks. If the cookie must span subdomains (`Domain=.example.com` for app + api), `__Host-` is impossible because it forbids `Domain` — fall back to `__Secure-session` (still enforces `Secure`) and accept the subdomain-injection tradeoff consciously. Either way, read **only** the exact cookie name you set — never fall back to an unprefixed variant, or a stale/attacker-injected `session` cookie can shadow the real prefixed one. |
| `Partitioned` attribute (CHIPS) | Set `Partitioned` on cookies used in third-party / embedded contexts. Chrome now isolates cross-site cookies by default; without `Partitioned` the cookie is dropped in iframes. |
| Session invalidation on sign-out | Delete the session row / add the token to a revocation list. Also clear the cookie (`Max-Age=0`) and return `Clear-Site-Data: "cookies", "storage"`. |
| Session fixation | Sign-in must **issue a new session ID** and invalidate any pre-auth session. Same for privilege changes (step-up, role change, impersonation end). |
| Session invalidation on password change | Changing password, email, or MFA factor must revoke all other active sessions except the current one. Offer a "sign out of all other devices" affordance. |
| Session freshness (sudo mode) | Record when the session last authenticated and require *recent* authentication (e.g. ≤ 15 min, else re-prompt for password/MFA) before sensitive operations: password/email change, MFA enroll/remove, revoking other sessions, account unlink/delete, API-key creation. Without this, any stolen long-lived cookie can silently rotate the account's credentials into the attacker's hands. Enforce the freshness check server-side on every sensitive endpoint — including the read/list endpoints that gate those flows — not just in the UI. |
| Refresh token rotation | If using refresh tokens, rotate on every use and detect **reuse** — if an old refresh token is replayed, revoke the entire family (indicates theft). |
| JWT-specific checks | `alg` must be validated on the server — never trust the header. Disable `alg: none`. Prefer EdDSA or RS256/ES256 over HS256 for asymmetric use cases. Validate `iss`, `aud`, `exp`, `nbf`, `iat`. |
| JWT ≠ revocation | JWTs are immutable until `exp`. If you need instant revocation (logout, compromise), keep a server-side allow/deny list or use short-lived access tokens (≤ 15 min) + refresh tokens. |
| JWT signing keys (JWKS ops) | If you issue JWTs: put a `kid` in every token header and publish verification keys at a JWKS endpoint; rotate signing keys periodically, keeping retired public keys published until the last token they signed has expired; store private keys encrypted at rest (KMS / sealed secret), never in the repo or plain env dumps. When *verifying* tokens from multiple issuers, cache JWKS per issuer with a TTL — a shared cache cross-contaminates keys between issuers. |
| Token storage (client) | Prefer `HttpOnly` cookies. If SPA + Authorization header is required, keep access tokens in memory only (not `localStorage`/`sessionStorage` — XSS readable). Use a silent refresh via HttpOnly cookie. |
| Concurrent session limit | Consider capping active sessions per user. Surface a "signed-in devices" UI so users can revoke individually — capture `ipAddress` and `userAgent` (nullable columns) at session creation to power it. |
| Device/IP binding (optional) | For high-sensitivity apps, bind the session to a coarse device fingerprint or ASN. Don't bind to exact IP — mobile users' IPs change mid-session. |

### Incorrect

```typescript
// BAD: predictable token
const token = Date.now().toString(36) + Math.random().toString(36);
```

```typescript
// BAD: cookie missing security flags, no prefix, stored raw
res.setHeader('Set-Cookie', `session=${token}`);
await db.session.create({ data: { token, userId } }); // raw token in DB
```

```typescript
// BAD: JWT with no revocation path and no alg check
const payload = jwt.decode(req.headers.authorization.slice(7)); // no verify!
```

### Correct

```typescript
// GOOD: crypto-random token, hashed before storage
import crypto from 'crypto';
const token = crypto.randomBytes(32).toString('hex');
const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
await db.session.create({ data: { tokenHash, userId, expiresAt } });

res.setHeader('Set-Cookie',
  `__Host-session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${7 * 24 * 60 * 60}`
);
```

```typescript
// GOOD: JWT verified with explicit algorithm allow-list
const decoded = jwt.verify(token, publicKey, {
  algorithms: ['EdDSA'], // explicit — prevents alg confusion
  issuer: 'https://auth.example.com',
  audience: 'api.example.com',
});
```

```typescript
// GOOD: session fixation prevention — new ID on sign-in
async function signIn(email, password) {
  const user = await verifyPassword(email, password);
  await invalidateCurrentSession(req);          // kill pre-auth session
  const newToken = crypto.randomBytes(32).toString('hex');
  await createSession(user.id, hash(newToken));
  return newToken;
}

// GOOD: revoke siblings on password change
async function changePassword(userId, newPassword, currentSessionId) {
  await updatePasswordHash(userId, newPassword);
  await db.session.deleteMany({
    where: { userId, id: { not: currentSessionId } },
  });
}
```

### References

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [MDN — Cookie prefixes (`__Host-`, `__Secure-`)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Cookies#cookie_prefixes)
- [CHIPS — Cookies Having Independent Partitioned State](https://developers.google.com/privacy-sandbox/cookies/chips)
- [OAuth 2.0 Refresh Token Rotation — RFC 6749 §10.4 + OAuth 2.0 Security BCP §4.14](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [RFC 8725 — JSON Web Token Best Current Practices](https://datatracker.ietf.org/doc/html/rfc8725)
