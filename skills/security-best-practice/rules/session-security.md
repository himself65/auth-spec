---
title: Session Security
impact: HIGH
tags: token, cookie, session-fixation, expiry, httponly, host-prefix, partitioned, rotation, revocation
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
| Session invalidation on sign-out | Delete the session row / add the token to a revocation list. Also clear the cookie (`Max-Age=0`) and return `Clear-Site-Data: "cookies", "storage"`. If the app mints longer-lived credentials off the back of a session — OAuth access tokens issued to an integration at `/authorize`, for example — record the issuing session's id on them and check that session is still alive when the credential is verified, not only at sign-out. A sign-out that deletes the session row and stops there leaves those tokens introspecting as active until their own TTL, so "sign out everywhere" silently excludes them. Credentials deliberately issued for unattended use (API keys, CI tokens) are the exception — they are *meant* to outlive the session; gate their creation on freshness instead (see the sudo-mode row). |
| Session fixation | Sign-in must **issue a new session ID** and invalidate any pre-auth session. Same for privilege changes (step-up, role change, impersonation end). |
| Session invalidation on password change | Changing password, email, or MFA factor must revoke all other active sessions except the current one. Offer a "sign out of all other devices" affordance. |
| Session invalidation on account termination | Deleting, banning, disabling, or deactivating a user must revoke **all** of that user's sessions in the same operation — including the current one, unlike the row above — and must clear every store the session validator reads, not just the one the delete statement happened to target. A session is a bearer credential that outlives the account row: flipping a `banned` / `deletedAt` flag that `GET /session` never joins against leaves the old cookie authenticating until it expires, and a cached copy survives a delete aimed only at the database. Route every multi-session revocation — sign-out-everywhere, password/email/MFA change, reset, delete, ban, admin force-logout — through the one `revokeAllSessions(userId, { except })` helper instead of inlining the delete at each call site; a per-call-site delete is how one path gets missed. The exception is in the signature because the row above needs it: account termination (delete/ban/disable) and admin force-logout pass no `except`; password/email/MFA change and sign-out-everywhere pass the current session id. |
| Session freshness (sudo mode) | Record when the session last authenticated and require *recent* authentication (e.g. ≤ 15 min, else re-prompt for password/MFA) before sensitive operations: password/email change, MFA enroll/remove, revoking other sessions, account unlink/delete, API-key creation. Without this, any stolen long-lived cookie can silently rotate the account's credentials into the attacker's hands. Enforce the freshness check server-side on every sensitive endpoint — including the read/list endpoints that gate those flows — not just in the UI. |
| Refresh token rotation | If using refresh tokens, rotate on every use and detect **reuse** — if an old refresh token is replayed, revoke the entire family (indicates theft). |
| JWT-specific checks | `alg` must be validated on the server — never trust the header. Disable `alg: none`. Prefer EdDSA or RS256/ES256 over HS256 for asymmetric use cases. Validate `iss`, `aud`, `exp`, `nbf`, `iat`. |
| JWT ≠ revocation | JWTs are immutable until `exp`. If you need instant revocation (logout, compromise), keep a server-side allow/deny list or use short-lived access tokens (≤ 15 min) + refresh tokens. |
| Cached session snapshots | Caching a session to skip the store read — signed cookie payload, Redis/KV mirror, in-process map — buys a revocation lag equal to the cache TTL: a session signed out, a user banned, or a role demoted keeps passing every check that reads the snapshot until it expires. The trap is the *hybrid* deployment, where a durable store exists so the app believes revocation is instant. Make the store read the **default** and the cached read an explicit opt-in, so a newly added endpoint is safe by omission — only low-consequence reads may opt in. Anything that changes state, elevates privilege, touches credentials, or is an administrative action (admin/impersonation gates, permission checks, account deletion, API-key management) must re-read the durable store. Verify the snapshot's embedded expiry, not just its signature — a well-signed expired snapshot must not read as live. Drop the cached entry in the same operation that revokes a session, changes a password, bans a user, or changes a role. |
| JWT signing keys (JWKS ops) | If you issue JWTs: put a `kid` in every token header and publish verification keys at a JWKS endpoint; rotate signing keys periodically, keeping retired public keys published until the last token they signed has expired; store private keys encrypted at rest (KMS / sealed secret), never in the repo or plain env dumps. Provision the keypair out of band — a migration, a startup step, or an explicit rotation command — so the request path only ever reads it: minting on first use puts key generation inside a user-facing request and lets concurrent cold starts each create their own key. When *verifying* tokens from multiple issuers, cache JWKS per issuer with a TTL — a shared cache cross-contaminates keys between issuers. |
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
