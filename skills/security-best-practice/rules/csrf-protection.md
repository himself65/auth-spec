---
title: CSRF Protection
impact: MEDIUM
tags: csrf, same-site, origin, double-submit, synchronizer-token, fetch-metadata
---

## CSRF Protection

**Impact: MEDIUM**

If the app uses cookie-based authentication, CSRF allows attackers to perform actions as the logged-in user by tricking the browser into sending authenticated requests. `SameSite=Lax` alone is **not sufficient** — top-level GETs can still carry cookies, and GET → state change is a common mistake.

### Checklist

| Check | Requirement |
|-------|------------|
| Cookie-based auth | If session is in a cookie, CSRF protection is mandatory on every state-changing request. |
| `SameSite` on session cookies | `SameSite=Lax` minimum; prefer `Strict` for the session cookie itself. Not a substitute for explicit CSRF defense — older browsers and some embedded contexts don't enforce it. |
| Idempotency of GET | `GET`/`HEAD`/`OPTIONS` must never change state. Enforce with routing — not with "we just don't do that". |
| CSRF token (primary defense) | For state-changing requests: synchronizer token or double-submit cookie. Token should be 128+ bits of entropy, bound to the session, and rotated on privilege change. |
| Origin/Referer (defense-in-depth) | On every unsafe-method request, require `Origin` (or `Referer` fallback) to equal an allow-list of your own origins. Reject with 403 otherwise. |
| `Sec-Fetch-Site` / Fetch Metadata | Modern browsers send `Sec-Fetch-Site`. Reject state-changing requests when `Sec-Fetch-Site` is `cross-site` unless the route is a whitelisted webhook. |
| CORS ≠ CSRF protection | A permissive CORS config (`Access-Control-Allow-Origin: *` with credentials, or reflecting `Origin`) **enables** CSRF. Never reflect origin for authenticated endpoints; use an explicit allow-list. |
| Authorization header auth | Bearer tokens in `Authorization` header are **not** auto-attached by the browser, so CSRF is not required — but ensure no cookie-based fallback exists on the same endpoint. |
| Login CSRF | The login endpoint also needs CSRF protection (otherwise an attacker can log the victim into the attacker's account to harvest behavior). Use a pre-session cookie + token. |
| Logout CSRF | Rate-limit or CSRF-protect logout so an attacker can't force-logout users en masse. |
| Token in URL | Never put CSRF tokens (or any session tokens) in query strings or path — they leak to logs, analytics, Referer. |

### Incorrect

```typescript
// BAD: SameSite=Lax alone, no CSRF token, no Origin check
app.post('/api/change-email', (req, res) => {
  const session = getSessionFromCookie(req);
  updateEmail(session.userId, req.body.email);
});
```

```typescript
// BAD: CORS reflecting Origin for credentialed requests — enables CSRF from any site
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  next();
});
```

### Correct

```typescript
// GOOD: layered defense — Origin check + double-submit CSRF token
const ALLOWED_ORIGINS = new Set(['https://app.example.com']);

function csrfProtection(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();

  // 1. Fetch Metadata / Origin allow-list
  const origin = req.headers.origin || req.headers.referer;
  if (!origin || !ALLOWED_ORIGINS.has(new URL(origin).origin)) {
    return res.status(403).json({ error: 'Invalid origin' });
  }
  if (req.headers['sec-fetch-site'] === 'cross-site') {
    return res.status(403).json({ error: 'Cross-site request blocked' });
  }

  // 2. Double-submit token (constant-time compare)
  const cookieToken = req.cookies['__Host-csrf'];
  const headerToken = req.headers['x-csrf-token'];
  if (!cookieToken || !headerToken ||
      !crypto.timingSafeEqual(Buffer.from(cookieToken), Buffer.from(headerToken))) {
    return res.status(403).json({ error: 'CSRF token mismatch' });
  }
  next();
}
```

```typescript
// GOOD: CSRF cookie — __Host- prefix + SameSite=Strict
res.setHeader('Set-Cookie',
  `__Host-csrf=${csrfToken}; HttpOnly=false; Secure; SameSite=Strict; Path=/`
);
// Note: CSRF cookie is intentionally NOT HttpOnly — JS reads it to echo in the X-CSRF-Token header.
```

### References

- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [MDN — Sec-Fetch-Site (Fetch Metadata Request Headers)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Site)
- [web.dev — Protect your resources from web attacks with Fetch Metadata](https://web.dev/articles/fetch-metadata)
