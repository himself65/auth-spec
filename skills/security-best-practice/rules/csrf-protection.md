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
| Origin/Referer (defense-in-depth) | On every unsafe-method request, require `Origin` (or `Referer` fallback) to equal an allow-list of your own origins. Reject with 403 otherwise. If an entry is a native-app custom scheme (`myapp://`, `exp://`), `new URL(x).origin` yields the string `"null"` — compare the scheme and the authority you parsed yourself, host matched exactly, never `startsWith`: a configured `myapp://callback` matched by prefix also accepts `myapp://callback.attacker.tld`. A host-less entry (`myapp://`) may deliberately mean "any host of this scheme"; a host-bearing one must be exact. |
| `Origin: null` has two unrelated sources | `null` is what a **foreign opaque origin** sends — a sandboxed iframe, a `data:`/`blob:` document — and it is *also* what **your own page** sends when it is served `Referrer-Policy: no-referrer` and the user submits an HTML form on it: per Fetch ("Append a request `Origin` header"), the initiating document's referrer policy serializes the Origin of a non-CORS non-`GET` request as `null`. Auth pages are precisely where `no-referrer` is recommended (`http-security-headers.md`), so this collides with your own hardening. Consequences: `null` is unattributable on its own and must **never** be allow-listed — but rejecting it *unconditionally* 403s every form navigation from your own hardened pages (consent screens, password-reset forms). Decide it with Fetch Metadata, never with the Origin value: `same-origin` accepts, everything else rejects. `fetch()` is unaffected (mode `"cors"` always carries a real Origin), so this only ever breaks the plain-HTML-form path — the progressive-enhancement one, which has no client-side JS to debug it with. |
| The origin must come from the request | The value the check reads must be the `Origin` the browser stamped — never one copied out of another request header (`X-Forwarded-Host`, a custom `app-origin`/`client-origin`). A header that overrides the origin "so the native app works" is an unauthenticated bypass of every check downstream of it: the attacker just sets it. Same rule as `X-Forwarded-For` for client IP — only a value your own proxy stamped is trustworthy. |
| `Sec-Fetch-Site` / Fetch Metadata | Modern browsers send `Sec-Fetch-Site`, and `Sec-Fetch-*` are forbidden header names — no page can set them, so the value is the browser's own verdict rather than a claim by the caller. Reject state-changing requests when it is `cross-site`, unless the route is a whitelisted webhook. **`same-origin` must be an accept**, short-circuiting *before* the Origin comparison: it already means the initiator's origin **is** this request's origin, which is the entire question an Origin allow-list is asking. A gate that only knows how to reject `cross-site` falls through to an Origin check that a genuine same-origin request cannot always pass — see the next row. `same-site` is **not** `same-origin`: a sibling subdomain still faces the allow-list. |
| Pre-session endpoints (no cookie yet) | Sign-up, sign-in, password-reset request, and OTP/magic-link send run before any session cookie exists — apply the Origin/Fetch-Metadata checks there anyway (login CSRF is real). When `Origin` and `Referer` are both absent, fall back to `Sec-Fetch-Site`: reject `cross-site` even when `Sec-Fetch-Mode` is `navigate` — a cross-site top-level form POST is exactly login CSRF. Requests with none of these headers (curl, native apps, very old browsers) pass the header gate — require `Content-Type: application/json` as the final backstop so plain HTML forms can't reach the handler at all. |
| CORS ≠ CSRF protection | A permissive CORS config (`Access-Control-Allow-Origin: *` with credentials, or reflecting `Origin`) **enables** CSRF. Never reflect origin for authenticated endpoints; use an explicit allow-list. |
| Authorization header auth | Bearer tokens in `Authorization` header are **not** auto-attached by the browser, so CSRF is not required — but ensure no cookie-based fallback exists on the same endpoint. |
| Login CSRF | The login endpoint also needs CSRF protection (otherwise an attacker can log the victim into the attacker's account to harvest behavior). Use a pre-session cookie + token. |
| Logout CSRF | Rate-limit or CSRF-protect logout so an attacker can't force-logout users en masse. A `GET /logout` link never acts — it renders an interstitial "sign out?" whose form POST carries the CSRF token (a token on the GET link itself would violate the two rows below). The one navigation-reachable logout that may act on GET is an OIDC `end_session` endpoint (RP-Initiated Logout 1.0 requires GET and POST), and only on a verified `id_token_hint` — issuer, audience, signature checked; expiry ignored per spec — that belongs to the browser's current session (`sub`, and `sid` when present); with no hint, or a hint for a *different* session than the browser holds, the spec **requires** the confirmation page, and even with a matching hint it still SHOULD-asks — acting without a prompt on a matching hint is upstream's permitted choice, not the default. Any post-logout redirect target is exact-allow-listed per client, and a caller-supplied `state` is appended only to a target that passed that check — an unregistered or query-modified `post_logout_redirect_uri` renders the logged-out page and never redirects. |
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

  // 1. Fetch Metadata FIRST — the browser's own verdict, and it settles both
  //    directions. `same-origin` has to be an accept: a page served
  //    `Referrer-Policy: no-referrer` sends `Origin: null` on the form POST it
  //    navigates with, and no allow-list can ever match that.
  const site = req.headers['sec-fetch-site'];
  if (site === 'cross-site') {
    return res.status(403).json({ error: 'Cross-site request blocked' });
  }

  // 2. No same-origin verdict to lean on — fall back to the Origin allow-list.
  //    `new URL('null')` THROWS: uncaught, this is a 500 rather than a 403.
  if (site !== 'same-origin') {
    const source = req.headers.origin || req.headers.referer;
    let origin = null;
    try { origin = source ? new URL(source).origin : null; } catch { /* opaque */ }
    if (!origin || !ALLOWED_ORIGINS.has(origin)) {
      return res.status(403).json({ error: 'Invalid origin' });
    }
  }

  // 3. Double-submit token (constant-time compare)
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
// GOOD: pre-session gate for sign-up / sign-in / reset-request (no cookie to bind a token to)
function preSessionCsrfGate(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();

  const source = req.headers.origin ?? req.headers.referer;
  if (source) {
    let origin;
    try { origin = new URL(source).origin; } catch { return res.status(403).end(); }
    // Rejecting "null" outright is safe HERE, and only here: the JSON backstop
    // at the bottom keeps HTML forms out of this handler entirely, so a
    // `no-referrer` page of your own can never arrive with a nulled Origin. A
    // gate that DOES serve form posts must use the same-origin accept instead.
    if (!ALLOWED_ORIGINS.has(origin)) return res.status(403).end(); // also rejects "null"
  } else if (req.headers['sec-fetch-site'] === 'cross-site') {
    // No Origin/Referer but the browser says cross-site — includes top-level
    // form-POST navigations, which is exactly login CSRF. Reject regardless
    // of Sec-Fetch-Mode.
    return res.status(403).end();
  }

  // Final backstop for clients that send none of the headers: HTML forms can
  // only produce urlencoded/multipart/text-plain, never application/json.
  if (!req.is('application/json')) return res.status(415).end();
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
- [Fetch — Append a request `Origin` header](https://fetch.spec.whatwg.org/#append-a-request-origin-header) (the clause that nulls Origin under `no-referrer`)
- [web.dev — Protect your resources from web attacks with Fetch Metadata](https://web.dev/articles/fetch-metadata)
