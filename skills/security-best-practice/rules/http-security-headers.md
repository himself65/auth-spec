---
title: HTTP Security Headers
impact: LOW
tags: hsts, csp, coop, coep, corp, x-frame-options, referrer-policy, permissions-policy, cache-control, clear-site-data, trusted-types
---

## HTTP Security Headers

**Impact: LOW (individually) / HIGH (cumulatively)**

Security headers are a defense-in-depth layer. They don't prevent auth bugs directly, but they contain the blast radius of XSS, clickjacking, protocol downgrade, and cross-origin attacks. Auth routes deserve stricter headers than the rest of the site.

### Checklist

| Check | Requirement |
|-------|------------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` once you've verified full HTTPS coverage (preload is hard to reverse). |
| `Content-Security-Policy` | At minimum: `default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'`. Prefer **nonce-** or **hash-** based `script-src` over `'unsafe-inline'`. Use `'strict-dynamic'` for modern apps. |
| `X-Content-Type-Options` | `nosniff` — prevents MIME sniffing. |
| `X-Frame-Options` / `frame-ancestors` | `X-Frame-Options: DENY` for legacy + `frame-ancestors 'none'` in CSP for modern browsers. Use `SAMEORIGIN` only if the app genuinely iframes itself. |
| `Referrer-Policy` | `strict-origin-when-cross-origin` (general) or `no-referrer` (auth pages, reset links) — prevents leaking URLs with tokens. |
| `Permissions-Policy` | Deny features the app doesn't use: `camera=(), microphone=(), geolocation=(), interest-cohort=()`. |
| `Cross-Origin-Opener-Policy` | `same-origin` on authenticated pages — prevents cross-origin window references and enables Spectre-style isolation. Required for some modern APIs. |
| `Cross-Origin-Embedder-Policy` | `require-corp` or `credentialless` — pairs with COOP for full origin isolation. Can break legacy embeds — verify before rolling out. |
| `Cross-Origin-Resource-Policy` | `same-origin` on auth responses — prevents other origins from embedding them via `<img>`/`<script>` for side-channel leaks. |
| `Cache-Control` on auth responses | `no-store` on sign-in, sign-up, token, reset, session, and user-profile responses. Prevents caching tokens or PII in browser/proxy caches. |
| `Clear-Site-Data` on logout | `Clear-Site-Data: "cookies", "storage", "cache"` on the logout response — reliably wipes client state. Omit `"executionContexts"` unless you want to force reload. |
| `Trusted Types` (optional, high security) | `Content-Security-Policy: require-trusted-types-for 'script'; trusted-types default` — eliminates DOM XSS sinks. Requires app code changes. |
| Verbose server headers | Strip `Server`, `X-Powered-By`, framework-version headers — they help attackers fingerprint your stack. |
| HTTPS redirect | Plain HTTP must 301 → HTTPS at the edge. Don't rely on HSTS alone for the first visit. |

### Correct

```typescript
// Middleware to set security headers on every response
function securityHeaders(req, res, next) {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "base-uri 'none'",
      "object-src 'none'",
      "frame-ancestors 'none'",
      "form-action 'self'",
      `script-src 'self' 'nonce-${res.locals.cspNonce}' 'strict-dynamic'`,
      "style-src 'self' 'unsafe-inline'", // tighten later with hashes/nonces
      "img-src 'self' data:",
      "connect-src 'self'",
      "upgrade-insecure-requests",
    ].join('; ')
  );
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), interest-cohort=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  // COEP is stricter — turn on only after auditing embeds
  // res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  res.removeHeader('X-Powered-By');
  next();
}

// On auth endpoints, add:
res.setHeader('Cache-Control', 'no-store');

// On logout:
res.setHeader('Clear-Site-Data', '"cookies", "storage", "cache"');
```

### Notes

- Deploy CSP in **report-only** mode first (`Content-Security-Policy-Report-Only`) and collect violations for 1–2 weeks before enforcing. A too-strict CSP breaks the app.
- Prefer nonce-based CSP over `'unsafe-inline'`. The nonce should be a per-request 128-bit random value.
- HSTS `preload` is a one-way trip — removal from the preload list takes weeks. Only preload once you're sure every subdomain serves HTTPS.

### References

- [MDN HTTP Security Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#security)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [web.dev — Why you need Cross-Origin Isolation](https://web.dev/articles/why-coop-coep)
- [MDN — Clear-Site-Data](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Clear-Site-Data)
- [W3C — Trusted Types](https://w3c.github.io/trusted-types/dist/spec/)
