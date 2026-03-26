---
title: HTTP Security Headers
impact: LOW
tags: hsts, csp, x-frame-options, referrer-policy, permissions-policy, cache-control
---

## HTTP Security Headers

**Impact: LOW**

Security headers are a defense-in-depth layer. They don't prevent auth bugs directly, but they limit the damage of XSS, clickjacking, and protocol downgrade attacks.

### Checklist

| Check | Requirement |
|-------|------------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` — enforces HTTPS. |
| `Content-Security-Policy` | At minimum: `default-src 'self'` — prevents XSS via inline scripts and external resources. Tune to the app's needs. |
| `X-Content-Type-Options` | `nosniff` — prevents MIME-type sniffing. |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` — prevents clickjacking. |
| `Referrer-Policy` | `strict-origin-when-cross-origin` or `no-referrer` — prevents leaking URLs with tokens. |
| `Permissions-Policy` | Restrict unnecessary browser features (camera, microphone, geolocation) if not used. |
| `Cache-Control` on auth responses | Auth endpoints should return `Cache-Control: no-store` to prevent caching sensitive data. |

### Correct

```typescript
// Middleware to set security headers
function securityHeaders(req, res, next) {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
}
```

### Notes

Be conservative with CSP. A too-strict `Content-Security-Policy` can break the application. Start with `default-src 'self'` and add exceptions based on what the app actually loads.

### References

- [MDN HTTP Security Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#security)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
