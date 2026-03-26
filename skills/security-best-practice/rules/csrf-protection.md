---
title: CSRF Protection
impact: MEDIUM
tags: csrf, same-site, double-submit, cookie, origin
---

## CSRF Protection

**Impact: MEDIUM**

If the app uses cookie-based authentication, cross-site request forgery allows attackers to perform actions as the logged-in user by tricking their browser into sending authenticated requests.

### Checklist

| Check | Requirement |
|-------|------------|
| Cookie-based auth | If using cookies for auth, CSRF protection is required. |
| SameSite cookies | `SameSite=Lax` (minimum) or `Strict` on session cookies. |
| CSRF token | For state-changing operations with cookie auth, verify a CSRF token (double-submit cookie or synchronizer token pattern). |
| Token-based auth | If using Authorization header (Bearer tokens) only, CSRF protection is not needed (browser does not auto-attach Authorization headers). |
| Origin/Referer check | As defense-in-depth, validate `Origin` or `Referer` header on state-changing requests. |

### Incorrect

```typescript
// BAD: no CSRF protection on state-changing endpoint with cookie auth
app.post('/api/change-email', (req, res) => {
  const session = getSessionFromCookie(req);
  // ... changes email without verifying CSRF token
});
```

### Correct

```typescript
// GOOD: double-submit CSRF protection
function csrfProtection(req, res, next) {
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
    const cookieToken = req.cookies['csrf-token'];
    const headerToken = req.headers['x-csrf-token'];
    if (!cookieToken || !headerToken || cookieToken !== headerToken) {
      return res.status(403).json({ error: 'CSRF token mismatch' });
    }
  }
  next();
}
```

### References

- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
