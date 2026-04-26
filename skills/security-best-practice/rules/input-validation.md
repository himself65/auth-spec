---
title: Input Validation
impact: HIGH
tags: sql-injection, xss, header-injection, path-traversal, ssrf, open-redirect, validation
---

## Input Validation

**Impact: HIGH**

Unvalidated input is the root cause of SQL injection, XSS, header injection, SSRF, and open redirect — all of which can lead to account takeover or full system compromise. Validate **at the boundary**, with an explicit schema, allow-list where possible.

### Checklist

| Check | Requirement |
|-------|------------|
| SQL injection | All queries use parameterized queries or ORM methods. No string concatenation with user input, including `ORDER BY`, `LIMIT`, or table/column names — use allow-lists for those. |
| NoSQL injection | For Mongo et al., reject operator keys (`$gt`, `$ne`, `$where`, `$regex`) in user-supplied objects. Cast types (string email should not become a `{$ne: null}` query). |
| Schema validation | Parse every request body through a schema library (Zod / Valibot / Pydantic / validator / Joi). Reject unknown fields (`.strict()` / `extra=forbid`). |
| Email validation | Validate format, normalize (lowercase, strip + aliases if your policy says so), reject control chars and CRLF. Treat Unicode confusables carefully for display. |
| Email / header CRLF | Never pass user input directly into email headers (`To`, `Subject`, `From`) or HTTP response headers. CRLF injection splits headers and can cause email spoofing or HTTP response splitting. |
| XSS — output encoding | Encode on output, not input. Use the framework's auto-escaping (React JSX, Jinja2 autoescape, Go `html/template`). Never set `dangerouslySetInnerHTML` / `innerHTML` with user input. |
| XSS — sanitize rich content | If you accept HTML (rich editor), run it through DOMPurify / bleach / sanitize-html on the server with an allow-list. Don't trust client-side sanitization. |
| XSS — CSP fallback | Even with perfect escaping, ship a nonce-based CSP (`script-src 'self' 'nonce-...'`). See `http-security-headers.md`. |
| Open redirect | **Every redirect target must be validated against an allow-list** (either a fixed list of paths, or your own origin). Common attack surfaces: `?redirect=`, `?next=`, OAuth `callbackUrl`, post-signin return URLs. Reject `//evil.com`, `\evil.com`, `javascript:`, `data:`, and URLs whose origin ≠ yours. |
| SSRF | If auth code fetches URLs (avatar fetch, SSO metadata, webhook), block requests to private IP ranges (RFC1918, link-local 169.254/16, loopback, IPv6 ULA, metadata IPs 169.254.169.254). Resolve DNS yourself and check the resolved IP — don't trust the hostname. |
| Path traversal | If auth involves file operations (avatar upload, export), reject `..`, `\`, NUL bytes, and absolute paths. Resolve and verify the final path is inside the intended root. |
| JSON parsing | Catch JSON parse errors → 400. Enforce request-body size limits (e.g. 1 MB for auth endpoints) to prevent memory-DoS. |
| Content-Type enforcement | Reject requests with unexpected `Content-Type` on auth endpoints. A `text/plain` POST can bypass some CSRF defenses. |
| Unicode normalization | Normalize usernames/emails (NFKC) before storage and comparison to prevent homoglyph account duplicates. |
| Prototype pollution | In Node.js, don't `Object.assign(target, userInput)`. Use `null`-prototype objects, `structuredClone`, or a parser that strips `__proto__` / `constructor.prototype`. |
| File uploads (avatars) | Validate magic bytes, not just extension. Strip EXIF. Serve from a separate cookie-less domain or with `Content-Disposition: attachment` + `X-Content-Type-Options: nosniff`. |

### Incorrect

```typescript
// BAD: SQL injection
const user = await db.query(`SELECT * FROM users WHERE email = '${email}'`);

// BAD: NoSQL injection (no type check)
const user = await User.findOne({ email: req.body.email }); // {$ne: null} bypass

// BAD: open redirect
res.redirect(req.query.next);

// BAD: SSRF
const avatar = await fetch(req.body.avatarUrl);

// BAD: XSS via innerHTML
document.getElementById('welcome').innerHTML = `Welcome, ${user.name}`;
```

### Correct

```typescript
// GOOD: parameterized query + Zod schema + normalized email
import { z } from 'zod';
const SignInBody = z.object({
  email: z.string().email().max(254).toLowerCase(),
  password: z.string().min(8).max(128),
}).strict();
const { email, password } = SignInBody.parse(req.body);
const user = await db.query('SELECT * FROM users WHERE email = $1', [email]);
```

```typescript
// GOOD: redirect allow-list (same-origin paths only)
const SAFE_NEXT = /^\/[a-zA-Z0-9/_-]*$/; // relative paths, no protocol-relative
const next = typeof req.query.next === 'string' && SAFE_NEXT.test(req.query.next)
  ? req.query.next
  : '/';
res.redirect(next);
```

```typescript
// GOOD: SSRF — resolve + block private ranges
import dns from 'node:dns/promises';
import net from 'node:net';
async function safeFetch(url: string) {
  const parsed = new URL(url);
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('bad scheme');
  const { address } = await dns.lookup(parsed.hostname);
  if (isPrivateIp(address)) throw new Error('blocked IP');
  return fetch(`${parsed.protocol}//${address}${parsed.pathname}`, {
    headers: { Host: parsed.hostname },
    redirect: 'manual', // follow manually so each hop is re-validated
  });
}
```

### References

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [CWE-601: URL Redirection to Untrusted Site (Open Redirect)](https://cwe.mitre.org/data/definitions/601.html)
