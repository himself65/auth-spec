---
title: Input Validation
impact: HIGH
tags: sql-injection, xss, header-injection, host-header, path-traversal, ssrf, open-redirect, mass-assignment, parameter-pollution, validation
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
| Mass assignment / server-owned fields | The parsed schema is an **allow-list of what the client may write**, never a deny-list of what it may not. Any field whose correct value is established by a permission check elsewhere — `role`, `emailVerified`, plan/quota, active organization or team, an impersonation marker, ownership (`userId`) — must be absent from the input type of every generic create/update route, and the parsed object (never the raw body) is what reaches the ORM. A deny-list exposes each new privileged column the day someone adds it. The permission-checking setters write through the data layer directly, so tightening the route schema never breaks them. Every write path shares the one parser — the one that gets forgotten is the IdP profile mapping (see `oauth-oidc.md`). |
| Email validation | Validate format, normalize (lowercase, strip + aliases if your policy says so), reject control chars and CRLF. Treat Unicode confusables carefully for display. |
| Email / header CRLF | Never pass user input directly into email headers (`To`, `Subject`, `From`) or HTTP response headers. CRLF injection splits headers and can cause email spoofing or HTTP response splitting. |
| XSS — output encoding | Encode on output, not input. Use the framework's auto-escaping (React JSX, Jinja2 autoescape, Go `html/template`). Never set `dangerouslySetInnerHTML` / `innerHTML` with user input. |
| XSS — sanitize rich content | If you accept HTML (rich editor), run it through DOMPurify / bleach / sanitize-html on the server with an allow-list. Don't trust client-side sanitization. |
| XSS — CSP fallback | Even with perfect escaping, ship a nonce-based CSP (`script-src 'self' 'nonce-...'`). See `http-security-headers.md`. |
| Open redirect | **Every redirect target must be validated against an allow-list** (either a fixed list of paths, or your own origin). Common attack surfaces: `?redirect=`, `?next=`, OAuth `callbackUrl`, post-signin return URLs. Reject `//evil.com`, `\evil.com`, `javascript:`, `data:`, and URLs whose origin ≠ yours. |
| Forwarded host / base URL | `Host`, `X-Forwarded-Host`, and `X-Forwarded-Proto` are request content, not facts. **Every host that reaches an emailed link, a redirect base, or the trusted-origin set must come from configuration** (env var / fixed allow-list), never from the incoming request. Building a reset link from the request host is password-reset poisoning: the attacker requests a reset for the victim, sets the header to their own host, and the victim's email carries a link that hands over the token. If the host must be resolved per request (multi-tenant), check it against an allow-list and make forwarded-header trust an explicit opt-in — most proxies rewrite `Host` to the public name, so the `X-Forwarded-*` pair is usually attacker-supplied. |
| SSRF | If auth code fetches URLs (avatar fetch, OIDC discovery, SSO metadata, webhooks), resolve DNS yourself and validate the **resolved, parsed IP** — don't trust the hostname or the URL string. Block: RFC1918, loopback `127.0.0.0/8`, `0.0.0.0/8` (routes to localhost on Linux/macOS yet is missed by loopback-only checks), link-local `169.254.0.0/16` and `fe80::/10`, IPv6 loopback `::1` and ULA `fc00::/7`, IPv4-mapped IPv6 (`::ffff:127.0.0.1` — normalize before checking, it bypasses naive IPv4 checks), IPv4-**compatible** IPv6 (`::127.0.0.1` — a different prefix that `URL` silently rewrites to `[::7f00:1]`, so blocking only the `::ffff:` form misses it), IPv6 unspecified `[::]` (the `0.0.0.0` twin), the tunnel and relay ranges (`2002::/16` 6to4, `64:ff9b::/96` NAT64, `2001::/32` Teredo, `192.88.99.0/24` 6to4-relay anycast) and site-local `fec0::/10`, cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`), and `*.localhost` hostnames (RFC 6761 — loopback without any DNS query). Compare hostnames case-insensitively with the trailing DNS root dot stripped — `metadata.google.internal.` is the same host and walks past an exact-string blocklist. Checking the parsed address also defeats alternate encodings (`http://2130706433/`, octal `0177.0.0.1`). Where following a redirect is legitimate (avatar fetch, outbound webhooks), re-validate the resolved IP on **every hop**; discovery, JWKS, token, refresh and introspection fetches refuse redirects outright — see the row below. Put every host decision behind **one** classifier and delete each bespoke copy — duplicated checkers drift, and each drift is a live SSRF. Any loopback exemption is an explicit flag defaulted off, never a silent development carve-out that ships to production. |
| SSRF — never follow redirects on security fetches | Token exchange, token refresh, introspection, JWKS and OIDC discovery URLs come from data a tenant or user registers, so a 3xx from an allow-list-passing host steers the request to an internal address *after* your pre-flight check already passed. Set `redirect: 'manual'` and treat a redirect as a hard failure — do not re-validate and follow it. RFC 6749 §5.1 defines the token response as a direct response and conformant providers never redirect on these endpoints, so refusing costs nothing. Reject **both** shapes a redirect takes: a real 3xx status (Node/undici) and an opaque-redirect response (`res.type === 'opaqueredirect'`, status 0 — spec-compliant runtimes and Cloudflare Workers). Push the same policy into whatever library performs the fetch (e.g. `jose`'s custom-fetch hook for JWKS) — a library that follows redirects re-opens the hole you just closed. |
| Path traversal | If auth involves file operations (avatar upload, export), reject `..`, `\`, NUL bytes, and absolute paths. Resolve and verify the final path is inside the intended root. |
| JSON parsing | Catch JSON parse errors → 400. Enforce request-body size limits (e.g. 1 MB for auth endpoints) to prevent memory-DoS. |
| Content-Type enforcement | Reject requests with unexpected `Content-Type` on auth endpoints. A `text/plain` POST can bypass some CSRF defenses. |
| Repeated parameters (HPP) | A form or query key can legally repeat, and parsers disagree about which occurrence wins — `URLSearchParams.get()` takes the first, `Object.fromEntries(formData)` the last, Express's `qs` yields an array. When the framework's parse and your own check land on different occurrences, the credential you validated is not the one that gets used (`token=<attacker>&token=<victim>`). Read each parameter with a cardinality-preserving call (`getAll`), drop empty occurrences regardless of position, and reject with 400 any parameter repeated with two non-empty values unless it is explicitly defined as repeatable (RFC 8707 `resource`). A `.strict()` schema does not catch this — it rejects unknown fields, not repeated ones. Apply the identical contract to every sibling endpoint that accepts the same credential; the one that skips it is the bypass. |
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

// BAD: reset-link base taken from the request — Host header poisoning
sendEmail(user.email, `https://${req.headers.host}/reset?t=${raw}`);

// BAD: SSRF
const avatar = await fetch(req.body.avatarUrl);

// BAD: XSS via innerHTML
document.getElementById('welcome').innerHTML = `Welcome, ${user.name}`;

// BAD: mass assignment — role / emailVerified / userId arrive from the body
await db.user.update({ where: { id: session.userId }, data: req.body });
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
// GOOD: mass assignment — allow-list the writable fields, write only the parsed object
const UpdateProfile = z.object({
  name: z.string().min(1).max(80),
  image: z.string().url().optional(),
}).strict(); // role, emailVerified, plan, userId are simply not in here
await db.user.update({ where: { id: session.userId }, data: UpdateProfile.parse(req.body) });
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
    redirect: 'manual', // avatar/webhook: re-validate each hop. OAuth/OIDC endpoints: a 3xx is a hard failure
  });
}
```

### References

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [CWE-601: URL Redirection to Untrusted Site (Open Redirect)](https://cwe.mitre.org/data/definitions/601.html)
