---
title: Error Handling & Information Leakage
impact: CRITICAL
tags: enumeration, timing-attack, stack-trace, generic-errors, side-channel
---

## Error Handling & Information Leakage

**Impact: CRITICAL**

Verbose error messages and inconsistent response behavior leak whether accounts exist, what tech stack is used, and internal implementation details — all of which help attackers. The fix is not just the error body: attackers also observe **status codes, response timing, and response size**.

### Checklist

| Check | Requirement |
|-------|------------|
| Generic auth errors | Sign-in failure must return generic "Invalid email or password" — never "User not found" or "Wrong password". |
| Status-code symmetry | "User not found" and "wrong password" must return the same HTTP status (both 401). Attackers distinguish 401 vs 404 just as easily as text. |
| Response-size symmetry | Success, "no such user", and "wrong password" branches should return similarly sized bodies. Differing sizes leak state even with identical text. |
| Sign-up enumeration | Sign-up with an existing email must return the same status/shape as success (and send a "someone tried to register with your email" email to the existing user). See create-auth skill for details. |
| Password reset enumeration | Always respond "If an account exists, we sent a reset email" — never confirm whether the email is registered. Enqueue the email async so timing doesn't leak. |
| Verify-step ordering | On an endpoint taking an identifier plus a server-issued secret (OTP, magic link, reset token), verify the secret first and load the account afterwards. A `findUserByEmail` → 404 placed ahead of the token check is an existence oracle no error wording can fix. Once possession is proven, a specific "no such account" leaks nothing. (Password sign-in is the exception — the hash lives on the user row; use the dummy-hash trick instead.) |
| Authorize before state-dependent validation | On an authenticated endpoint, evaluate the caller's permission on the target **before** validating the body against server state — whether the requested role exists, whether the member/org/record exists, whether a value is already taken. A validation error returned to a caller who is not allowed to make the request at all is an oracle: a non-admin learns which roles and members exist from the difference between "unknown role" and 403 (better-auth 1.7 reordered `updateMemberRole` this way). Pure shape checks (schema parse, size limits) may run first — they reveal nothing about state. Unauthorized callers get one uniform 403 (or 404 for resources whose existence is itself sensitive) regardless of body content. |
| Forgot-username / email-exists UX | The "check if email is available" UX at sign-up does leak enumeration. If you ship it, rate-limit it aggressively and CAPTCHA-gate it. |
| Stack traces | Production error responses must never include stack traces, SQL errors, internal paths, or library versions. Log server-side; return opaque error IDs to the client for support. |
| Timing attacks — password | Use constant-time verify (bcrypt/argon2 `verify` is constant-time). When the user doesn't exist, still hash a dummy password so the response time matches. |
| Timing attacks — tokens | Compare session tokens, CSRF tokens, API keys, email-verification tokens with `crypto.timingSafeEqual` / `hmac.compare_digest`. Never `==` / `===`. |
| Timing attacks — external calls | Async email sending, DB lookups by email, and OAuth provider calls can all add branch-dependent latency. Wrap in constant-time wrappers or jitter where critical. |
| Side-channel via rate-limit responses | If your 429 appears only when the account exists, attackers enumerate via the rate-limit. Apply the limiter uniformly. |
| Verbose headers | Strip `X-Powered-By`, `Server`, framework-version headers. |
| Debug mode | Verify debug/dev mode is off in prod: Django `DEBUG=False`, Rails `config.consider_all_requests_local=false`, Express `NODE_ENV=production`, Next.js `next build` not `next dev`. |
| Source maps | Don't ship production JS source maps unless they're behind auth. They reveal original file paths and logic. |
| Error IDs for support | On 500s, return `{ error: "Internal server error", errorId: "<uuid>" }` and log the UUID server-side. Lets support correlate without leaking internals. |

### Incorrect

```typescript
// BAD: leaks whether email exists (text + status + timing)
const user = await db.user.findUnique({ where: { email } });
if (!user) return res.status(404).json({ error: "User not found" });
const ok = await bcrypt.compare(password, user.passwordHash);
if (!ok) return res.status(401).json({ error: "Wrong password" });
```

```python
# BAD: stack trace in response
except Exception as e:
    return jsonify(error=str(e), trace=traceback.format_exc()), 500
```

```typescript
// BAD: token comparison not constant-time
if (providedToken === expectedToken) { /* ... */ }
```

### Correct

```typescript
// GOOD: same status, same shape, constant-time-ish regardless of user existence
const DUMMY_HASH = '$argon2id$v=19$m=19456,t=2,p=1$...'; // pre-computed at boot

async function signIn(email, password) {
  const user = await db.user.findUnique({ where: { email } });
  const hash = user?.passwordHash ?? DUMMY_HASH;
  const ok = await argon2.verify(hash, password);
  if (!user || !ok) {
    return res.status(401).json({ error: "Invalid email or password" });
  }
  // ...
}
```

```python
# GOOD: generic error, correlation ID, real details server-side
import uuid, logging
try:
    ...
except Exception:
    error_id = str(uuid.uuid4())
    logging.exception(f"auth error {error_id}")
    return jsonify(error="Internal server error", errorId=error_id), 500
```

```typescript
// GOOD: constant-time token compare
import crypto from 'crypto';
const a = Buffer.from(providedToken);
const b = Buffer.from(expectedToken);
if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
  return res.status(401).json({ error: 'Invalid token' });
}
```

### References

- [OWASP Authentication Cheat Sheet — Authentication Responses](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#authentication-responses)
- [CWE-209: Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)
- [CWE-208: Observable Timing Discrepancy](https://cwe.mitre.org/data/definitions/208.html)
- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
