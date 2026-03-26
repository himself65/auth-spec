---
title: Rate Limiting & Brute-Force Protection
impact: MEDIUM
tags: rate-limit, brute-force, account-lockout, captcha, 429
---

## Rate Limiting & Brute-Force Protection

**Impact: MEDIUM**

Without rate limiting, attackers can brute-force passwords, spam sign-up, and abuse verification endpoints at scale.

### Checklist

| Check | Requirement |
|-------|------------|
| Sign-in rate limit | Must limit login attempts per IP + email combination (recommended: 5 per 15 minutes). |
| Sign-up rate limit | Must limit sign-up attempts per IP (recommended: 10 per hour). |
| OTP/code verification | Must limit verification attempts (recommended: 5 per 15 minutes per target). |
| 429 response | Rate limit responses must include `Retry-After` header. |
| Password reset | Password reset endpoint must be rate-limited like sign-in. |
| Account lockout | Consider temporary lockout after repeated failures (e.g., 15 minutes after 10 failed attempts). |

### Implementation Notes

Refer to `references/features/rate-limiting.md` in the create-auth skill for full implementation details and code examples across languages.

### References

- [OWASP Blocking Brute Force Attacks](https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks)
- [IETF RFC 6585 — 429 Too Many Requests](https://datatracker.ietf.org/doc/html/rfc6585#section-4)
