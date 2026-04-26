---
title: Rate Limiting & Brute-Force Protection
impact: MEDIUM
tags: rate-limit, brute-force, account-lockout, captcha, 429, sms-pumping, credential-stuffing
---

## Rate Limiting & Brute-Force Protection

**Impact: MEDIUM**

Without rate limiting, attackers can brute-force passwords, credential-stuff leaked lists, spam sign-up, abuse verification endpoints, and burn money through SMS/email providers. Naive per-IP limits are trivially bypassed by rotating through residential proxies — combine dimensions.

### Checklist

| Check | Requirement |
|-------|------------|
| Sign-in rate limit | Combine **per-account** (e.g. 5 failures / 15 min per email) **and** per-IP (e.g. 20 / 15 min) **and** global. Per-IP alone is bypassed by proxies; per-account alone lets one attacker lock out all users. |
| Sign-up rate limit | Per-IP (e.g. 10/hour) + per-device-fingerprint if available. Block disposable-email domains at sign-up. |
| OTP/code verification | Limit attempts per target (5 / 15 min per phone/email) **and** per IP. Invalidate the code after N failed attempts — don't just block retries. |
| 429 response | Include `Retry-After` (seconds) header. Return the same shape as success to avoid leaking rate-limit thresholds. |
| Password reset | Rate-limit both the **request** (e.g. 3/hour per email, 10/hour per IP) and the **token verification** endpoint. |
| SMS-OTP pumping defense | Cap SMS spend per phone number + per country + per IP. Reject numbers in high-risk countries you don't serve. Prefer WhatsApp/email/authenticator over SMS. Monitor daily SMS spend — a spike means abuse. |
| Email bombardment | Rate-limit any endpoint that sends email to a user-controlled address (sign-up, reset, magic link). An attacker can enumerate emails and spam victims otherwise. |
| Account lockout | After ~10 failures, require CAPTCHA or a cool-off (15 min). **Do not** permanently lock — that's a DoS vector. Notify the user by email. |
| Credential stuffing | Detect patterns: many distinct accounts from one IP/ASN, same password hash across attempts, velocity spikes. Trigger CAPTCHA / 2FA step-up. Cross-check against HIBP Pwned Passwords at sign-in when feasible. |
| CAPTCHA placement | Add CAPTCHA on the 2nd+ failure, not the 1st (UX). Use invisible/v3 for legit users; visible for suspected bots. Never rely on CAPTCHA as the only defense. |
| Distributed store | Use Redis / DB-backed counters, not in-memory — each server instance otherwise has its own counter. Set a ceiling on memory growth. |
| Key choice | Rate-limit keys should include the **authenticated user ID** once known, not just IP. Hash IPs if you store them for limiter buckets (privacy). |
| Endpoint-specific limits | Different limits per endpoint: sign-in tighter than sign-up, MFA verification tight, read endpoints looser. |

### Implementation Notes

- For IP extraction behind proxies, trust `X-Forwarded-For` **only** from known load balancers. A naive `req.headers['x-forwarded-for']` is attacker-controlled.
- When using sliding-window or token-bucket algorithms, document the window and burst. Don't silently change them — it affects support triage.
- Prefer **fail-closed** on the limiter: if Redis is down, reject auth attempts rather than letting them all through.

Refer to `references/features/rate-limiting.md` in the create-auth skill for full implementation details and code examples across languages.

### References

- [OWASP Blocking Brute Force Attacks](https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks)
- [OWASP Credential Stuffing Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)
- [IETF RFC 6585 — 429 Too Many Requests](https://datatracker.ietf.org/doc/html/rfc6585#section-4)
- [Twilio — Defending against SMS pumping fraud](https://www.twilio.com/docs/verify/preventing-toll-fraud)
