# Captcha

Bot protection on authentication endpoints using CAPTCHA verification.

## Schema Additions

None — captcha is stateless and verified server-side via provider API.

## Configuration

The implementation should accept a captcha configuration:
- `provider`: "recaptcha" | "hcaptcha" | "turnstile"
- `secretKey`: server-side verification key
- `siteKey`: client-side key (returned in config endpoint)
- `endpoints`: which endpoints require captcha (default: sign-up, sign-in)

## Endpoints

**GET /api/auth/captcha/config**
- Returns `{ provider, siteKey }` so the client can render the captcha widget
- No authentication required

**Middleware: Captcha Verification**
Rather than a separate endpoint, add captcha verification as middleware on protected endpoints.

Protected endpoints receive an additional field:
- `captchaToken` in the request body

Verification:
1. Extract `captchaToken` from request body
2. Call the provider's verification API:
   - reCAPTCHA: `POST https://www.google.com/recaptcha/api/siteverify`
   - hCaptcha: `POST https://hcaptcha.com/siteverify`
   - Turnstile: `POST https://challenges.cloudflare.com/turnstile/v0/siteverify`
3. Send `{ secret, response: captchaToken }` (plus `remoteip` optionally)
4. If verification fails: return 400 `{ error: "captcha_failed" }`
5. If verification passes: proceed with the endpoint logic

## Implementation Rules

- Captcha verification is server-side only — never trust the client
- Make captcha optional per-endpoint via configuration
- Provider API calls should have a timeout (5 seconds)
- If the provider API is unreachable, decide based on config: fail-open or fail-closed (default: fail-closed)
- Log captcha failures for monitoring but do not expose provider details to the client
- The captchaToken field should be stripped from the body before passing to the endpoint handler

## Best Practices (Industry Consensus)

- **Provider comparison**:
  - *reCAPTCHA v3* (Google) — invisible, score-based (0.0–1.0); widely adopted but raises privacy concerns due to Google tracking
  - *hCaptcha* — privacy-focused alternative, API-compatible with reCAPTCHA v2; used by Cloudflare previously
  - *Turnstile* (Cloudflare) — invisible, non-interactive JS challenges; WCAG 2.2 AAA compliant; no user friction in most cases; free tier available
- **Invisible captcha preferred for UX**: reCAPTCHA v3 and Turnstile both run without user interaction — prefer these over challenge-based v2 widgets
- **Server-side only**: never trust client-side captcha results; always validate tokens via the provider's siteverify API — unverified tokens may be invalid, expired, or already redeemed
- **Timeout on provider API**: set a 5-second timeout on verification calls; default to fail-closed (reject the request) if the provider is unreachable
- **Make captcha configurable per-endpoint**: not all endpoints need captcha — sign-up and sign-in are high-value targets; session refresh is not
- **Turnstile as a drop-in replacement**: Cloudflare provides migration guides from reCAPTCHA and hCaptcha with minimal code changes
- **Score thresholds** (reCAPTCHA v3): tune the score threshold per action — 0.5 is a reasonable default; lower thresholds for sensitive actions like sign-up

Sources: [Cloudflare Turnstile Docs](https://developers.cloudflare.com/turnstile/), [reCAPTCHA v3 Docs](https://developers.google.com/recaptcha/docs/v3), [hCaptcha Developer Guide](https://docs.hcaptcha.com/)
