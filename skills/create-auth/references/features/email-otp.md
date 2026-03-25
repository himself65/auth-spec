# Email OTP

Passwordless authentication via one-time codes sent to email.

## Schema Additions

**EmailVerificationCode**
| Field     | Type     | Constraints                        |
|-----------|----------|------------------------------------|
| id        | string   | primary key                        |
| userId    | string   | foreign key -> User, nullable (for sign-up flows) |
| email     | string   | not null                           |
| code      | string   | not null (6-digit numeric)         |
| expiresAt | datetime | not null (default: 10 minutes)     |
| createdAt | datetime | default now                        |

## Endpoints

**POST /api/auth/email-otp/send**
- Body: `{ email }`
- Generate a 6-digit numeric code (crypto-random)
- Store code with 10-minute expiry
- Send code via email (use the project's email service)
- Return 200 (always — do not reveal whether email exists)
- Rate limit: max 3 requests per email per 10 minutes

**POST /api/auth/email-otp/verify**
- Body: `{ email, code }`
- Look up the most recent unexpired code for this email
- If valid: create or find User, create Session, delete code, return token + user
- If invalid or expired: return 401 with generic error
- Delete code after successful verification (single use)

## Implementation Rules

- Codes MUST be 6 digits, zero-padded (e.g., "003847")
- Generate with crypto-random, not Math.random
- Each code is single-use — delete after verification
- Delete all previous codes for the same email when generating a new one
- Constant-time comparison for code verification
- Do not reveal in error messages whether the email exists
- If the user does not exist, create a new User + Account (providerId: "email-otp") on successful verification

## Best Practices (Industry Consensus)

### Code Format and Entropy
- Use **6-digit numeric codes** — provides ~20 bits of entropy, meeting the OWASP ASVS
  minimum (OWASP ASVS V2.8). Longer alphanumeric codes (e.g., 8 chars) improve entropy
  but hurt usability on mobile; 6 digits is the dominant industry choice.
- Generate codes with a cryptographically secure RNG (`crypto.randomInt`, not `Math.random`).

### Expiry
- **10 minutes** is the OWASP-recommended maximum for out-of-band codes (OWASP Cheat Sheet).
- Supabase defaults to 60 minutes but allows configuration; Auth.js magic-link tokens
  default to 24 hours. For OTP (manual entry), 5-10 minutes is the safe range —
  shorter windows reduce brute-force exposure.

### Attempt Limits
- **3-5 failed attempts per code**, then invalidate it and require a new send
  (OWASP recommends 3). This caps brute-force probability to ~0.3% for a 6-digit code.
- Optionally apply a temporary lockout (30-60 s) after exhausting attempts.

### Rate Limiting (Send Endpoint)
- **Max 3 sends per email per 10-minute window** to prevent OTP flooding / email bombing.
- Also rate-limit by IP (e.g., 10 sends per IP per 10 min) to block distributed abuse.
- Enforce a minimum resend interval (e.g., 60 seconds) per email — Supabase enforces this.
- Consider CAPTCHA on repeated triggers from the same IP or email.

### Storage and Comparison
- **Hash OTP codes at rest** — Supabase stores hashed tokens; OWASP ASVS V2.7.3 requires
  the verifier to retain "only a hashed version of the authentication code." While a
  6-digit keyspace is small, hashing still raises the bar for opportunistic DB access.
- Use a fast hash (SHA-256 with a per-row salt) rather than bcrypt — OTPs are short-lived
  and low-entropy, so slow hashing adds latency without meaningful brute-force resistance.
- **Constant-time comparison** (`crypto.timingSafeEqual`) to prevent timing side-channels
  (OWASP Authentication Cheat Sheet).

### Cleanup
- Delete all previous codes for the same email when generating a new one.
- Purge expired codes via a periodic cron job or lazy cleanup (check-and-delete on the
  next request for that email). Avoid unbounded table growth.

### Response Privacy
- **Never reveal whether an email exists** — always return 200 on send, generic errors on
  verify (OWASP Authentication Cheat Sheet). This matches NIST SP 800-63B guidance on
  minimizing oracle attacks against user enumeration.

### NIST Caveat
- NIST SP 800-63B explicitly states email "SHALL NOT be used for out-of-band
  authentication" at AAL2+ because it cannot prove device possession. Email OTP is
  acceptable for low-assurance sign-in / passwordless convenience but should not be
  the sole factor for sensitive operations.

### Sources
- [OWASP ASVS V2 — Authentication](https://github.com/OWASP/ASVS/blob/master/4.0/en/0x11-V2-Authentication.md)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST SP 800-63B — Digital Identity Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [Supabase Email OTP Docs](https://supabase.com/docs/guides/auth/passwordless-login/auth-email-otp)
- [Auth.js Email Providers](https://authjs.dev/getting-started/authentication/email)
- [Unkey — Ratelimiting OTP Endpoints](https://www.unkey.com/blog/ratelimiting-otp)
