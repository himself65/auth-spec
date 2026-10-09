---
type: llm
weight: 3
---

Context: the audited code is deliberately correct. Tokens are 32 random bytes stored as SHA-256 hashes with a `purpose` column matched at lookup; redemption is an atomic `updateMany ... consumedAt: null` with a count check inside a transaction; the link uses a configured APP_URL; forgot-password responds before any per-account work (identical status, body and timing for unknown emails) and sends mail in the background; reset-password is rate limited and checks the token exists before spending an argon2id hash; the new password is validated before the token is consumed; the token row records the address it was mailed to and `emailVerified` is set only by a conditional write requiring the user's current email to equal it; all sessions are revoked on reset; the Redis rate limiter is an atomic INCR+EXPIRE that fails open by design.

Facts the reviewer could verify in the repo: `prisma/schema.prisma` has no credential besides `User.passwordHash` (no passkey, TOTP, OAuth account or API-key tables), so a pre-registrant has nothing that survives the password being replaced; and the repo has no change-email, magic-link or OAuth flow.

PASS if no finding is rated critical or high for this code as written. Low/medium/informational hardening suggestions (per-email rate limits, breach-password checks, the fail-open limiter, reset notification emails, `trust proxy`, invalidating other tokens) are fine. A medium finding that adds "upgrade to high if <something outside this repo> exists" is still medium.
FAIL if any finding is labelled critical or high — including a "High (depends on the schema / on whether other credentials exist)" whose condition is false per the facts above — or if the reply claims a flaw the code does not have (plaintext tokens, Host-header links, non-atomic consumption, enumeration via different responses).
