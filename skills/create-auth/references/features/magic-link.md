# Magic Link

Passwordless authentication via emailed one-time links.

## Schema Additions

**MagicLinkToken**
| Field     | Type     | Constraints                    |
|-----------|----------|--------------------------------|
| id        | string   | primary key                    |
| email     | string   | not null (stored in canonical form) |
| tokenHash | string   | unique, not null (SHA-256 of the raw token) |
| expiresAt | datetime | not null (default: 15 minutes) |
| createdAt | datetime | default now                    |

## Endpoints

**POST /api/auth/magic-link/send**
- Body: `{ email, callbackUrl? }` (canonicalize the email through the shared helper — NFKC, trim, lowercase — before any lookup; see `references/pitfalls/email-case-normalization.md`)
- Generate a crypto-random token (min 32 bytes, URL-safe base64)
- Store the SHA-256 hash of the token with 15-minute expiry — the raw token exists only inside the emailed link
- Send email with link: `{callbackUrl}?token={token}` (or a default callback)
- Return 200 (always — do not reveal whether email exists)
- Rate limit: max 3 requests per email per 15 minutes

**POST /api/auth/magic-link/verify**
- Body: `{ token }`
- Hash the presented token (SHA-256) and look up by `tokenHash`; verify not expired
- **Consume atomically** (conditional delete gated on affected rows — see `references/pitfalls/single-use-token-race.md`); concurrent redemptions of the same link must mint at most one session
- If consumed and no User exists for this email: create User + Account (providerId: "magic-link") with `emailVerified = true`, create Session, return session token + user
- If consumed and a User already exists with `emailVerified = false` **and has proven no other identifier** (`phoneVerified` false): that row may have been planted by someone who never proved control of the address — claim and strip it in one transaction (see `references/pitfalls/pre-account-hijack-strip.md`), then create Account (providerId: "magic-link") + Session. If it already carries a verified phone it is an established account, not a plant: return the generic 401 and let the owner attach the address from an authenticated session
- If consumed and a User already exists with `emailVerified = true`: this is the proven owner — do not strip, leave every Account, Passkey and TwoFactor row intact; upsert this feature's Account on `(providerId, accountId)`, create Session, return session token + user
- If invalid or expired: return 401 with generic error

## Implementation Rules

- Tokens must be crypto-random (min 32 bytes), URL-safe base64 encoded
- Store only the SHA-256 hash at rest (see Token Generation & Storage below); look up by hash at verify time
- Each token is single-use — consume with one conditional write (affected-rows check), never find-then-delete
- Delete all previous tokens for the same email when generating a new one
- Do not reveal in error messages whether the email exists
- On successful verification, resolve the User through the shared sign-up gate in `SKILL.md`'s Implementation Rules rather than inserting one here; if it permits a new account, create User + Account (providerId: "magic-link") with `emailVerified = true`
- Never send to, resolve, or create against a synthesized placeholder address (`*.placeholder.invalid`, see `references/features/phone-number.md`) — treat a request for one as a no-op that still returns the generic success response
- If the User already exists and is still unverified, use the single-transaction claim-and-strip of `references/pitfalls/pre-account-hijack-strip.md` — nothing that predates this proof (password, passkey, session) may survive it. That strip deletes every Account row, so create this feature's own Account (providerId: "magic-link") after it and before minting the Session. On an already-verified row no strip runs and the Account may already exist — upsert on `(providerId, accountId)` rather than blind-inserting, or the second passwordless sign-in violates the unique constraint
- The callback URL should be validated against an allowlist to prevent open redirect

## Best Practices (Industry Consensus)

Derived from Slack, Supabase, Auth.js/NextAuth, and OWASP guidelines.

### Token Generation & Storage

- **Min 32 bytes crypto-random, URL-safe base64.** Slack uses RS256-signed JWTs; Supabase and Auth.js both use random hex/base64 tokens. 32 bytes (256 bits) is the common floor across all three.
- **Hash tokens at rest.** Store a SHA-256 hash in the database, not the raw token. If the database leaks, raw tokens remain unusable. Auth.js hashes verification tokens by default.

### Expiry

- **10-15 minutes recommended.** Supabase defaults to 1 hour (configurable, max 24h); Slack uses shorter-lived tokens. OWASP advises keeping lifetime low to limit brute-force and interception windows. 15 minutes balances usability and security.

### Single Use

- **Always delete (or invalidate) after verification.** Every major provider enforces this. Also delete all prior tokens for the same email when issuing a new one to prevent token accumulation.

### Open Redirect Prevention

- **Validate the callback URL against a strict allowlist.** This is a critical OWASP item. Never redirect to an arbitrary user-supplied URL. Compare scheme + host + port against configured origins.

### Rate Limiting

- **Max 3 requests per email per 15 minutes.** Supabase enforces one request per 60 seconds by default. Rate limiting prevents enumeration attacks and email bombing. Return 200 regardless of whether the email exists.

### Email Content

- Clear subject line (e.g., "Your sign-in link for {app}").
- Visible, clickable link (not hidden behind a button only).
- "If you didn't request this, you can safely ignore this email" disclaimer.
- Transmit links only over TLS (HTTPS URLs).

### Cross-Device Support

- Magic links should work even if opened in a different browser or device than the one that initiated the request. Achieve this with **stateless verification**: the token alone (not a session cookie) must be sufficient to complete sign-in. Bind the token to the email, not to a browser session.
