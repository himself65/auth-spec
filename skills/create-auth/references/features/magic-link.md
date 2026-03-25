# Magic Link

Passwordless authentication via emailed one-time links.

## Schema Additions

**MagicLinkToken**
| Field     | Type     | Constraints                    |
|-----------|----------|--------------------------------|
| id        | string   | primary key                    |
| email     | string   | not null                       |
| token     | string   | unique, not null (crypto-random) |
| expiresAt | datetime | not null (default: 15 minutes) |
| createdAt | datetime | default now                    |

## Endpoints

**POST /api/auth/magic-link/send**
- Body: `{ email, callbackUrl? }`
- Generate a crypto-random token (min 32 bytes, URL-safe base64)
- Store token with 15-minute expiry
- Send email with link: `{callbackUrl}?token={token}` (or a default callback)
- Return 200 (always — do not reveal whether email exists)
- Rate limit: max 3 requests per email per 15 minutes

**POST /api/auth/magic-link/verify**
- Body: `{ token }`
- Look up token, verify not expired
- If valid: create or find User, create Session, delete token, return token + user
- If invalid or expired: return 401 with generic error
- Delete token after successful verification (single use)

## Implementation Rules

- Tokens must be crypto-random (min 32 bytes), URL-safe base64 encoded
- Each token is single-use — delete after verification
- Delete all previous tokens for the same email when generating a new one
- Do not reveal in error messages whether the email exists
- If the user does not exist, create a new User + Account (providerId: "magic-link") on successful verification
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
