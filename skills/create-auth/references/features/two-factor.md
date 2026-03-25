# Two-Factor Authentication (2FA)

TOTP-based second factor with backup codes.

## Schema Additions

**TwoFactor**
| Field        | Type     | Constraints                   |
|--------------|----------|-------------------------------|
| id           | string   | primary key                   |
| userId       | string   | foreign key -> User, unique, not null |
| secret       | string   | not null (encrypted TOTP secret) |
| backupCodes  | string   | not null (JSON array of hashed codes) |
| enabled      | boolean  | default false                 |
| createdAt    | datetime | default now                   |
| updatedAt    | datetime | auto-update                   |

## Endpoints

**POST /api/auth/two-factor/enable**
- Requires valid session (Bearer token)
- Generate TOTP secret (base32 encoded, 20 bytes)
- Generate 10 backup codes (8 chars each, crypto-random alphanumeric)
- Store secret and hashed backup codes (not yet enabled)
- Return `{ secret, uri, backupCodes, qrCode? }`
  - `uri` is the otpauth:// URI for QR code scanning
  - `backupCodes` are shown ONCE — not retrievable later

**POST /api/auth/two-factor/verify**
- Requires valid session (Bearer token)
- Body: `{ code }` (6-digit TOTP code)
- Verify TOTP code against stored secret (allow ±1 time step window)
- If valid: set `enabled = true`, return 200
- If invalid: return 401

**POST /api/auth/two-factor/disable**
- Requires valid session (Bearer token)
- Body: `{ code }` (current TOTP code to confirm)
- Verify code, then delete TwoFactor record
- Return 200

**POST /api/auth/two-factor/challenge**
- Called during sign-in when 2FA is enabled
- Body: `{ code, trustDevice? }` plus session token from initial sign-in
- Verify TOTP code OR backup code
- If backup code used: remove it from the list (single use)
- If valid: upgrade session to fully authenticated, return token + user
- If invalid: return 401

## Sign-In Flow Changes

When a user with 2FA enabled signs in:
1. Verify email + password as normal
2. Create a session but mark it as `twoFactorVerified: false`
3. Return `{ twoFactorRequired: true, token }` (token for the challenge step only)
4. Client must call `/two-factor/challenge` with a TOTP code to complete sign-in
5. Only after challenge is the session fully authenticated

Add to **Session** table:
| Field              | Type    | Constraints    |
|--------------------|---------|----------------|
| twoFactorVerified  | boolean | default true   |

Set `twoFactorVerified = false` on sign-in for 2FA users; set to `true` after challenge.
The session endpoint must reject sessions where `twoFactorVerified = false`.

## Implementation Rules

- Use a TOTP library (e.g., `otpauth`/`otplib` for JS, `pyotp` for Python, `pquerna/otp` for Go)
- TOTP parameters: SHA-1, 6 digits, 30-second period (RFC 6238 defaults)
- Allow ±1 time step window to account for clock drift
- Encrypt the TOTP secret at rest (use the app's encryption key)
- Backup codes: generate 10, hash with bcrypt before storing, each is single-use
- Never expose the TOTP secret after initial setup
- The enable flow is: generate → user scans QR → user enters code to verify → enabled

## Best Practices (Industry Consensus)

Derived from RFC 6238, RFC 4226, NIST SP 800-63B, and observed implementations
at GitHub and Bitwarden.

### TOTP Defaults (RFC 6238)

- **Algorithm**: HMAC-SHA-1 — the universal default; SHA-256/SHA-512 are allowed
  by the spec but not supported by all authenticator apps.
- **Digits**: 6.
- **Period**: 30 seconds.
- **Time window**: Accept ±1 step (i.e., current, previous, and next period) to
  tolerate clock drift and entry delay. GitHub, Bitwarden, and most services use
  this same tolerance.

### Shared Secret

- **Minimum length**: 128 bits (16 bytes) per RFC 4226; **recommended** 160 bits
  (20 bytes). Use 20 bytes.
- **Encoding**: Base32 (standard for `otpauth://` URIs and QR codes).
- **Storage**: Encrypt at rest with an application-level key. NIST SP 800-63B
  requires symmetric keys to be "strongly protected against compromise."
- Never expose the secret after the initial setup flow.

### Backup / Recovery Codes

- Generate **8–16 single-use codes** at enable time.
  - GitHub provides 16 codes in `xxxxx-xxxxx` alphanumeric format.
  - A common alternative is 8–10 codes of 8 alphanumeric characters each.
- Hash each code (bcrypt or similar) before storing; show plaintext only once.
- Consuming a code removes it permanently.
- Provide a "regenerate codes" action that invalidates all previous codes.

### Recovery When 2FA Device Is Lost

- Primary path: backup codes (all major services).
- Optional additional paths: verified email with identity confirmation,
  pre-registered SSH keys or passkeys (GitHub), or account recovery request with
  manual review. Choose based on your threat model.

### Anti-Replay

- NIST SP 800-63B: "verifiers SHALL accept a given time-based OTP only once
  during the validity period."
- Track the last successfully used time step per user. Reject any code whose
  time step is ≤ the stored value.

### Partial Session (2FA Challenge Flow)

- On password verification for a 2FA-enabled account, issue a short-lived token
  that is scoped exclusively to the `/two-factor/challenge` endpoint.
- All other endpoints must reject this token.
- Expire the partial session quickly (e.g., 5 minutes).

### Rate Limiting

- NIST SP 800-63B requires rate limiting on OTP verification, especially when
  the code is fewer than 64 bits (6-digit TOTP = ~20 bits).
- Recommended: lock the challenge after 5–10 consecutive failures with an
  exponential backoff or temporary account lock.
