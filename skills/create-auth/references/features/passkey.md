# Passkey (WebAuthn/FIDO2)

Passwordless authentication using platform authenticators and security keys.

## Schema Additions

**Passkey**
| Field           | Type     | Constraints                        |
|-----------------|----------|------------------------------------|
| id              | string   | primary key                        |
| userId          | string   | foreign key -> User, not null      |
| credentialId    | string   | unique, not null (base64url)       |
| publicKey       | string   | not null (base64url-encoded COSE key) |
| counter         | integer  | not null, default 0                |
| deviceType      | string   | nullable ("singleDevice" or "multiDevice") |
| backedUp        | boolean  | default false                      |
| transports      | string   | nullable (JSON array of transport types) |
| createdAt       | datetime | default now                        |

## Endpoints

**POST /api/auth/passkey/register/options**
- Requires valid session (Bearer token)
- Generate WebAuthn registration options (challenge, RP info, user info, supported algorithms)
- Store challenge temporarily (5-minute expiry)
- Return registration options JSON

**POST /api/auth/passkey/register/verify**
- Requires valid session (Bearer token)
- Body: `{ credential }` (WebAuthn attestation response)
- Verify attestation against stored challenge
- Store new Passkey record with extracted public key, credential ID, counter
- Return 200 with passkey info

**POST /api/auth/passkey/authenticate/options**
- Body: `{ email? }` (optional — for discoverable credentials, no email needed)
- Generate WebAuthn authentication options (challenge, allowed credentials)
- Store challenge temporarily (5-minute expiry)
- Return authentication options JSON

**POST /api/auth/passkey/authenticate/verify**
- Body: `{ credential }` (WebAuthn assertion response)
- Look up Passkey by credential ID
- Verify assertion against stored public key and challenge
- Verify and update counter (must be greater than stored value)
- Create Session, return token + user

## Implementation Rules

- Use a WebAuthn library for your language (e.g., `@simplewebauthn/server` for JS/TS, `py_webauthn` for Python, `go-webauthn` for Go)
- Relying Party (RP) ID should be configurable (defaults to the domain)
- Challenges must be crypto-random (min 32 bytes) with short expiry
- Support both platform authenticators (Touch ID, Windows Hello) and cross-platform (security keys)
- Counter verification prevents cloned authenticators
- Credential IDs and public keys should be stored as base64url
- Registration requires an existing session (user must be signed in first)
- Authentication is passwordless (no session required)

## Best Practices (Industry Consensus)

- **Use WebAuthn Level 2** — the current W3C standard, supported across all major OS platforms (Windows, macOS, Linux, Android, iOS, ChromeOS)
- **Support discoverable credentials (resident keys)** for truly passwordless login — the credential (private key, credential ID, user handle) is stored entirely in the authenticator, so no user ID is needed upfront
- **RP ID**: use the registrable domain (e.g., `example.com`), make it configurable; origin verification on the server prevents phishing
- **Algorithms**: prefer ES256 (`-7`) as the primary algorithm; also support RS256 (`-257`) for broader authenticator compatibility
- **Counter verification**: always check that the returned counter is greater than the stored value — this detects cloned authenticators
- **Attestation**: use `"none"` for most consumer apps (simplifies implementation and avoids managing attestation CA certificates); only use `"direct"` or `"enterprise"` when regulatory or enterprise policy requires device provenance
- **Libraries**: use well-maintained, spec-compliant libraries — `@simplewebauthn/server` (JS/TS), `py_webauthn` (Python), `go-webauthn` (Go)
- **Registration requires an existing session**; authentication is passwordless — this is by design per the FIDO Alliance guidance
- **Backup eligibility**: store `deviceType` and `backedUp` flags (from authenticator data) to detect multi-device credentials synced via cloud providers (Apple, Google, Microsoft)

Sources: [W3C WebAuthn Level 2](https://www.w3.org/TR/webauthn-2/), [FIDO Alliance Passkeys](https://fidoalliance.org/passkeys/), [passkeys.dev Specs](https://passkeys.dev/docs/reference/specs/)
