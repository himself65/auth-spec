# Passkey (WebAuthn/FIDO2)

Passwordless authentication using platform authenticators (Touch ID, Windows Hello, Face ID) and cross-platform security keys (YubiKey, etc.). Based on W3C WebAuthn Level 3 and FIDO2/CTAP 2.2.

## Schema Additions

**Passkey**
| Field           | Type     | Constraints                                  |
|-----------------|----------|----------------------------------------------|
| id              | string   | primary key                                  |
| userId          | string   | foreign key -> User, not null                |
| credentialId    | string   | unique, indexed, not null (base64url)        |
| publicKey       | bytes    | not null (COSE public key, store as raw bytes/BYTEA/BLOB) |
| counter         | bigint   | not null, default 0                          |
| deviceType      | string   | not null ("singleDevice" or "multiDevice")   |
| backedUp        | boolean  | not null, default false                      |
| transports      | string   | nullable (JSON array: "internal", "usb", "ble", "nfc", "hybrid") |
| aaguid          | string   | nullable (authenticator model identifier)    |
| name            | string   | nullable (user-given label, e.g. "MacBook Touch ID") |
| lastUsedAt      | datetime | nullable                                     |
| createdAt       | datetime | default now                                  |

**PasskeyChallenge** (ephemeral — can use cache/Redis instead of a table)
| Field     | Type     | Constraints                    |
|-----------|----------|--------------------------------|
| id        | string   | primary key                    |
| userId    | string   | nullable (null for auth flows) |
| challenge | string   | not null (base64url)           |
| type      | string   | not null ("registration" or "authentication") |
| expiresAt | datetime | not null (5 minutes from now)  |

## Endpoints

### POST /api/auth/passkey/register/options

Generate WebAuthn registration options. Requires an existing session (user must be signed in).

- **Auth**: Bearer token (valid session required)
- **Response 200**: `PublicKeyCredentialCreationOptionsJSON`

Server must:
1. Generate a crypto-random challenge (min 32 bytes), base64url-encode it
2. Build `PublicKeyCredentialCreationOptions`:
   ```
   {
     rp: { id: <configurable, default: domain>, name: <app name> },
     user: {
       id: <base64url of user's unique webauthn ID — NOT the user table PK>,
       name: <user email or username>,
       displayName: <user display name>
     },
     challenge: <base64url challenge>,
     pubKeyCredParams: [
       { type: "public-key", alg: -7 },    // ES256 (preferred)
       { type: "public-key", alg: -257 }    // RS256 (broad compat)
     ],
     timeout: 300000,  // 5 minutes
     authenticatorSelection: {
       residentKey: "preferred",
       userVerification: "preferred",
     },
     attestation: "none",
     excludeCredentials: [
       // All user's existing passkeys, to prevent re-registration
       { id: <credentialId>, type: "public-key", transports: [...] }
     ]
   }
   ```
3. Store challenge in PasskeyChallenge (or cache) with 5-minute expiry and `type: "registration"`
4. Return the options as JSON

### POST /api/auth/passkey/register/verify

Verify WebAuthn registration (attestation) response and store the new passkey.

- **Auth**: Bearer token (valid session required)
- **Body**: `{ credential: RegistrationResponseJSON }`
- **Response 200**: `{ id, name, deviceType, backedUp, transports, createdAt }`
- **Response 400**: invalid/expired challenge, verification failed

Server must:
1. Retrieve the stored challenge for this user (type: "registration")
2. Verify the attestation response:
   - `clientDataJSON.type` === `"webauthn.create"`
   - `clientDataJSON.challenge` matches stored challenge
   - `clientDataJSON.origin` matches expected origin(s)
   - RP ID hash in authenticator data matches expected RP ID
   - User presence (UP) flag is set
   - Extract public key, credential ID, counter, device type, backed-up flag
3. Check credential ID is not already registered (prevent duplicate)
4. Store new Passkey record with all extracted fields
5. Delete the used challenge
6. Return passkey metadata (never return the public key to the client)

### POST /api/auth/passkey/authenticate/options

Generate WebAuthn authentication options. No session required — this is passwordless.

- **Auth**: none
- **Body**: `{ email? }` (optional — omit for discoverable credential flow)
- **Response 200**: `PublicKeyCredentialRequestOptionsJSON`

Server must:
1. Generate crypto-random challenge (min 32 bytes)
2. If `email` provided, look up user's passkeys for `allowCredentials`
3. If no `email`, leave `allowCredentials` empty (discoverable credential / conditional UI flow)
4. Build `PublicKeyCredentialRequestOptions`:
   ```
   {
     challenge: <base64url challenge>,
     rpId: <RP ID>,
     timeout: 300000,
     userVerification: "preferred",
     allowCredentials: [
       // Empty for discoverable, or list user's passkeys:
       { id: <credentialId>, type: "public-key", transports: [...] }
     ]
   }
   ```
5. Store challenge with 5-minute expiry and `type: "authentication"`
6. Return the options as JSON

### POST /api/auth/passkey/authenticate/verify

Verify WebAuthn authentication (assertion) response and sign the user in.

- **Auth**: none
- **Body**: `{ credential: AuthenticationResponseJSON }`
- **Response 200**: `{ user: { id, email, name }, token }`
- **Response 401**: invalid credential, expired challenge, counter mismatch

Server must:
1. Extract credential ID from the response
2. Look up the Passkey record by credential ID
3. Retrieve the stored challenge (type: "authentication")
4. Verify the assertion response:
   - `clientDataJSON.type` === `"webauthn.get"`
   - `clientDataJSON.challenge` matches stored challenge
   - `clientDataJSON.origin` matches expected origin(s)
   - RP ID hash matches
   - User presence (UP) flag is set
   - Signature is valid against stored public key
   - Counter > stored counter (detects cloned authenticators)
5. Update the passkey's counter and `lastUsedAt`
6. Delete the used challenge
7. Create a new Session and return token + user

### DELETE /api/auth/passkey/:passkeyId

Remove a registered passkey. Requires valid session.

- **Auth**: Bearer token
- **Response 200**: `{ success: true }`
- **Response 403**: passkey does not belong to authenticated user
- **Response 400**: cannot delete last passkey if user has no password (would lock them out)

### GET /api/auth/passkey

List all passkeys for the authenticated user. Requires valid session.

- **Auth**: Bearer token
- **Response 200**: `{ passkeys: [{ id, name, deviceType, backedUp, transports, lastUsedAt, createdAt }] }`

Never return `publicKey` or `credentialId` to the client in listing responses.

## Implementation Rules

### Libraries (use these, do NOT implement WebAuthn crypto yourself)

| Language    | Library                         | Notes                          |
|-------------|---------------------------------|--------------------------------|
| JS/TS       | `@simplewebauthn/server`        | Most popular, well-maintained  |
| Python      | `py_webauthn`                   | Spec-compliant, async support  |
| Go          | `github.com/go-webauthn/webauthn` | Standard Go library          |
| Rust        | `webauthn-rs`                   | Type-safe, well-tested        |
| Java/Kotlin | `com.yubico:webauthn-server-core` | From Yubico, reference impl |
| Ruby        | `webauthn-ruby`                 | ActiveRecord integration       |
| C#/.NET     | `Fido2NetLib`                   | FIDO2 certified               |

### Algorithms

- **MUST** support ES256 (alg: `-7`) — ECDSA with SHA-256 on P-256 curve. This is the most universally supported.
- **SHOULD** support RS256 (alg: `-257`) — RSASSA-PKCS1-v1_5 with SHA-256. Needed for older Windows Hello and some security keys.
- **MAY** support EdDSA (alg: `-8`) — Ed25519. Exclude on Node.js <18 or Firefox ≤118.
- List them in preference order: `[{ alg: -7 }, { alg: -257 }]`

### RP (Relying Party) Configuration

- RP ID = registrable domain (e.g. `example.com`), not the full origin
- Must be configurable (environment variable or config file)
- Origin = `https://<rpId>` — server validates this from `clientDataJSON`
- For localhost development, browsers allow `http://localhost` as a special case

### Challenges

- Crypto-random, minimum 32 bytes, base64url-encoded
- 5-minute expiry (configurable)
- Single-use: delete after verification (prevents replay)
- Store server-side only (cache, DB, or session)

### Credential Storage

- `publicKey`: store as raw bytes (BYTEA/BLOB), NOT base64 string — avoids re-encoding on every verification
- `credentialId`: base64url string, **must be indexed** for fast lookup during authentication
- `counter`: use bigint — some authenticators use large counter values
- `transports`: store as JSON array string, return during `allowCredentials` to help the browser pick the right transport

### Counter Verification

- On each authentication, assert `response.counter > stored.counter`
- If counter goes backwards or stays at 0 when stored > 0, the authenticator may be cloned — reject and alert
- Some authenticators (especially synced passkeys) always return counter = 0; handle this by only failing if stored counter was > 0

### Security

- **Registration requires an existing session** — user must prove identity first (password, magic link, etc.)
- **Authentication is passwordless** — no prior session needed
- **Attestation**: use `"none"` for consumer apps. Only use `"direct"` or `"enterprise"` when compliance requires device provenance.
- **Never expose `publicKey` or raw `credentialId` in API list responses** — only return metadata
- **RP ID validation prevents phishing** — the browser enforces origin matches

### Discoverable Credentials (Resident Keys)

- Set `residentKey: "preferred"` (not `"required"`) — some older authenticators don't support it
- Discoverable credentials enable autofill / conditional UI: user doesn't need to type their email
- The `user.id` in registration options should be a random opaque identifier (NOT email, NOT user table PK) — this is the `webauthnUserID` returned during authentication in `userHandle`
- Store this `webauthnUserID` on the user record to map assertion responses back to users

### Multi-Device / Backup Awareness

- `deviceType: "singleDevice"` = credential lives on one device only (e.g. hardware security key)
- `deviceType: "multiDevice"` = credential can sync across devices (e.g. Apple/Google passkey)
- `backedUp: true` = credential has been synced to cloud
- Store these flags to give users visibility into their credential security posture

Sources: [W3C WebAuthn Level 3](https://w3c.github.io/webauthn/), [FIDO Alliance CTAP 2.2](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html), [SimpleWebAuthn](https://simplewebauthn.dev/), [passkeys.dev](https://passkeys.dev/docs/reference/specs/)
