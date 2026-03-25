# API Keys

Generate and manage API keys for programmatic access.

## Schema Additions

**ApiKey**
| Field     | Type     | Constraints                        |
|-----------|----------|------------------------------------|
| id        | string   | primary key                        |
| userId    | string   | foreign key -> User, not null      |
| name      | string   | not null                           |
| keyHash   | string   | unique, not null (SHA-256 of key)  |
| prefix    | string   | not null (first 8 chars of key)    |
| scopes    | string   | nullable (JSON array of scopes)    |
| expiresAt | datetime | nullable                           |
| lastUsedAt| datetime | nullable                           |
| createdAt | datetime | default now                        |

## Key Format

API keys follow the format: `{prefix}_{secret}`
- Prefix: 8 chars (stored in plaintext for identification)
- Secret: 32 bytes crypto-random, base62 encoded
- Full key example: `ak_live_x7K9mP2vL5nQ8wR3tY6uI1oP4sD7fG`
- The full key is shown ONCE at creation — only the hash is stored

## Endpoints

**POST /api/auth/api-keys**
- Requires valid session (Bearer token)
- Body: `{ name, scopes?, expiresAt? }`
- Generate key, store SHA-256 hash + prefix
- Return `{ id, name, key, prefix, scopes, expiresAt, createdAt }`
- `key` is the full plaintext key — shown only at creation

**GET /api/auth/api-keys**
- Requires valid session (Bearer token)
- Return all API keys for the user (without key or hash)
- Each entry: `{ id, name, prefix, scopes, expiresAt, lastUsedAt, createdAt }`

**DELETE /api/auth/api-keys/:keyId**
- Requires valid session (Bearer token)
- Delete the specified key if it belongs to the current user
- Return 200

**API Key Authentication (middleware)**
- Check for `Authorization: Bearer ak_...` header or `X-API-Key` header
- Extract prefix from the key
- Look up matching ApiKey records by prefix
- Hash the provided key with SHA-256 and compare to stored keyHash
- If valid and not expired: set the authenticated user from userId, update lastUsedAt
- If invalid or expired: return 401

## Implementation Rules

- Never store the plaintext API key — only store the SHA-256 hash
- The prefix is stored separately for efficient lookups (avoids hashing every request against all keys)
- Use SHA-256 (not bcrypt) for API key hashing — keys are high-entropy so brute force is not practical, and lookup speed matters
- Update `lastUsedAt` on each successful authentication
- Scopes are optional — if present, they restrict what the key can access
- A user should have a max of 25 active API keys
- API key auth should work alongside session auth (check both)

## Best Practices (Industry Consensus)

- **Key format: `prefix_secret`** following Stripe's well-established pattern (`sk_live_...`, `sk_test_...`). The prefix encodes environment and key type, making keys visually identifiable and enabling secret-scanning tools (e.g., GitHub secret scanning) to detect leaked keys by pattern.
- **Use SHA-256 for hashing, not bcrypt.** API keys are high-entropy (256-bit random), so brute-force is not practical. SHA-256 provides O(1) lookup speed, while bcrypt's intentional slowness would create unacceptable latency on every API request.
- **Prefix stored in plaintext for O(1) lookup.** On authentication, extract the prefix, query matching rows, then SHA-256 the full key and compare. This avoids hashing against every key in the database.
- **Show the full key only once at creation.** After creation, only the prefix and metadata are retrievable. Stripe, GitHub, and all major providers follow this pattern. Prompt the user to copy it immediately.
- **Max 25 keys per user.** Prevents key sprawl and limits blast radius. Stripe and GitHub both impose per-user/per-org limits on active tokens.
- **Scopes for least-privilege access.** Each key should declare what it can access (e.g., `read:users`, `write:billing`). Reject requests outside the key's scopes with 403.
- **Track `lastUsedAt` for auditing.** Update on each successful authentication. Surface this in the key listing UI so users can identify and revoke unused keys. Stripe shows last-used timestamps in the dashboard.
