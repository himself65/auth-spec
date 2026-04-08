# Pitfall: API key hash/generation must not be duplicated

The API key feature has two consumers of the hash function: the key management endpoints (create) and the authentication middleware (verify). If the hash function is copy-pasted into both files, they can drift — e.g., one gets updated to a new algorithm while the other doesn't, silently breaking authentication.

Extract all shared logic into a single utility module:

```typescript
// BAD — duplicated across router and middleware
// api-key-router.ts
async function hashApiKey(key: string) {
  /* SHA-256 */
}

// api-key-auth.ts
async function hashApiKey(key: string) {
  /* SHA-256 — same code, will drift */
}

// GOOD — single source of truth
// api-key-utils.ts
export async function hashApiKey(key: string) {
  /* SHA-256 */
}
export function generateApiKey() {
  /* ... */
}
export const API_KEY_PREFIX = "...";

// api-key-router.ts
import { hashApiKey, generateApiKey } from "./api-key-utils";

// api-key-auth.ts
import { hashApiKey, API_KEY_PREFIX } from "./api-key-utils";
```

This also applies to the prefix constant and key generation function. Any change to the key format must take effect in both creation and verification simultaneously.
