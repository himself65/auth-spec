# Pitfall: A secret minted for one purpose must be unredeemable by every other

Auth systems mint many short-lived secrets — OAuth `state`, magic-link and reset tokens, verification codes, WebAuthn challenges, sealed cookies, proxy payloads — and two features that share a **store** or a **key** are one lookup away from accepting each other's secrets. The token itself is valid and unexpired; it is simply being presented to the wrong door. Atomic consumption (`references/pitfalls/single-use-token-race.md`) does not help: the wrong door consumes it exactly once.

## Shared store: the purpose is part of the key

better-auth GHSA-965c-763c-88jm (critical, fixed 1.7.7): OAuth state records and Magic Link tokens lived in one verification table, both looked up by a bare identifier. An unauthenticated attacker started an OAuth sign-in naming the victim's email, received the `state` value, and presented it to the Magic Link verify endpoint — which found a live row, consumed it, and signed the attacker in as the victim (or created a fresh account marked `emailVerified = true` for an unused address, which then defeated the pre-account-hijack strip). The attacker never read the mailbox and never finished an OAuth callback.

```typescript
// BAD — one table, one namespace: any live row is accepted by any flow
const row = await kv.getAndDelete(token);            // state? magic link? challenge?
if (row) return signInByEmail(JSON.parse(row).email);

// GOOD — the consumer names its purpose; a value minted elsewhere cannot resolve
const row = await kv.getAndDelete(`magic-link:${sha256(token)}`);
if (!row) return unauthorized();
```

Rules:

- **Every lookup of a stored secret carries a purpose the *consumer* supplies** — a key prefix (`magic-link:`, `oauth-state:`, `passkey-challenge:`), a `purpose` column matched in the `WHERE` clause (the core `VerificationToken` table does this), or a dedicated table per flow (the `MagicLinkToken` table does this). Never read the purpose back out of the stored row or the presented value and trust it; the caller decides what it is looking for.
- **Hashing must never drop the purpose.** `magic-link:{sha256(token)}` (prefix outside the hash) and `sha256("magic-link:" + token)` (prefix inside) both keep flows apart; a hashing layer that stores `sha256(token)` alone — a custom hasher, a global "hash all identifiers" setting applied after the prefix was stripped — silently re-merges the namespaces. Upstream hit exactly this: Magic Link `storeToken: "hashed"` combined with global identifier hashing made both flows store the same digest, and the fix requires custom hashers to hash the prefixed value.
- **Purpose isolation also covers creation side-effects.** A wrongly-redeemed token that can *create* an account must not be able to stamp a proof flag (`emailVerified`) the flow never established — `disableSignUp` was explicitly called insufficient upstream, because existing accounts were still taken over.

## Shared key: what you seal for one purpose must not open for another

better-auth GHSA-r4xp-prcw-77qf (high, fixed 1.7.7): the OAuth Proxy plugin accepted any profile payload it could decrypt as provider-verified. With cookie-backed state, the same global secret encrypted the state cookie — which contains caller-chosen fields — and handed it to whoever started a sign-in. The sealing endpoint was therefore an **encryption oracle**: the attacker asked it to seal data shaped like a profile for the victim's email, and the proxy callback opened it as genuine. Implicit account linking did the rest.

Authenticated encryption proves *who sealed a blob*, never *what the blob is*. If two features seal with one key and either of them will seal content the caller influenced, the other feature can be fed forgeries.

- **Derive one subkey per purpose** from the root secret — `HKDF(root, info = "auth:oauth-state:v1")`, `"auth:session-cookie:v1"`, `"auth:proxy-profile:v1"` — and use the root only for derivation. A feature that is configured with its own secret (a proxy shared across environments) must refuse to start when that secret equals the global one.
- **Put the message type inside the authenticated data** as well (an AEAD associated-data label, or a signed `typ` field checked first), so a blob that somehow crosses keys still fails closed.
- **A payload that asserts an identity must come from a party that proved it** — a provider callback, a token response, a signed assertion verified against that provider's keys. "It decrypted" is not that proof.

## Checklist

- List every place the server mints a secret and every place it redeems one. Each redeemer must be unable to resolve a secret minted by any other minter — by key prefix, `purpose` match, separate table, or separate subkey.
- Grep for the global secret: each use should be a key-derivation call, not a direct encrypt/sign.
- Add a test per pair that matters: an OAuth `state` presented to magic-link verify, reset-token verify, and passkey verify must each fail.
