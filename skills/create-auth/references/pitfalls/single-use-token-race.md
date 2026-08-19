# Pitfall: Single-use tokens must be consumed atomically

Every "check then consume" sequence on a single-use credential is a race. Two concurrent requests both find the token unconsumed, both pass the check, and the token is redeemed twice — two sessions minted from one magic link, one reset link changing the password twice, a 2FA challenge accepted after it already completed. Duplicate form submissions and client retries trigger this in practice, not just attackers.

Consume with a single conditional write and gate on the affected-row count. This works on every SQL database without locks or serializable transactions — the database serializes the writes for you.

```typescript
// BAD — find, check, then delete: two requests interleave between the
// findUnique and the delete, and both mint a session
const row = await db.magicLinkToken.findUnique({ where: { tokenHash } });
if (!row || row.expiresAt < new Date()) return unauthorized();
await db.magicLinkToken.delete({ where: { id: row.id } });
return createSession(row.email);

// GOOD — read for data if needed, but the *gate* is one conditional write;
// exactly-one-row-changed decides who wins
const row = await db.magicLinkToken.findUnique({ where: { tokenHash } });
if (!row) return unauthorized();
const consumed = await db.magicLinkToken.deleteMany({
  where: { id: row.id, expiresAt: { gt: new Date() } },
});
if (consumed.count !== 1) return unauthorized(); // a concurrent request got here first
return createSession(row.email);
```

In raw SQL the read and the gate collapse into one statement: `DELETE FROM magic_link_token WHERE token_hash = $1 AND expires_at > now() RETURNING email` — proceed only if a row came back. For tokens that must be retained for audit, use `UPDATE … SET consumed_at = now() WHERE token_hash = $1 AND consumed_at IS NULL` and check the row count.

This applies to every single-use credential: password-reset tokens, magic links, email/phone OTP codes, 2FA sign-in challenges, WebAuthn challenges, organization invitations, OAuth authorization codes, and refresh-token rotation.

The same race lives in a KV store, with the same fix. A challenge or token kept in Redis/KV (`PasskeyChallenge` may live there; the `email-verify:{sha256(token)}` pattern in `references/features/kv-cache.md`) must be consumed with one read-and-delete operation — `getAndDelete` (Redis `GETDEL`, `DELETE … RETURNING` on a table-backed store) — never `get` followed by `delete`. When the presented value *is* the lookup key — a magic-link or reset token hash, an OAuth `state`, a WebAuthn challenge — consume first and treat "nothing came back" as the failure: a fresh options call or a fresh link is the remedy, and there is nothing to guess. A **low-entropy code keyed by its target** (`otp:{target}`, a 6-digit SMS/email code) is different: `increment` the attempt counter first, compare, and consume with `getAndDelete` (or the conditional delete) **only on a match** — consuming on every presentation would let a single typo burn the owner's code, and the attempt cap, not the consume, is what bounds guessing. Counters that gate anything — OTP attempts, lockout counts, rate-limit buckets — are the read-modify-write version of the bug: `get` → compare → `set(count + 1)` lets a burst of concurrent requests all read the same stale count and all pass. Bump them with an atomic `increment` and decide on the value it returns (`INCR` + `EXPIRE` set only when the key is created; `INSERT … ON CONFLICT DO UPDATE SET value = value + 1 RETURNING value`).

Ordering matters as much as atomicity. Run every check that does not depend on the token — new-password policy, field shapes, required fields, size limits — before the conditional write, and do the state mutation immediately after it. Anything fallible in between spends a single-use credential on a user error: a too-short new password burns the reset code, and the user needs a whole new email to try again. This is a rule about ordering, not a licence to keep the token alive on failure — a wrong or expired code still counts against the attempt cap and still dies at the ceiling.

A related but distinct rule covers proofs rather than counts: when the thing being recorded is *that a value was verified* — a phone number, a domain, an email — and the verification made an external round trip, the write must also name the value proved — see `references/pitfalls/async-proof-value-binding.md`.
