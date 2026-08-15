# Pitfall: An asynchronous proof must be written back against the value it proved

Verification that leaves the process and returns — a DNS TXT lookup, fetching a `.well-known` file, an SMS or email round trip, a webhook echo, a third-party KYC or card check — opens a window between the read that decided *what* to prove and the write that records *that it was proven*. The attacker usually controls the endpoint being called, so they can hold that window open for the full resolver or HTTP timeout and edit the record mid-flight. `UPDATE … SET verified = true WHERE id = ?` then stamps the proof onto whatever the row says now, which may be a value nobody proved.

Name the proven value in the `WHERE` clause, and guard on the row's **immutable primary key** — never on a re-registrable business key (`providerId`, slug, username, tenant subdomain). Deleting the record mid-flight and re-registering a fresh one under the same business key is the same attack with one extra step, and a business-key guard would bless the attacker's replacement row.

```typescript
// BAD — the DNS answer is about `claim.domain` as it was 20 seconds ago
const claim = await db.domainClaim.findUnique({ where: { id } });
await verifyDnsTxt(claim.domain, claim.challenge);  // attacker edits the row during this await
await db.domainClaim.update({ where: { id: claim.id }, data: { verified: true } });

// GOOD — the write names the exact value the external check answered for
const claim = await db.domainClaim.findUnique({ where: { id } });
await verifyDnsTxt(claim.domain, claim.challenge);
const proved = await db.domainClaim.updateMany({
  where: { id: claim.id, domain: claim.domain },  // immutable id AND the proven value
  data: { verified: true, verifiedAt: new Date(), challenge: null },
});
if (proved.count !== 1) throw new HttpError(409, 'Record changed during verification');
```

In raw SQL: `UPDATE domain_claim SET verified = true, verified_at = now(), challenge = NULL WHERE id = $1 AND domain = $2 RETURNING id`, with `$2` the exact string the external check answered for. Keep `verified` itself **out** of the guard — it is a monotone latch, not a contended resource, and including it turns two honest concurrent proofs of the same unchanged value into a spurious conflict. An edit to an unrelated column must not invalidate the proof either, so guard only the fields the proof was actually about. That holds while the write merely *records* a proof; when winning the flip is itself what authorizes a destructive follow-on — stripping credentials that predate the proof — the flag belongs in the guard and exactly-one semantics are the point (see `references/pitfalls/pre-account-hijack-strip.md`).

Zero rows changed means the subject mutated: discard the proof and return `409`. Do not re-read and re-issue the write — the proof is stale, and a retry loop just re-opens the window. The caller must restart verification with a fresh challenge and a fresh external check.

Two companion rules keep the flag honest:

- Every write path that changes the proven value must clear `verified`, `verifiedAt` and any outstanding challenge **in the same statement** that changes it.
- One boolean must never cover a list of values. Store the proof per normalized value — a row per `(subjectId, value)` — so a value edited or added later cannot inherit an older value's proof.

Distinct from `references/pitfalls/single-use-token-race.md`: that guard is about consuming a credential once, this one is about binding a proof to the value it proved — a subject-field guard, not a consumed-state guard.
