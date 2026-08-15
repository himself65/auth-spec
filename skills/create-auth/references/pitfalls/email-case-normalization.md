# Pitfall: Normalize email casing at the boundary, not at query time

Emails arrive in whatever casing the user's keyboard produced — `Foo@Example.com` from mobile autocapitalize, `foo@example.com` everywhere else. If endpoints store and compare them as-received: the same mailbox becomes two accounts (sign-up), a registered user can't sign in (exact-match lookup misses), OTP and magic-link verification fails for users who typed a different casing than they registered with, and an attacker can register `Victim@example.com` alongside `victim@example.com` to confuse flows that match case-insensitively elsewhere.

Compensating per-query with `LOWER()` / `ILIKE` / `citext` is fragile: every new query must remember to do it, plain indexes stop being used, and feature endpoints added later (OTP, invitations) silently miss the convention.

Normalize once, at the API boundary, on **every** path an email enters — sign-up, sign-in, OTP send *and* verify, magic-link send, password-reset request, invitation create *and* accept — and store only the normalized form.

```typescript
// BAD — stored as typed; the sign-in lookup later exact-matches and misses
await db.user.create({ data: { email: req.body.email, ...rest } });

// GOOD — one helper, called in every handler that receives an email
const normalizeEmail = (raw: string) => raw.trim().toLowerCase();
const email = normalizeEmail(req.body.email);
```

Lowercasing is not validation. `attacker@corp.com@evil.com` survives `trim().toLowerCase()` untouched, and any later `email.split('@')[1]` reads its domain as `corp.com` even though the mail is delivered to `evil.com`. Reject the address at the boundary — exactly one `@`, a non-empty local part, and a host part with no `/`, `\`, `:`, whitespace, or trailing dot — so a malformed address is never persisted in the first place. If anything downstream ever derives a trust decision from the domain (routing a corporate domain to an organization, say), run both sides through that same parser and match on label boundaries — `d === base || d.endsWith('.' + base)` — because a bare `endsWith(base)` accepts `notacme.com` for `acme.com`, and suffix matching means the apex grants every subdomain under it.

RFC 5321 technically allows a case-sensitive local part; no real mail system honors it, and every major auth provider lowercases. If the project already has mixed-case rows, backfill them (and resolve duplicates) before relying on the lowercased unique index.
