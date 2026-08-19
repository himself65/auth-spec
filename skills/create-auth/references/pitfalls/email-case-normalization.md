# Pitfall: Canonicalize emails at the boundary — then validate the canonical string

Emails arrive in whatever casing the user's keyboard produced — `Foo@Example.com` from mobile autocapitalize, `foo@example.com` everywhere else. If endpoints store and compare them as-received: the same mailbox becomes two accounts (sign-up), a registered user can't sign in (exact-match lookup misses), OTP and magic-link verification fails for users who typed a different casing than they registered with, and an attacker can register `Victim@example.com` alongside `victim@example.com` to confuse flows that match case-insensitively elsewhere.

Compensating per-query with `LOWER()` / `ILIKE` / `citext` is fragile: every new query must remember to do it, plain indexes stop being used, and feature endpoints added later (OTP, invitations) silently miss the convention.

Normalize once, at the API boundary, on **every** path an email enters — sign-up, sign-in, OTP send *and* verify, magic-link send, password-reset request, invitation create *and* accept — and store only the normalized form.

```typescript
// BAD — stored as typed; the sign-in lookup later exact-matches and misses
await db.user.create({ data: { email: req.body.email, ...rest } });

// GOOD — one helper, called in every handler that receives an email: canonicalize
// (NFKC, trim, lowercase) *first*, validate the result, store and mail that string
const normalizeEmail = (raw: string) => raw.normalize('NFKC').trim().toLowerCase();
const email = normalizeEmail(req.body.email);
// Strict lowercase dot-atom grammar — nothing a mailer can re-parse into another recipient
const EMAIL_SHAPE = /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@[a-z0-9-]+(?:\.[a-z0-9-]+)*$/;
const isValidEmail = (e: string) => e.length <= 254 && EMAIL_SHAPE.test(e);
if (!isValidEmail(email)) return res.status(400).json({ error: 'Invalid email or password' });
```

**Order matters: canonicalize, then validate — never the reverse (CWE-180).** Unicode has characters that are not U+0040 `@` but fold to it under NFKC — in Unicode 16 exactly two: the fullwidth `＠` (U+FF20) and the small `﹫` (U+FE6B). `victim@example.com＠attacker.example` passes an "exactly one `@`" check on the raw bytes; a mail library that normalizes recipient addresses on its own then sees two separators and can route the sign-in link to a mailbox you never validated (the advisory says most SMTPUTF8-capable senders normalize; nodemailer itself punycodes the trailing label instead of folding — the rule holds either way, because you cannot know what the transport will do). Auth.js shipped this as GHSA-7rqj-j65f-68wh, rated account takeover: a link requested under a confusable spelling of the victim's address is deliverable to the attacker's domain. Apply NFKC (`String.prototype.normalize`, `unicodedata.normalize`, `java.text.Normalizer`) *before* trim and lowercase and before the `@` count and every other shape check, so a homoglyph separator is either folded into a real `@` and rejected by the count, or rejected by the ASCII rule below. The property to preserve is simple: **the string you validated is the string you store and the string you hand to the mailer**, and nothing downstream may see a different one. Where the standard library has no NFKC (Go, Rust), reject every non-ASCII byte that survives trim + lowercase instead — the homoglyphs are all non-ASCII — and say so in a comment; supporting internationalized addresses in those languages means taking a normalization dependency, not skipping the step.

Lowercasing is not validation. `attacker@corp.com@evil.com` survives `trim().toLowerCase()` untouched, and any later `email.split('@')[1]` reads its domain as `corp.com` even though the mail is delivered to `evil.com`. And "printable ASCII" is not validation either: RFC 5322 lets a mailer *re-parse* what you accepted — nodemailer turns `a(b)@example.com` into `a@example.com`, `x<attacker@evil.example>` into `attacker@evil.example`, and `a,b@example.com` into two recipients — so three spellings become one mailbox and one spelling becomes someone else's. Reject the address at the boundary against a **strict grammar** — a lowercase RFC 5322 dot-atom local part (`[a-z0-9!#$%&'*+/=?^_`{|}~-]` runs joined by single dots), one `@`, dot-separated `[a-z0-9-]` domain labels, ≤ 254 characters; no `( ) < > [ ] : ; \ , "` or space anywhere, no control characters, no IP-literal domain, and no non-ASCII unless the project deliberately supports internationalized email — so a malformed or re-parseable address is never persisted in the first place. Lowercase-only on purpose: the validator then also fails closed on any input that skipped the canonicalizer. If anything downstream ever derives a trust decision from the domain (routing a corporate domain to an organization, say), run both sides through that same parser and match on label boundaries — `d === base || d.endsWith('.' + base)` — because a bare `endsWith(base)` accepts `notacme.com` for `acme.com`, and suffix matching means the apex grants every subdomain under it.

RFC 5321 technically allows a case-sensitive local part; no real mail system honors it, and every major auth provider lowercases. If the project already has mixed-case rows, backfill them (and resolve duplicates) before relying on the lowercased unique index.
