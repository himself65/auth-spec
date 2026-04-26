---
title: Short-Lived Token Lifecycle
impact: HIGH
tags: email-verification, password-reset, magic-link, otp, invitation, token, one-time-use
---

## Short-Lived Token Lifecycle

**Impact: HIGH**

Email-verification links, password-reset links, magic links, OTPs, and invitation tokens are all variants of the same primitive: a server-issued token a user presents to perform an action. Getting any of them wrong turns "forgot my password" into "take over any account".

### Checklist — Common

| Check | Requirement |
|-------|------------|
| Generation | Cryptographically random, ≥ 128 bits entropy (32 hex / 22 base64url). For numeric OTP: 6–8 digits. Never time-derived, sequential, or predictable. |
| Storage | Store a **hash** of the token (SHA-256) server-side, not the raw token. Compare using constant-time equality. A DB dump must not yield reusable tokens. |
| One-time use | Mark consumed on first successful use. Subsequent attempts fail even within the TTL. |
| Short TTL | Reset: ≤ 30 min. Email verification: ≤ 24 h. Magic link: ≤ 15 min. OTP: ≤ 10 min (shorter is better). Invitations: ≤ 7 days. Enforce server-side — don't trust a JWT `exp`. |
| Scope binding | Token stores the `userId` (and `action` — "reset", "verify", "invite"). Reject cross-type use (a "verify" token cannot complete a reset). |
| Invalidate on state change | Password change / MFA change / email change must invalidate **all** outstanding tokens for that user. |
| Invalidate siblings on use | Using one reset token invalidates all other pending reset tokens for that account. |
| Delivery channel binding | A token emailed to `foo@example.com` should only be usable to act on the account whose current email is `foo@example.com` at consumption time, not just at issuance. Otherwise an attacker who emails-change mid-flow races the token. |
| Rate-limit issuance | See `rate-limiting.md`. Cap requests per account, per IP, and global — both to prevent enumeration and to prevent email/SMS bombardment. |
| Constant-time lookup | Lookup by token-hash returns the same latency whether found or not. Don't branch on existence before hashing. |
| Don't log tokens | No raw tokens in application logs, error logs, or third-party error trackers. Log only the token ID (a non-sensitive UUID) for support. |
| Don't put tokens in URL fragments that then POST | A token in `?t=...` ends up in browser history, Referer, and analytics. Mitigate: strip from `Referer` (`Referrer-Policy: no-referrer` on reset pages), redirect away from the token URL once consumed, and keep TTL short. |

### Checklist — Password Reset

| Check | Requirement |
|-------|------------|
| Response uniformity | "If an account exists with that email, we sent a reset link" — identical response whether or not the account exists. See `error-handling.md`. |
| Invalidate sessions on completion | On successful reset, revoke all active sessions for that user except (optionally) the current one. |
| Require MFA after reset | If the account has MFA, enforce it after password reset before issuing a session. See `mfa-passkeys.md`. |
| No password leak in the URL | The link carries the reset token, not the new password. The new password is submitted via POST over HTTPS. |
| Notify on completion | Send an email to the user's current address when a reset completes. Include IP/UA and a "wasn't me" link. |

### Checklist — Email Verification / Change

| Check | Requirement |
|-------|------------|
| Pending email change | Store the new email separately until verified. Don't update the primary email until the new address confirms. |
| Verify both sides on email change | Send a "you requested to change" notice to the **old** email (with a cancel link), and a "confirm" link to the **new** email. Otherwise an attacker who temporarily controls the session can silently change email. |
| Email change invalidates tokens/sessions | On email change completion, invalidate all sessions and pending reset/verification tokens; require re-login. |

### Checklist — Magic Link

| Check | Requirement |
|-------|------------|
| Same-device requirement (optional) | Consider binding the link to a device cookie set at request time. The link only works in the same browser that requested it. Blocks phishing where the attacker gets the user to click their link. |
| Short TTL | ≤ 15 min. Magic links should not outlive their intended use. |
| Signal phishing | If a user opens a magic link they didn't request, show "You're signing in as X" and require an explicit click (not auto-login). |
| Magic link + passkey | For security-sensitive apps, disable magic link if passkeys are enrolled. |

### Checklist — OTP / Verification Codes

| Check | Requirement |
|-------|------------|
| Length | 6 digits is the UX floor; 8 digits for higher-value flows. With a 5-attempt lockout, 6 digits is tolerable. |
| Attempt cap | Invalidate the code after ~5 wrong attempts. Don't just block further requests — the code must be **dead**. |
| Single outstanding code | Issuing a new code invalidates the previous one. |
| Channel | Email/authenticator > SMS. SMS is vulnerable to SIM swap and pumping (see `rate-limiting.md`). |
| Cross-channel prevent | A code sent via email is not usable to verify a phone number, and vice versa. Bind `(code, target, channel)`. |

### Incorrect

```typescript
// BAD: raw token in URL stored in plain text, no expiry, no one-time use
const token = crypto.randomUUID();
await db.resetToken.create({ data: { token, userId } });
sendEmail(`https://example.com/reset?token=${token}`);

// Later — found it? Great, let them set a password.
async function confirmReset(token, newPassword) {
  const row = await db.resetToken.findUnique({ where: { token } });
  if (!row) throw new Error('invalid');
  await setPassword(row.userId, newPassword);
  // row not deleted — token is reusable forever
}
```

### Correct

```typescript
// GOOD: hashed storage, one-time, short TTL, invalidated on use, sessions revoked
async function issueReset(email) {
  const user = await db.user.findUnique({ where: { email } });
  if (user) {
    const raw = crypto.randomBytes(32).toString('base64url');
    const hash = crypto.createHash('sha256').update(raw).digest('hex');
    await db.resetToken.deleteMany({ where: { userId: user.id } }); // invalidate siblings
    await db.resetToken.create({
      data: { userId: user.id, tokenHash: hash, expiresAt: new Date(Date.now() + 30 * 60_000) },
    });
    await sendEmail(user.email, `https://example.com/reset?t=${raw}`);
  }
  // Always same response:
  return { status: 'ok' };
}

async function confirmReset(raw, newPassword) {
  const hash = crypto.createHash('sha256').update(raw).digest('hex');
  const row = await db.resetToken.findUnique({ where: { tokenHash: hash } });
  if (!row || row.consumedAt || row.expiresAt < new Date()) {
    throw new HttpError(400, 'Invalid or expired link');
  }
  await db.$transaction([
    db.resetToken.update({ where: { id: row.id }, data: { consumedAt: new Date() } }),
    db.user.update({ where: { id: row.userId }, data: { passwordHash: await hashPassword(newPassword) } }),
    db.session.deleteMany({ where: { userId: row.userId } }),
    db.resetToken.deleteMany({ where: { userId: row.userId, consumedAt: null } }),
  ]);
  await notifyPasswordChanged(row.userId);
}
```

### References

- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [OWASP Authentication Cheat Sheet — Password Recovery](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#password-reset)
- [NIST SP 800-63B — Memorized Secret Verifier Recovery](https://pages.nist.gov/800-63-4/sp800-63b.html)
