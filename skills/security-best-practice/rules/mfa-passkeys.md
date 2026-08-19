---
title: MFA, TOTP, Passkeys / WebAuthn
impact: HIGH
tags: mfa, 2fa, totp, webauthn, passkey, recovery-codes, step-up, device-trust
---

## MFA, TOTP, Passkeys / WebAuthn

**Impact: HIGH**

MFA closes the "stolen password" attack class — but only if enrollment, recovery, and step-up flows don't themselves become bypasses. Passkeys / WebAuthn are the strongest modern option and should be the default for new systems.

### Checklist — General MFA

| Check | Requirement |
|-------|------------|
| Prefer phishing-resistant factors | Passkeys (WebAuthn) and hardware keys (FIDO2) are phishing-resistant. TOTP and push notifications are **not** — they can be relayed in real time. SMS is the weakest. |
| MFA not bypassable by alternate flows | Ensure **every** sign-in path enforces MFA once enabled: password login, magic link, "forgot password" reset completion, OAuth account linking, API token issuance. A common bug: password reset sets a new session without MFA. |
| Step-up for sensitive actions | Re-verify MFA before: password/email/phone change, MFA factor add/remove, session revocation of others, payment changes, privileged API key creation. |
| Recovery codes | Generate 8–10 one-time codes (≥ 64 bits entropy each) at MFA enrollment. Show once. Store **hashed** server-side. Invalidate after use — remove/mark only the consumed code and leave the remaining entries byte-for-byte untouched; re-serializing the set through a different encoding/encryption than enrollment used corrupts every remaining code. |
| Account recovery ≠ "contact support" as a bypass | Document recovery: identity verification + cooling-off period. Never let support bypass MFA without verification + audit log. Advertise the delay publicly so attackers know it's not exploitable. |
| MFA enrollment requires re-auth | Require password / current-session-in-good-standing to add or remove a factor. Send a confirmation email. |
| Enrollment requires a proven identifier | Adding a factor or a passkey requires the account's **proven primary identifier** — `emailVerified` for an email account, `phoneVerified` for a phone-only one (a row whose `email` is NULL or a non-routable `*.placeholder.invalid` synthetic) — not merely a live session. A session issued at sign-up on an identifier its owner has not yet claimed lets whoever planted it enrol persistence that survives password reset — and a passkey needs no session at all to use. Re-auth and session freshness do not cover this: the planted session is both authentic and fresh. |
| 2FA challenge state | The state between password-ok and second-factor-ok is its own short-TTL (≤ 5 min), single-use credential scoped exclusively to the challenge endpoint — every other endpoint rejects it. Completing the challenge must consume it **atomically** (concurrent verifies mint at most one session) and issue a **new** session token — rotation on the privilege boundary, never an in-place upgrade of the pending token. An expired challenge fails closed. |
| Rate-limit verification | See `rate-limiting.md` — MFA verification must be throttled per account and per IP. A cap scoped to one challenge bounds nothing on its own: the attacker abandons the challenge, signs in again, and draws a fresh budget. Run both — a per-challenge cap (~5 codes, cancels the challenge) **and** an account-scoped failure counter (~10 → 15-min cool-off, 429 + `Retry-After`) incremented atomically and **shared across every enrolled factor** — TOTP, backup codes, emailed/SMS codes — so alternating factors can't multiply the budget. Reset on success. Lock on the sign-in path only, never on re-verification from a valid session. |
| Audit log | Log MFA enroll/remove, factor use, recovery-code use, "sign out all other sessions", and email them to the user. |

### Checklist — TOTP (RFC 6238)

| Check | Requirement |
|-------|------------|
| Secret length | ≥ 160 bits (20 bytes) of entropy, base32-encoded. |
| Algorithm | SHA-1 is still the RFC default for compatibility; SHA-256 is fine if your authenticator app supports it. |
| Time window | Accept ±1 time step (30s default) to tolerate clock drift. No more — wider windows weaken security. |
| Replay prevention | Track the last successfully used counter per user and reject codes ≤ that counter. Without this, an attacker who sees one code can reuse it within its window. |
| Secret storage | Encrypted at rest. Never returned to the client after enrollment. |
| Enrollment confirmation | Require the user to enter a code from the QR before activating TOTP — otherwise users lock themselves out. Gate sign-in's 2FA requirement on the *activated* flag, never on the mere existence of a TOTP-secret row: an abandoned half-enrollment must not demand a factor the user never finished setting up. |

### Checklist — WebAuthn / Passkeys

| Check | Requirement |
|-------|------------|
| Relying Party ID | `rpId` must be your registrable domain (e.g. `example.com`, not `auth.example.com`). Never set it to a public suffix. |
| `origin` check | On verification, the returned `clientDataJSON.origin` must be in your allow-list of exact origins. No wildcards. |
| Challenge | Server-generated random challenge (≥ 128 bits). One-time use — consumed with a single atomic read-and-delete (`DELETE … RETURNING`, KV `getAndDelete`) *before* the ceremony is verified, so two concurrent submissions of one response cannot both mint a session and a failed attempt asks for fresh options. Bound to the session / short TTL (≤ 5 min). |
| User verification (UV) | Require `userVerification: "required"` for passkey-only login; `preferred` if combined with password. Check `flags.uv` on the authenticator data. |
| Attestation | `attestation: "none"` is fine for consumer apps. Use `"direct"` + attestation verification only if you need to restrict to specific authenticator vendors. |
| Credential ID storage | Store the credential's ID, public key, sign counter, transports, and backup-state. Key on `(userId, credentialId)`. |
| Sign counter | If the authenticator reports a counter, reject on counter regression (indicates cloning). Resident-key / synced passkeys often report 0 — don't treat 0 as regression. |
| Multiple passkeys per user | Allow users to register ≥ 2 passkeys (primary + backup). A single-authenticator lockout is a common support issue. |
| Conditional UI / autofill | Use `mediation: "conditional"` for the nicer passkey UX, but never depend on the UI for security — always re-verify server-side. |
| Discoverable credentials (resident keys) | Prefer `residentKey: "required"` for passkey sign-in without a username step. |
| Passkey + password downgrade | Once a user has passkeys, consider disabling password sign-in or gating it behind an extra factor. Otherwise the weakest factor still sets the security level. |

### Incorrect

```typescript
// BAD: TOTP — no replay tracking, too-wide window
function verifyTotp(secret, code) {
  for (let w = -5; w <= 5; w++) { // 10 steps!
    if (totp(secret, nowStep() + w) === code) return true;
  }
  return false;
}
```

```typescript
// BAD: password reset skips MFA
async function confirmReset(token, newPassword) {
  const userId = await consumeResetToken(token);
  await setPassword(userId, newPassword);
  await createSession(userId); // no MFA step — takeover complete
}
```

### Correct

```typescript
// GOOD: TOTP with replay protection and tight window
async function verifyTotp(user, code) {
  for (const step of [nowStep() - 1, nowStep(), nowStep() + 1]) {
    if (step <= user.totpLastUsedStep) continue; // replay
    if (constantTimeEq(totp(user.totpSecret, step), code)) {
      await db.user.update({ where: { id: user.id }, data: { totpLastUsedStep: step } });
      return true;
    }
  }
  return false;
}

// GOOD: password reset requires MFA before new session
async function confirmReset(token, newPassword) {
  const userId = await consumeResetToken(token);
  await setPassword(userId, newPassword);
  await revokeAllSessions(userId);
  if (await userHasMfa(userId)) {
    return { status: 'mfa_required', pendingId: issuePendingMfaSession(userId) };
  }
  return createSession(userId);
}
```

### References

- [OWASP Multifactor Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)
- [RFC 6238 — TOTP](https://datatracker.ietf.org/doc/html/rfc6238)
- [W3C WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/)
- [passkeys.dev — Developer guidance](https://passkeys.dev/)
- [FIDO Alliance — FIDO2 specs](https://fidoalliance.org/specifications/)
