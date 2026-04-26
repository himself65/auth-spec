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
| Recovery codes | Generate 8–10 one-time codes (≥ 64 bits entropy each) at MFA enrollment. Show once. Store **hashed** server-side. Invalidate after use. |
| Account recovery ≠ "contact support" as a bypass | Document recovery: identity verification + cooling-off period. Never let support bypass MFA without verification + audit log. Advertise the delay publicly so attackers know it's not exploitable. |
| MFA enrollment requires re-auth | Require password / current-session-in-good-standing to add or remove a factor. Send a confirmation email. |
| Rate-limit verification | See `rate-limiting.md` — MFA verification must be throttled per account and per IP. Lock the factor after ~5 failed codes. |
| Audit log | Log MFA enroll/remove, factor use, recovery-code use, "sign out all other sessions", and email them to the user. |

### Checklist — TOTP (RFC 6238)

| Check | Requirement |
|-------|------------|
| Secret length | ≥ 160 bits (20 bytes) of entropy, base32-encoded. |
| Algorithm | SHA-1 is still the RFC default for compatibility; SHA-256 is fine if your authenticator app supports it. |
| Time window | Accept ±1 time step (30s default) to tolerate clock drift. No more — wider windows weaken security. |
| Replay prevention | Track the last successfully used counter per user and reject codes ≤ that counter. Without this, an attacker who sees one code can reuse it within its window. |
| Secret storage | Encrypted at rest. Never returned to the client after enrollment. |
| Enrollment confirmation | Require the user to enter a code from the QR before activating TOTP — otherwise users lock themselves out. |

### Checklist — WebAuthn / Passkeys

| Check | Requirement |
|-------|------------|
| Relying Party ID | `rpId` must be your registrable domain (e.g. `example.com`, not `auth.example.com`). Never set it to a public suffix. |
| `origin` check | On verification, the returned `clientDataJSON.origin` must be in your allow-list of exact origins. No wildcards. |
| Challenge | Server-generated random challenge (≥ 128 bits). One-time use. Bound to the session / short TTL (≤ 5 min). |
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
