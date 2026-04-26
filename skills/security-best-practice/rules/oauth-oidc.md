---
title: OAuth 2.0 / OIDC Security
impact: HIGH
tags: oauth, oidc, pkce, state, redirect-uri, account-takeover, token-exchange
---

## OAuth 2.0 / OIDC Security

**Impact: HIGH**

OAuth bugs are the most common source of modern account takeover. The protocol is flexible; the specific choices you make decide whether "sign in with Google/GitHub" becomes a universal takeover primitive.

### Checklist

| Check | Requirement |
|-------|------------|
| Authorization Code + PKCE | Always use the **Authorization Code** flow. Always include **PKCE** (`code_challenge`, `S256`) even for confidential (server-side) clients — OAuth 2.1 and 2024 Security BCP mandate this. Never use the Implicit flow (deprecated) or Resource Owner Password Credentials. |
| `state` parameter | Always include a cryptographically random `state` (≥ 128 bits) on the authorization request. Bind it to the session (store in cookie or server-side). Verify on callback — reject if missing or mismatched. Stops CSRF on the OAuth callback. |
| `nonce` (OIDC) | For OIDC flows, include `nonce` in the auth request and verify it in the returned ID token. Stops ID-token replay. |
| Redirect URI — exact match | The `redirect_uri` registered with the provider must be **exact string match**, no wildcards, no substring. An attacker who can register `https://example.com.evil.com` when the match is a prefix gets the code. |
| Redirect URI allow-list | If you proxy / accept a dynamic `redirect_uri` (e.g. for preview deploys), validate against a strict allow-list with full URL equality. |
| Code one-time use | Authorization codes must be redeemed exactly once and expire within ~60s. Invalidate on reuse — reuse signals interception. |
| Client secret | Server-side only — never in SPA / mobile bundles. Use PKCE-only (public client) for browser and native apps. Rotate on suspected leak. |
| Token storage | Access + refresh tokens from IdPs must be encrypted at rest (AES-GCM with KMS key) if you persist them. Don't log them. |
| Account linking — verified email only | When linking an OAuth account to a local account by email, **require the IdP to mark the email as verified** (`email_verified: true` for Google/OIDC, GitHub's verified-emails API). Otherwise an attacker registers an IdP account with victim's email and takes over. |
| Account linking — re-auth | Require the user to re-authenticate (password or existing session in good standing) before linking a new IdP, and before unlinking the **only** sign-in method. |
| Provider identity binding | Key the link on `(provider, provider_account_id)`, not the email. Emails change; provider IDs don't. |
| `email` from IdP is not authoritative | Treat the IdP-provided email as unverified unless `email_verified=true` is explicit. Some providers (e.g. Azure AD personal accounts) allow unverified emails. |
| ID token signature | Verify `iss`, `aud`, `exp`, `iat`, and signature (use the provider's JWKS). Cache JWKS with a sensible TTL and handle key rotation. |
| `scope` minimization | Request the minimum scopes. Review on each provider update — `profile` + `email` is enough for sign-in; don't request `offline_access` unless refresh is needed. |
| Consent / incremental auth | Reauthorize ("incremental consent") for elevated scopes. Don't silently acquire drive/contact/repo scopes on first sign-in. |
| Logout propagation (RP-initiated / back-channel) | On logout, revoke refresh tokens at the IdP when possible. For SSO-heavy apps, support back-channel logout (OIDC Front-Channel / Back-Channel Logout). |
| Dynamic provider registration | Don't enable dynamic client registration at your IdP endpoint unless strictly required — it's a footgun. |
| "Sign in with X" button CSRF (login CSRF) | The login callback itself is CSRF-exposed if `state` isn't bound. See `csrf-protection.md`. |
| Open-redirect via `redirect_uri` trick | The `redirect_uri` parameter on your own authorize endpoint is a classic open-redirect vector. Validate it server-side before sending the user to the IdP. |

### Incorrect

```typescript
// BAD: no state, no PKCE, implicit flow
const url = `https://accounts.google.com/o/oauth2/v2/auth?response_type=token&client_id=${id}&redirect_uri=${cb}`;
```

```typescript
// BAD: account linking on unverified email
async function onGithubCallback(profile) {
  const existing = await db.user.findUnique({ where: { email: profile.email } });
  if (existing) {
    await db.account.create({ data: { userId: existing.id, provider: 'github', providerAccountId: profile.id } });
  }
}
```

### Correct

```typescript
// GOOD: authorization code + PKCE + state + nonce
const state = crypto.randomBytes(32).toString('hex');
const nonce = crypto.randomBytes(32).toString('hex');
const verifier = crypto.randomBytes(32).toString('base64url');
const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
await setTempCookies({ state, nonce, verifier }); // HttpOnly, Secure, Path=/auth/callback

const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
url.search = new URLSearchParams({
  response_type: 'code',
  client_id,
  redirect_uri, // EXACT match to what's registered
  scope: 'openid email profile',
  state,
  nonce,
  code_challenge: challenge,
  code_challenge_method: 'S256',
}).toString();
```

```typescript
// GOOD: verified-email-only linking, keyed by provider account id
async function onGithubCallback(profile, verifiedEmails) {
  const emailVerified = verifiedEmails.some(e => e.email === profile.email && e.verified);
  const existingLink = await db.account.findUnique({
    where: { provider_providerAccountId: { provider: 'github', providerAccountId: profile.id } },
  });
  if (existingLink) return signInAsUser(existingLink.userId);

  if (!emailVerified) {
    // Don't auto-link. Sign in as a new user or prompt for manual link.
    return createNewUser({ email: profile.email, emailVerified: false });
  }
  const existing = await db.user.findUnique({ where: { email: profile.email } });
  if (existing) {
    await requireReAuth(); // step up before linking
    await db.account.create({
      data: { userId: existing.id, provider: 'github', providerAccountId: profile.id },
    });
  }
}
```

### References

- [OAuth 2.0 Security Best Current Practice (draft-ietf-oauth-security-topics)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [OAuth 2.1 (draft)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1)
- [RFC 7636 — PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 8252 — OAuth 2.0 for Native Apps (BCP 212)](https://datatracker.ietf.org/doc/html/rfc8252)
- [OIDC Core — `nonce`](https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes)
- [Dirk Balfanz / Google — "Pre-Account Takeover" pattern via OAuth account linking](https://www.descope.com/blog/post/account-takeover-oauth)
