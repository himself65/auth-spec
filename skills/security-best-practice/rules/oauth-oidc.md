---
title: OAuth 2.0 / OIDC Security
impact: HIGH
tags: oauth, oidc, pkce, state, redirect-uri, account-takeover, token-exchange, discovery, issuer-validation, ssrf
---

## OAuth 2.0 / OIDC Security

**Impact: HIGH**

OAuth bugs are the most common source of modern account takeover. The protocol is flexible; the specific choices you make decide whether "sign in with Google/GitHub" becomes a universal takeover primitive.

### Checklist

| Check | Requirement |
|-------|------------|
| Authorization Code + PKCE | Always use the **Authorization Code** flow. Always include **PKCE** (`code_challenge`, `S256`) even for confidential (server-side) clients — OAuth 2.1 and 2024 Security BCP mandate this. Never use the Implicit flow (deprecated) or Resource Owner Password Credentials. Build **every** provider's authorization URL through one shared function that takes the verifier and always emits `code_challenge` + `code_challenge_method=S256`. A provider with its own URL-building branch is where the challenge silently goes missing while the callback still sends `code_verifier` at token exchange — the flow reads as PKCE-protected end to end, passes its tests, and protects nothing. Audit each provider path separately, and assert in a test that the generated URL carries an S256 challenge and never the verifier. |
| `state` parameter | Always include a cryptographically random `state` (≥ 128 bits) on the authorization request. Bind it to the session (store in cookie or server-side). Verify on callback — reject if missing or mismatched. Stops CSRF on the OAuth callback. An unsolicited callback (IdP-initiated login, a user clicking the app tile at their IdP) has no matching record: never accept it — bounce into a fresh, properly bound authorization request instead. |
| Check record bound to the provider | The sealed record holding `state`, `nonce`, the PKCE verifier and `iss` also names the **provider** (and for federated IdPs the issuer and client id) it was minted for, and the callback for provider B rejects a record minted for provider A before anything else is checked. Otherwise, in a multi-provider app that allows linking while signed in, the victim is lured into starting a legitimate flow with a provider whose authorization request the attacker can observe; the attacker lifts `state`, gets a code for *their own* account at the target provider, and drives the victim's browser to that callback — the global cookie matches and the attacker's account is linked to the victim's user (Auth.js GHSA-x445-f3h2-j279, CWE-345/346/940). One sealed cookie whose payload names the provider is enough (that is the Auth.js fix); a server-side record for concurrent flows is keyed by `state` **and** tied to the browser's pre-auth cookie, never reachable by `state` alone. PKCE on every provider is the advisory's mitigation and raises the bar, but an attacker who observes the whole authorization request also sees `code_challenge`, so it does not replace the binding. |
| `nonce` (OIDC) | For OIDC flows, include `nonce` in the auth request and verify it in the returned ID token. Stops ID-token replay. |
| `iss` on the callback (RFC 9207) | Before redirecting, record the provider's `issuer` — from its discovery document or a hardcoded constant, never from anything the authorization request could influence — in the same per-request record that holds `state` and the PKCE `code_verifier`. On callback compare the returned `iss` with **simple string comparison** (RFC 3986 §6.2.1): no case folding, no default-port elision, no trailing-slash trimming, no percent-decoding. Reject if the provider advertises `authorization_response_iss_parameter_supported: true` and `iss` is missing; compare whenever `iss` is present, advertised or not; proceed only when it is both unadvertised and absent — that last branch is what keeps GitHub working, while Google advertises the parameter and sends `iss` today. On mismatch, discard the code without redeeming it and do not render the provider's `error` / `error_description` / `error_uri` — on a mismatch those strings came from the attacker. A valid `state` proves the request was yours; only `iss` proves which provider answered. Stops AS mix-up. For providers that send no `iss`, use a distinct callback path per provider instead (Security BCP §4.4.2.2 — weaker, fallback only). |
| Redirect URI — exact match | The `redirect_uri` registered with the provider must be **exact string match**, no wildcards, no substring. An attacker who can register `https://example.com.evil.com` when the match is a prefix gets the code. |
| Redirect URI allow-list | If you proxy / accept a dynamic `redirect_uri` (e.g. for preview deploys), validate against a strict allow-list with full URL equality. |
| Code one-time use | Authorization codes must be redeemed exactly once and expire within ~60s. Consume **atomically** (single conditional write on the unconsumed state, exactly-one-row check) so concurrent exchange requests can't both succeed. On reuse, revoke the tokens already issued from that code — reuse signals interception. |
| Client secret | Server-side only — never in SPA / mobile bundles. Use PKCE-only (public client) for browser and native apps. Rotate on suspected leak. |
| Token storage | Access + refresh tokens from IdPs must be encrypted at rest (AES-GCM with KMS key) if you persist them. Don't log them. |
| Account linking — verified email only | When linking an OAuth account to a local account by email, **require the IdP to mark the email as verified** (`email_verified: true` for Google/OIDC, GitHub's verified-emails API). Otherwise an attacker registers an IdP account with victim's email and takes over. |
| Account linking — re-auth | Require the user to re-authenticate (password or existing session in good standing) before linking a new IdP, and before unlinking the **only** sign-in method. |
| Provider identity binding | Key the link on `(provider, provider_account_id)`, not the email. Emails change; the tuple must not. Lookups must always filter by the **full tuple** — never by `provider_account_id` alone. Providers use overlapping ID spaces (numeric IDs especially), so a bare-ID lookup can resolve an attacker's provider-A account to a victim's provider-B link. Enforce with a composite unique constraint on `(provider, provider_account_id)`. The `provider` half must name the **issuing authority** — the ID token's `iss`, the SAML entity id, or an immutable id you map 1:1 to it — not a local config label. One label aimed at several customer IdPs collides subjects across tenants; two labels for one IdP split a person into two accounts, the second inheriting none of the first's MFA enrollment. If the config label has to stay on the row (two clients for one issuer), add a separate `issuer` column and move the unique constraint to `(issuer, provider_account_id)` — the shape better-auth 1.7 adopted; locally issued factors use a fixed `local:<factor>` issuer, and a plain-OAuth provider with no `iss` gets a synthetic value you never rename (`local:oauth:<encoded providerId>` upstream). The same rule governs any lookup that resolves an identifier to a **trust target** where equality on a unique column isn't possible — an email domain or hostname matched against a tenant's claimed domains, say: fetch **all** matches and require exactly one distinct target. Zero denies; two or more denies, logs both target ids, and alerts — a second claim on a security identifier is an attack signal. Never let `findFirst` / `LIMIT 1` decide: storage order is not a security property, and whoever can plant the second row picks the winner. |
| Subject claim — stable and verified | Take the account subject from the verified ID token or signed assertion (`sub`, SAML `NameID`, plain OAuth `id`) — never from a profile-mapping callback or a follow-up profile API, which populate display attributes and must not redefine identity. Use the claim the provider **documents** as immutable: Microsoft Entra's `sub` is pairwise to *your application registration*, so rotating your own app registration orphans every existing link — key on `oid` instead. |
| Provider profile `id` null-guard | Reject the callback when the provider profile's `id` is null/undefined/empty — never stringify it. `String(undefined)` persists the literal `"undefined"` as the account key, collapsing every broken profile into one shared account: the first attacker to hit the bug owns every user who hits it after. |
| `email` from IdP is not authoritative | Treat the IdP-provided email as unverified unless `email_verified=true` is explicit. Some providers (e.g. Azure AD personal accounts) allow unverified emails. Parse the claim **strictly**: IdPs routinely serialize booleans as strings and every non-empty string is truthy, so `if (claim)` accepts the literal `"false"`. Accept only `true` or `"true"`; treat `"false"`, `"0"`, `""`, numbers and objects as unverified. SAML attributes arrive as `string \| string[]` — unwrap the single value *before* the strict check, or a legitimate `["true"]` also fails. |
| Front-channel fields are not identity | Everything the browser hands to your callback — query params and, with `response_mode=form_post`, the entire POST body — is attacker-settable; a matching `state` only proves the flow started in that browser, not that the fields came from the IdP. The account key, email, and email-verified flag must come from the ID token you verified or from a server-to-server token/userinfo response. A provider's one-time front-channel profile blob (Apple's `user`) may fill cosmetic columns (display name, avatar) and nothing else — and stays cosmetic if a proxy forwards the callback on. |
| Provider profile → local user fields | The whole profile is untrusted input, not just `email`. Map it through the **same** allow-list schema every other create/update path uses (see `input-validation.md`), so a field the client cannot write stays unwritable when the account is provisioned by OAuth, re-synced on sign-in, or synced on account link. A mapper that spreads the profile into the user row writes `role`, `plan`, or `emailVerified` straight from the provider — and at a self-service IdP the attacker owns those claims. Otherwise "which sign-up method did this user use" becomes a privilege difference. |
| Authorize from the stored row, not the carried object | Before any privilege grant — creating a membership, linking an identity, elevating a role, releasing data — re-read the subject by primary key and evaluate the policy against **those** columns. The user object threaded through a callback (the IdP profile, `id_token` claims, the session's cached user, a DTO passed down the call stack) is an input, not a fact: derive the email domain from the stored email, and read the stored `email_verified`, not the asserted one. A missing row fails closed — never fall through to the in-memory copy. |
| Domain restriction is a claim check, not a request hint | Passing a hosted-domain hint on the authorization request (Google's `hd`, Microsoft's `tenant`) only pre-fills the account chooser — the returned token can still carry any domain. Enforce the restriction against the **verified claim** on the ID token, and apply the same predicate on every path that accepts that identity: redirect callback, direct ID-token sign-in, and any embedded one-tap widget. A second surface onto the same provider that skips the check is a full bypass. |
| Wildcard in an allow-list means "present", not "skip" | An allow-list entry meaning "any" (`hd: "*"`, "any tenant") must still require the claim to be present, non-empty, and read from a signature-verified token. Implemented as an early `return true` before the claim is read, "any Workspace domain" silently becomes "no domain check", and a personal `@gmail.com` identity passes. |
| Discovery document self-attestation | When you build a metadata URL from an identifier — `https://issuer/.well-known/oauth-authorization-server`, `.../.well-known/openid-configuration`, a per-tenant config blob — the `issuer` the fetched document declares about itself **MUST** be identical to the identifier you used to build that URL, by simple string comparison (RFC 3986 §6.2.1: no case folding, no default-port elision, no trailing-slash forgiveness). Compare **before** reading any `authorization_endpoint`, `token_endpoint`, or `jwks_uri` out of it, and discard the whole document on mismatch. A document served from `https://attacker.example/.well-known/oauth-authorization-server` claiming `"issuer": "https://honest.example"` must be rejected: the document's self-declared identity is the only thing binding those bytes to the principal you meant to reach, so without the check every endpoint inside it is attacker-controlled and the authorization request, the code exchange, and the signing keys all point at the attacker. Required by RFC 8414 §3.3 and OIDC Discovery §4.3. Cache the validated document under a TTL **you** choose — never one the document's own origin dictates. |
| ID token signature | Verify `iss`, `aud`, `exp`, `iat`, `nonce`, and signature (use the provider's JWKS). Cache JWKS **per issuer** with a sensible TTL (a shared cache cross-contaminates keys between issuers) and handle key rotation. Route **every** path that accepts an ID token through the same verifier — the redirect callback, a mobile SDK handing you an `id_token` directly, an embedded one-tap widget — each configured per provider with its JWKS source, issuer and expected audience; a provider with no such configuration *rejects* the direct-token path rather than decoding and trusting the token (better-auth's PayPal path accepted any decodable `id_token` unverified until 1.7 collapsed the per-provider verifiers into one). |
| Outbound endpoint fetches (SSRF) | Your token, refresh, introspection, JWKS and discovery URLs are attacker-influenced the moment a tenant registers its own SSO/OIDC provider or you trust a discovery document's contents. Validate the **resolved** IP against the private-range block-list, and refuse redirects outright — `redirect: 'manual'`, any 3xx or opaque-redirect treated as a failure, never followed. See `input-validation.md`. |
| `scope` minimization | Request the minimum scopes. Review on each provider update — `profile` + `email` is enough for sign-in; don't request `offline_access` unless refresh is needed. |
| Consent / incremental auth | Reauthorize ("incremental consent") for elevated scopes. Don't silently acquire drive/contact/repo scopes on first sign-in. |
| Logout propagation (RP-initiated / back-channel) | On logout, revoke refresh tokens at the IdP when possible. For SSO-heavy apps, support back-channel logout (OIDC Front-Channel / Back-Channel Logout). |
| Dynamic provider registration | Don't enable dynamic client registration at your IdP endpoint unless strictly required — it's a footgun. |
| "Sign in with X" button CSRF (login CSRF) | The login callback itself is CSRF-exposed if `state` isn't bound. See `csrf-protection.md`. |
| Open-redirect via `redirect_uri` trick | The `redirect_uri` parameter on your own authorize endpoint is a classic open-redirect vector. Validate it server-side before sending the user to the IdP. Reject dangerous schemes (`javascript:`, `data:`, `vbscript:`) and any value containing a fragment — RFC 6749 §3.1.2 forbids fragments in redirect URIs. |

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

```typescript
// BAD: loose parse of an IdP claim — booleans arrive as strings, so "false" is truthy
if (idTokenClaims.email_verified) await linkToExistingUser(idTokenClaims.email);
```

### Correct

```typescript
// GOOD: ONE builder for every provider — authorization code + PKCE + state + nonce
const state = crypto.randomBytes(32).toString('hex');
const nonce = crypto.randomBytes(32).toString('hex');
const verifier = crypto.randomBytes(32).toString('base64url');
const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
// The issuer this request is bound to — compared byte-for-byte on the callback
const { issuer } = await getProviderMetadata('google'); // 'https://accounts.google.com'
await setTempCookies({ state, nonce, verifier, issuer }); // HttpOnly, Secure, Path=/auth/callback

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

// On the callback, before the token request:
const iss = new URL(req.url).searchParams.get('iss');
if (iss !== null && iss !== expected.issuer) throw new HttpError(400, 'Issuer mismatch');
if (iss === null && providerAdvertisesIss) throw new HttpError(400, 'Missing iss');
// `!==` IS the required comparison — do not normalize either side first.
```

```typescript
// GOOD: verified-email-only linking, keyed by provider account id
async function onGithubCallback(profile, verifiedEmails) {
  if (profile.id == null || profile.id === '') {
    throw new HttpError(502, 'Provider returned no account id'); // never String(undefined)
  }
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

```typescript
// GOOD: strict parse of an IdP-supplied verified flag (OIDC claim or SAML attribute)
function isVerifiedClaim(raw: unknown): boolean {
  const value = Array.isArray(raw) ? raw[0] : raw; // SAML attrs are string | string[]
  return value === true || value === 'true';       // anything else, incl. "false", is unverified
}

const emailVerified = isVerifiedClaim(idTokenClaims.email_verified);
```

### References

- [OAuth 2.0 Security Best Current Practice (draft-ietf-oauth-security-topics)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [OAuth 2.1 (draft)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1)
- [RFC 7636 — PKCE](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 9207 — OAuth 2.0 Authorization Server Issuer Identification](https://datatracker.ietf.org/doc/html/rfc9207)
- [RFC 8252 — OAuth 2.0 for Native Apps (BCP 212)](https://datatracker.ietf.org/doc/html/rfc8252)
- [RFC 8414 — OAuth 2.0 Authorization Server Metadata (§3.3 issuer validation)](https://datatracker.ietf.org/doc/html/rfc8414#section-3.3)
- [OpenID Connect Discovery 1.0 §4.3 — Provider Configuration Validation](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationValidation)
- [OIDC Core — `nonce`](https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes)
- [OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html)
- [Dirk Balfanz / Google — "Pre-Account Takeover" pattern via OAuth account linking](https://www.descope.com/blog/post/account-takeover-oauth)
