# Pitfall: OAuth account lookups key on the (providerId, accountId) tuple

A family of account-takeover bugs lives in OAuth callback code — most treat the provider's user id as globally unique or mutable, and one lets a callback for provider B redeem a flow that was started with provider A:

**Cross-provider ID collision.** Provider user ids share no namespace — GitHub's numeric `12345` and another provider's `12345` are different people. A lookup by `accountId` alone signs the GitHub user into whichever row some other provider created first.

**Null id stringification.** When a provider returns a malformed or scope-restricted profile, `profile.id` is `undefined`; interpolating it stores the literal string `"undefined"` as the account key. Every broken profile then maps to the *same* account row — the first person to hit the bug creates the row, and everyone who hits it after signs in as them.

**One label in front of two authorities.** `providerId` must name the *issuing authority*, not the config key you happened to type. Point one `"sso"` / `"oidc"` label at several customer IdPs and subject `12345` from tenant A resolves to tenant B's row — the collision above, now inside a single provider. Two config entries for one IdP fail the other way: one person becomes two accounts, and the second carries none of the first's 2FA enrollment or revocations. For federated providers derive the value from the protocol issuer — `iss` in the ID token, the SAML entity id — or from an immutable id you map 1:1 to it, never from a renameable display name. Locally issued factors (`"credential"`, `"magic-link"`, `"email-otp"`, `"phone"`) are each their own authority and keep their fixed labels.

**The pre-redirect record must name the provider it was minted for.** `state`, `nonce`, and the PKCE `code_verifier` are written before the redirect and read back on the callback. If that record — a cookie, a KV entry, a DB row — is not bound to the provider that created it, a value minted while starting a sign-in with provider A satisfies the callback for provider B. In an app that allows linking a second provider while signed in: the *victim* is lured into starting a legitimate same-origin flow with a provider whose authorization request the attacker can observe (one the attacker runs, say); the attacker lifts `state` from that request, obtains a code for *their own* account at the target provider B, and drives the victim's browser to B's callback with that code — the global check cookie matches, and the attacker's B account is linked to the victim's user. Auth.js shipped this as GHSA-x445-f3h2-j279 (CWE-345/346/940). Store the provider id (and, for federated providers, the issuer and client id) *inside* the sealed record next to `state`/`nonce`/`verifier`, and on the callback require the record's provider to equal the callback's provider before anything else is checked — a mismatch discards the code unredeemed. A single sealed cookie is fine as long as its payload names the provider (that is exactly the Auth.js fix); if you need concurrent flows, keep the record server-side, keyed by `state` **and** tied to the browser's pre-auth cookie — a record reachable by `state` alone is the login-CSRF the `state` check exists to stop. PKCE on every provider is the advisory's stated mitigation and raises the bar, but it does not replace the binding: an attacker who can observe the whole authorization request also sees `code_challenge` and can put it on their own request at B.

**"The provider's id" is not always immutable.** Read the subject from the verified ID token or signed assertion — OIDC `sub`, SAML `NameID`, plain OAuth `id` — never from a profile-mapping callback or a follow-up profile API. Those exist to populate display attributes; let one define identity and a mapping change silently re-points a live link. Then use the claim the provider *documents* as immutable: Microsoft Entra's `sub` is pairwise to your application registration, so rotating your own app registration orphans every link you hold; `oid` is the tenant-stable one.

```typescript
// BAD — bare-id lookup, id never checked for null
const account = await db.account.findFirst({
  where: { accountId: String(profile.id) },
});

// GOOD — reject missing ids, then look up by the full tuple
if (profile.id == null || profile.id === '') {
  throw new HttpError(502, 'Provider returned no account id');
}
const account = await db.account.findUnique({
  where: {
    providerId_accountId: { providerId: 'github', accountId: String(profile.id) },
  },
});

// Federated / multi-tenant: both halves of the key come from the verified token
const claims = await verifyIdToken(idToken); // signature, iss, aud, exp, nonce
const subject = provider === 'microsoft' ? claims.oid : claims.sub; // Entra sub is per-app-registration
if (!claims.iss || !subject) throw new HttpError(502, 'No stable issuer/subject');
const federated = await db.account.findUnique({
  where: { providerId_accountId: { providerId: claims.iss, accountId: subject } },
});
```

Back the lookup with a unique constraint on `(providerId, accountId)` — the core schema in this skill defines it — so even a buggy code path cannot create colliding rows. The same tuple rule applies when unlinking a provider and when checking "is this provider already linked".

If `providerId` has to stay a *configuration* label — because two configurations legitimately point at one authority (a consumer client and a workspace client for the same Google issuer), or because the row also records which client configuration last minted its tokens — add a separate `issuer` column carrying the authority and move the unique constraint to `(issuer, accountId)`: `iss` for OIDC, the SAML entity id, a fixed `local:<factor>` for locally issued factors, and for a plain-OAuth provider that has no `iss` (GitHub) a synthetic value you commit to never renaming (better-auth 1.7 uses `local:oauth:<encodeURIComponent(providerId)>`). Two configurations for one issuer then share one identity row — one person, one account, the last configuration's tokens on it. Either way, exactly one column names the authority, that column is what the unique constraint and every lookup use, and it is never derived from an email, an unverified request value, or a config key you might later rename.
