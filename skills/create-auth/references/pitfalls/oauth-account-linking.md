# Pitfall: OAuth account lookups key on the (providerId, accountId) tuple

Two separate account-takeover bugs live in OAuth callback code that treats the provider's user id as globally unique:

**Cross-provider ID collision.** Provider user ids share no namespace — GitHub's numeric `12345` and another provider's `12345` are different people. A lookup by `accountId` alone signs the GitHub user into whichever row some other provider created first.

**Null id stringification.** When a provider returns a malformed or scope-restricted profile, `profile.id` is `undefined`; interpolating it stores the literal string `"undefined"` as the account key. Every broken profile then maps to the *same* account row — the first person to hit the bug creates the row, and everyone who hits it after signs in as them.

**One label in front of two authorities.** `providerId` must name the *issuing authority*, not the config key you happened to type. Point one `"sso"` / `"oidc"` label at several customer IdPs and subject `12345` from tenant A resolves to tenant B's row — the collision above, now inside a single provider. Two config entries for one IdP fail the other way: one person becomes two accounts, and the second carries none of the first's 2FA enrollment or revocations. For federated providers derive the value from the protocol issuer — `iss` in the ID token, the SAML entity id — or from an immutable id you map 1:1 to it, never from a renameable display name. Locally issued factors (`"credential"`, `"magic-link"`, `"email-otp"`, `"phone"`) are each their own authority and keep their fixed labels.

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
