# Pitfall: OAuth account lookups key on the (providerId, accountId) tuple

Two separate account-takeover bugs live in OAuth callback code that treats the provider's user id as globally unique:

**Cross-provider ID collision.** Provider user ids share no namespace — GitHub's numeric `12345` and another provider's `12345` are different people. A lookup by `accountId` alone signs the GitHub user into whichever row some other provider created first.

**Null id stringification.** When a provider returns a malformed or scope-restricted profile, `profile.id` is `undefined`; interpolating it stores the literal string `"undefined"` as the account key. Every broken profile then maps to the *same* account row — the first person to hit the bug creates the row, and everyone who hits it after signs in as them.

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
```

Back the lookup with a unique constraint on `(providerId, accountId)` — the core schema in this skill defines it — so even a buggy code path cannot create colliding rows. The same tuple rule applies when unlinking a provider and when checking "is this provider already linked".
