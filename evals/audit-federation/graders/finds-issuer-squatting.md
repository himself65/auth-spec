---
type: llm
weight: 3
---

Context: any signed-in user can register an SSO provider with an arbitrary `issuer` and their own `jwksUri`. Sign-in verifies the ID token against the registering user's JWKS, then looks up `Account` by `(providerId = provider.issuer, accountId = sub)`. An attacker registers a provider claiming a real IdP's issuer, signs a token with the victim's `sub`, and is signed into the victim's account.

PASS if the reply explains that a user-registered provider can claim another provider's issuer and reach accounts linked through the real one, and recommends keying accounts on the registration's own id (or equivalent binding).
FAIL otherwise.
