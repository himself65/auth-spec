# Pitfall: MCP bearer tokens MUST be audience-bound

Every access token presented to the MCP server has to carry — and the server has to verify — the canonical resource URI of *this* MCP server (RFC 8707 Resource Indicators). Skipping this check is the confused-deputy bug the MCP authorization spec is specifically written to prevent. The spec wording is unambiguous: MCP servers **MUST NOT** accept tokens that were not explicitly issued for them.

## The drift pattern (seen in production)

The most common version of this bug isn't "no resource handling at all." It's **half** the work done: the schema grows a `resource` column on the access token, the `/oauth/token` endpoint stamps it correctly from the authorization code, but the bearer middleware on the MCP route never reads it back. Issuance is audience-bound; validation is not. Tokens issued for `https://example.com/api/something-else` are happily accepted at `/api/mcp`.

When you add the `resource` column, grep for every place that reads it. If the bearer middleware is not in the results, the column is decoration and the audit log will tell a misleading story.

## The attack

Say `auth.example.com` is your OAuth authorization server and it issues tokens for three resources: `https://mcp.example.com`, `https://api.example.com`, and `https://files.example.com`. A malicious app obtains a user's access token for `api.example.com` through legitimate means (the user installed it). Without an audience check, the attacker can replay that same token against `mcp.example.com` and get full MCP tool access — even though the user never granted MCP scopes to the attacker.

The fix is to bind each token to a specific resource at issue time, and have every resource server verify the binding on every request.

## The rule

The token's `resource` (Mode B, opaque) or `aud` claim (Mode A, JWT) MUST exactly equal the MCP server's canonical resource URI — the same value advertised in `/.well-known/oauth-protected-resource`. No prefix matching, no host-only matching.

```typescript
// BAD — accepts any token signed by our IdP
const claims = verifyJwt(token, jwks);
if (!claims.sub) return 401;
// proceeds to serve MCP requests with attacker's API token

// GOOD — token must be audience-bound to THIS MCP server
const claims = verifyJwt(token, jwks);
const expectedResource = "https://mcp.example.com"; // matches PRM "resource"
const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
if (!aud.includes(expectedResource)) return 401;
```

For opaque tokens (Mode B):

```typescript
const row = await db.oauthAccessToken.findUnique({ where: { tokenHash } });
if (!row || row.expiresAt < new Date() || row.revokedAt) return 401;
if (row.resource !== CANONICAL_RESOURCE) return 401; // <-- the audience check
```

## At issue time

The authorize endpoint MUST require a `resource` parameter and the token endpoint MUST stamp that exact value onto the access token (and refresh token). Refresh MUST NOT allow changing `resource`. If a client wants a token for a different resource, it does a new authorize flow.

```typescript
// In POST /oauth/token (authorization_code grant)
const accessToken = await db.oauthAccessToken.create({
  data: {
    tokenHash: sha256(plaintext),
    userId: code.userId,
    clientId: code.clientId,
    scope: code.scope,
    resource: code.resource, // <-- stamped from authorize, NOT from token request
    expiresAt: addMinutes(new Date(), 60),
  },
});
```

If the authorize request didn't include `resource`, reject it with `error=invalid_request` — do not default to "all resources" or to the issuer URL.
