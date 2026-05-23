# Pitfall: MCP server must not pass tokens through to upstream APIs

When an MCP tool calls another service on behalf of the user (e.g., a `search_drive` tool calls Google Drive), the natural-but-wrong instinct is to forward the incoming `Authorization` header to the upstream API. Don't. The MCP authorization spec explicitly forbids this pattern — it's a **MUST NOT**, not a suggestion. It breaks audience binding and turns the MCP server into an open-relay credential laundromat.

## Why it's wrong

The bearer token your MCP server received was minted for the audience `https://mcp.example.com`. The upstream API (Google Drive, your internal `api.example.com`, etc.) has a different audience. If you forward the token:

- The upstream API either rejects it (best case, audience check works), or accepts it (worst case — the audience check is missing or the issuer overlaps), giving the MCP server's caller access they were never granted.
- You bypass the upstream's scope/consent model. The user agreed to give Claude Desktop `mcp:read` against your MCP server; they did not agree to give Claude Desktop Drive access.
- An attacker who steals an MCP token can fan out to every API the MCP server can reach.

## The rule

Each downstream call needs its own credential, minted for that downstream service's audience. Three correct patterns:

**1. Server-stored upstream credential (most common).** The user previously connected their Google account through your normal app UI; you have a Google refresh token in your DB indexed by `userId`. The MCP tool looks up that refresh token, exchanges it for an access token, and uses *that* against Drive. The MCP token is never forwarded.

**2. Token Exchange (RFC 8693).** If you have a token-exchange-capable AS, the MCP server presents its bearer token to the AS and asks for a token bound to the upstream resource. The new token has the right audience and (typically) a narrower scope.

**3. Service-to-service auth.** If the upstream is your own internal service, use service credentials (mTLS, signed JWT with `act` claim for the user) — not the user-facing bearer.

```typescript
// BAD — token passthrough
async function searchDrive(ctx: McpContext, query: string) {
  return fetch("https://www.googleapis.com/drive/v3/files?q=" + query, {
    headers: { Authorization: ctx.req.headers.authorization }, // <-- the incoming MCP token
  });
}

// GOOD — mint a fresh credential bound to Drive
async function searchDrive(ctx: McpContext, query: string) {
  const google = await getStoredGoogleAccessToken(ctx.userId); // refresh if expired
  return fetch("https://www.googleapis.com/drive/v3/files?q=" + query, {
    headers: { Authorization: `Bearer ${google.accessToken}` },
  });
}
```

## Tell-tale signs you're doing this wrong

- Anywhere you read `ctx.req.headers.authorization` outside the bearer-validation middleware.
- A tool implementation that takes `accessToken` from its caller and uses it on a `fetch`.
- A "transparent proxy" tool that exposes upstream API responses 1:1.
