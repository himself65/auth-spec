# Pitfall: 401 on MCP endpoints must include `resource_metadata` in `WWW-Authenticate`

When the MCP transport returns 401, MCP clients (Claude Desktop, mcp-inspector, Cursor, etc.) read the `WWW-Authenticate` header to discover which authorization server to use. If `resource_metadata=` is missing, the client has no way to auto-configure — it surfaces a generic "auth failed" error and the user has to manually configure auth, which mostly means they give up.

## The rule

Every 401 response from any MCP transport endpoint MUST include a `WWW-Authenticate: Bearer …` header carrying at least:

- `realm="mcp"` (any short identifier — humans see this)
- `error="invalid_token"` (or `"invalid_request"` for malformed Authorization)
- `resource_metadata="<absolute URL to your PRM document>"`

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="mcp",
  error="invalid_token",
  error_description="The access token is missing, expired, or invalid",
  resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"
Content-Type: application/json

{"error":"invalid_token"}
```

The `resource_metadata` value MUST be an absolute URL (scheme + host + path), even if your framework would happily accept a relative one. Per RFC 9728 §5.1.

## Common mistakes

**Missing the header entirely.** Many web frameworks send a bare 401 by default. Override at the bearer middleware so every 401 path goes through one helper that always sets the header.

```typescript
// GOOD — single helper used everywhere we return 401
function unauthorized(res: Response, error = "invalid_token", description = "…") {
  res.setHeader(
    "WWW-Authenticate",
    `Bearer realm="mcp", error="${error}", error_description="${description}", resource_metadata="${PRM_URL}"`,
  );
  return res.status(401).json({ error });
}
```

**Returning 403 instead of 401.** A missing or invalid token is `401`. A valid token without sufficient scope is `403` with `error="insufficient_scope", scope="…"` — also requires `WWW-Authenticate`, but the client will not re-run the auth flow (the user just doesn't have permission).

**PRM URL pointing at the wrong host.** The `resource_metadata` URL must be served by the same host that hosts the MCP endpoint, and its `resource` field must match the canonical MCP server URL. If you front the MCP server with a proxy, the PRM URL has to point at the externally visible URL, not the internal one.

**Insufficient scope returning 401.** Returning 401 for a scope problem causes the client to re-run the authorize flow expecting *more permission* on the same token — but the user already granted everything they were going to. Use 403 with `insufficient_scope` so the client surfaces a useful error to the user.
