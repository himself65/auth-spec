# Pitfall: 401 — and a recoverable 403 — on MCP endpoints must include `resource_metadata` in `WWW-Authenticate`

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

**Missing the header entirely.** Many web frameworks send a bare 401 by default. Override at the bearer middleware so every 401 path goes through one helper that always sets the header — the validated version of it is at the end of this file.

```typescript
// BAD — right shape (one helper), wrong values: raw interpolation lets a `"` or CRLF split the header
function unauthorized(res: Response, error = "invalid_token", description = "…") {
  res.setHeader(
    "WWW-Authenticate",
    `Bearer realm="mcp", error="${error}", error_description="${description}", resource_metadata="${PRM_URL}"`,
  );
  return res.status(401).json({ error });
}
```

**Returning 403 instead of 401.** A missing or invalid token is `401`. A valid token that lacks a scope is `403` with `error="insufficient_scope", scope="…", resource_metadata="…"` — a compliant client SHOULD respond to that by stepping up: re-authorizing for more scope and retrying. A `403` for something re-authorizing cannot fix gets **no** `WWW-Authenticate` at all; a challenge there sends the client through consent for scopes it already holds, and users who see repeated pointless prompts learn to approve them without reading.

**PRM URL pointing at the wrong host.** The `resource_metadata` URL must be served by the same host that hosts the MCP endpoint, and its `resource` field must match the canonical MCP server URL. If you front the MCP server with a proxy, the PRM URL has to point at the externally visible URL, not the internal one.

**Insufficient scope returning 401.** `401` means *your credential is bad*, so the client discards a working token and re-authenticates for the same scope set — then hits the identical wall, forever. Name every scope the operation needs and the token lacks in that one `403` header; drip-feeding them one per 403 costs a browser round trip each.

**Interpolating unvalidated values into the header.** The helper above interpolates raw: a `"` or a CR/LF reaching `error_description` splits the challenge apart or injects a second header. Every value MUST be checked against its grammar first, and the two kinds are handled differently. Values with a defined grammar are **rejected**, never escaped: each scope must match `^[\x21\x23-\x5b\x5d-\x7e]+$` (RFC 6749 `scope-token` — no space, no `"`, no `\`) and `error_description` must match `^[\x20-\x21\x23-\x5b\x5d-\x7e]+$` (same, plus space). Only values that may legitimately contain those bytes — the `resource_metadata` URL — get RFC 7230 quoted-string escaping (`\` → `\\`, `"` → `\"`); a control character (`\x00-\x1f`, `\x7f`) is fatal everywhere. De-duplicate the scope list before joining on a space. Every one of these values is server-derived, so a violation is your own misconfiguration: throw and let it 500 rather than stripping the bytes and sending a mangled challenge no client can step up from.

```typescript
const SCOPE_TOKEN = /^[\x21\x23-\x5b\x5d-\x7e]+$/;
const ERROR_DESCRIPTION = /^[\x20-\x21\x23-\x5b\x5d-\x7e]+$/;

function scopeParam(scopes: string[]) {
  for (const s of scopes) if (!SCOPE_TOKEN.test(s)) throw new TypeError(`invalid scope: ${s}`);
  return [...new Set(scopes)].join(" "); // de-dupe before joining
}
function descriptionParam(text: string) {
  if (!ERROR_DESCRIPTION.test(text)) throw new TypeError("invalid error_description");
  return text; // rejected, never escaped
}
function quoted(value: string) {
  if (/[\x00-\x1f\x7f]/.test(value)) throw new TypeError("invalid WWW-Authenticate parameter");
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

// GOOD — the same single helper, every value validated on the way in
type ChallengeError = "invalid_token" | "invalid_request" | "insufficient_scope";
function challenge(res: Response, status: 401 | 403, error: ChallengeError, description: string, scopes: string[] = []) {
  res.setHeader("WWW-Authenticate", [
    `Bearer realm="mcp"`,
    `error="${error}"`, // fixed set, so no runtime check needed
    `error_description="${descriptionParam(description)}"`,
    ...(scopes.length ? [`scope="${scopeParam(scopes)}"`] : []), // 403 insufficient_scope only
    `resource_metadata="${quoted(PRM_URL)}"`,
  ].join(", "));
  return res.status(status).json({ error });
}
```
