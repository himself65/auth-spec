# Pitfall: Mount `.well-known/*` discovery at the project root, not just under the auth prefix

The MCP spec relies on `WWW-Authenticate: ..., resource_metadata="<absolute URL>"` to point clients at your Protected Resource Metadata document. In theory that means you can host PRM anywhere — `/api/auth/.well-known/oauth-protected-resource` is just as valid as `/.well-known/oauth-protected-resource`. In practice, multiple MCP clients shipped with the assumption that `.well-known` lives at the project root and probe there directly, ignoring the hint they were given.

If your discovery documents only exist under `/api/auth/.well-known/...`, those clients silently fall back to "no auth configured" and report a confusing failure.

## The rule

Expose **both** mount points:

- The canonical one your `WWW-Authenticate` header advertises (wherever your auth router naturally puts it).
- The project root: `/.well-known/oauth-protected-resource` and (Mode B) `/.well-known/oauth-authorization-server`.

The handlers are the same JSON document; they just need to be reachable at both URLs. better-auth ships dedicated helpers (`oAuthProtectedResourceMetadata(auth)`, `oAuthDiscoveryMetadata(auth)`) explicitly for the root re-export — that's the lesson encoded in their plugin.

```typescript
// Next.js App Router example
// app/api/auth/.well-known/oauth-protected-resource/route.ts  <-- canonical
// app/.well-known/oauth-protected-resource/route.ts           <-- root re-export
export { GET } from "@/lib/auth/oauth-protected-resource-handler";
```

```typescript
// Express example
app.get("/api/auth/.well-known/oauth-protected-resource", handlePrm);
app.get("/.well-known/oauth-protected-resource", handlePrm); // <-- same handler
```

## Why this isn't optional

Discovery is the *only* zero-config path that exists in the MCP spec. If a client can't find your PRM, the user is stuck pasting URLs into config dialogs. The cost of a duplicate route registration is one line; the cost of breaking Claude Desktop or mcp-inspector users is real support load.

## Don't conflate with per-resource PRM

RFC 9728 §3.1 also defines per-resource PRM at `/.well-known/oauth-protected-resource/<resource-path>` (e.g. `/.well-known/oauth-protected-resource/mcp`). That's a *different* mechanism — used when one host serves several distinct resources. Both can coexist. If your MCP server lives at `/api/mcp`, advertise the canonical resource as `https://host/api/mcp` and host the per-resource PRM at `/.well-known/oauth-protected-resource/api/mcp`. The root-mount rule above still applies for the generic discovery probe.
