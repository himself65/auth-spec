# MCP Server Auth

Authentication for a [Model Context Protocol](https://modelcontextprotocol.io) server. MCP clients (Claude Desktop, mcp-inspector, Cursor, ChatGPT desktop, custom agents) authenticate to the MCP server via OAuth 2.1 bearer tokens. This feature scaffolds the endpoints, schema, middleware, and discovery documents required by the MCP authorization spec.

**Spec reference:** MCP authorization is profiled in the `/specification/<version>/basic/authorization` doc — the latest stable is **2025-11-25**, the working draft is `DRAFT-2026-v1`. The spec is updated frequently; before generating, verify any `MUST/MAY` claim against the current doc — clauses like Dynamic Client Registration have been re-graded between versions.

**Transport applicability:** This whole feature is for **HTTP-based MCP transports** (Streamable HTTP, the JSON-RPC over HTTP profile). The spec explicitly notes that STDIO transports SHOULD NOT use OAuth and SHOULD pull credentials from the environment — if the project's MCP server is STDIO-only, skip this feature entirely and instead read secrets from `process.env`. Authorization at the MCP layer is OPTIONAL overall; this feature only applies when the user has decided they want it.

## Two Modes

A project can adopt one of two postures. Ask the user which one applies before generating code — the scaffolding differs.

**Mode A — Resource Server only.** The MCP server validates bearer tokens issued by an external authorization server (the project's existing IdP: Google, GitHub, Okta, Auth0, the auth server scaffolded by this skill's other features, etc.). Generate:

- `/.well-known/oauth-protected-resource` (PRM)
- Bearer middleware that validates tokens and rejects with the `WWW-Authenticate` header pointing at the PRM URL
- Resource-indicator (audience) check on every token

**Mode B — Self-hosted Authorization Server.** The MCP server issues its own tokens. Everything from Mode A, plus:

- `/.well-known/oauth-authorization-server` (ASM)
- `POST /oauth/register` (RFC 7591 Dynamic Client Registration)
- `GET /oauth/authorize` (Authorization Code grant — PKCE required)
- `POST /oauth/token` (code exchange + refresh)
- `POST /oauth/revoke` (RFC 7009)
- Schema for `OAuthClient`, `OAuthAuthorizationCode`, `OAuthAccessToken`, `OAuthRefreshToken`

Both modes share the same bearer middleware and the same PRM document. Mode B is a strict superset of Mode A.

## Schema Additions

Schema is only required for Mode B. Mode A relies on the upstream IdP's storage.

**OAuthClient**

| Field                  | Type     | Constraints                                              |
| ---------------------- | -------- | -------------------------------------------------------- |
| id                     | string   | primary key (`client_id`)                                |
| clientSecretHash       | string   | nullable (SHA-256; null = public client, PKCE only)      |
| name                   | string   | not null (`client_name`)                                 |
| redirectUris           | string   | not null (JSON array, exact-match)                       |
| grantTypes             | string   | not null (JSON array; typical: `["authorization_code","refresh_token"]`) |
| tokenEndpointAuthMethod| string   | not null (`none` for public, `client_secret_basic` for confidential) |
| scope                  | string   | nullable (space-separated default scopes)                |
| logoUri                | string   | nullable                                                 |
| clientUri              | string   | nullable                                                 |
| softwareId             | string   | nullable (DCR metadata)                                  |
| createdByUserId        | string   | nullable (foreign key -> User; null for self-registered) |
| createdAt              | datetime | default now                                              |

**OAuthAuthorizationCode**

| Field               | Type     | Constraints                                                  |
| ------------------- | -------- | ------------------------------------------------------------ |
| code                | string   | primary key (crypto-random, single-use)                      |
| clientId            | string   | foreign key -> OAuthClient, not null                         |
| userId              | string   | foreign key -> User, not null                                |
| redirectUri         | string   | not null (echoed back; must match at exchange)               |
| scope               | string   | not null (space-separated; granted scopes)                   |
| resource            | string   | not null (the MCP server's canonical resource URI)           |
| codeChallenge       | string   | not null (PKCE)                                              |
| codeChallengeMethod | string   | not null (must be `S256`)                                    |
| expiresAt           | datetime | not null (10 minute max)                                     |
| consumedAt          | datetime | nullable (set on exchange — must be null when redeemed)      |

**OAuthAccessToken**

| Field      | Type     | Constraints                                              |
| ---------- | -------- | -------------------------------------------------------- |
| id         | string   | primary key                                              |
| tokenHash  | string   | unique, not null (SHA-256 of opaque token)               |
| clientId   | string   | foreign key -> OAuthClient, not null                     |
| userId     | string   | foreign key -> User, not null                            |
| scope      | string   | not null (space-separated)                               |
| resource   | string   | not null (audience — the MCP server's canonical URI)     |
| expiresAt  | datetime | not null                                                 |
| revokedAt  | datetime | nullable                                                 |
| createdAt  | datetime | default now                                              |

**OAuthRefreshToken**

| Field        | Type     | Constraints                                            |
| ------------ | -------- | ------------------------------------------------------ |
| id           | string   | primary key                                            |
| tokenHash    | string   | unique, not null (SHA-256)                             |
| clientId     | string   | foreign key -> OAuthClient, not null                   |
| userId       | string   | foreign key -> User, not null                          |
| scope        | string   | not null                                               |
| resource     | string   | not null                                               |
| expiresAt    | datetime | not null                                               |
| consumedAt   | datetime | nullable (rotation — set on use, must be null at use)  |
| replacedById | string   | nullable (forensic chain after rotation)               |
| createdAt    | datetime | default now                                            |

## Discovery Endpoints

Both endpoints MUST be **unauthenticated** and served over HTTPS. `Cache-Control: max-age=3600` is reasonable. **Mount the well-known documents at the project root** — not nested under your auth router (e.g. `/api/auth/.well-known/...`) — because several MCP clients in the wild ignore the `WWW-Authenticate: resource_metadata=` hint and probe root paths directly. If your auth code lives at `/api/auth`, expose the same handlers at `/.well-known/oauth-protected-resource` and `/.well-known/oauth-authorization-server`. See `references/pitfalls/mcp-discovery-mounting.md`.

**GET `/.well-known/oauth-protected-resource`** (RFC 9728 — required in both modes; MCP servers **MUST** implement this)

```json
{
  "resource": "https://mcp.example.com",
  "authorization_servers": ["https://mcp.example.com"],
  "bearer_methods_supported": ["header"],
  "scopes_supported": ["mcp:read", "mcp:write"],
  "resource_documentation": "https://example.com/docs/mcp"
}
```

- `resource` MUST exactly match the canonical URL the MCP server identifies as (scheme + host + optional path). Tokens whose `aud` (or stored `resource`) does not match this value MUST be rejected.
- `authorization_servers` is required and MUST contain at least one entry. In Mode A these are the upstream IdPs; in Mode B it's the MCP server itself.
- If the MCP server is mounted under a path (e.g. `/mcp`), the canonical resource MUST include that path. Per-resource PRM lives at `/.well-known/oauth-protected-resource/mcp` (RFC 9728 §3.1).
- `scopes_supported` is a **convention**, not spec-mandated. The MCP spec mandates a *strategy* (least-privilege + step-up authorization), not a namespace. Project-specific scopes like `mcp:read`, `read:profile`, or `tools:filesystem` are all fine; what matters is that the values you advertise here match what `/authorize` will accept.

**Authorization Server discovery** (Mode B) — the MCP spec requires the AS to publish **at least one of**:

- `/.well-known/oauth-authorization-server` (RFC 8414 Authorization Server Metadata)
- `/.well-known/openid-configuration` (OIDC Discovery 1.0)

MCP clients MUST support both. Picking RFC 8414 is the simpler choice when you're not running a full OIDC provider. Either way:

```json
{
  "issuer": "https://mcp.example.com",
  "authorization_endpoint": "https://mcp.example.com/oauth/authorize",
  "token_endpoint": "https://mcp.example.com/oauth/token",
  "registration_endpoint": "https://mcp.example.com/oauth/register",
  "revocation_endpoint": "https://mcp.example.com/oauth/revoke",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "token_endpoint_auth_methods_supported": ["none", "client_secret_basic"],
  "code_challenge_methods_supported": ["S256"],
  "scopes_supported": ["mcp:read", "mcp:write"],
  "authorization_response_iss_parameter_supported": true
}
```

- `code_challenge_methods_supported` MUST contain only `S256`. Do not advertise `plain` — OAuth 2.1 removes it and the newer MCP-targeted libraries actively reject it.
- `grant_types_supported` MUST NOT include `password` or `implicit` — OAuth 2.1 removes them.
- `authorization_response_iss_parameter_supported: true` declares that you emit `iss` in authorization responses (RFC 9207). This defends against authorization-server mix-up attacks: a client that talks to multiple ASes can confirm the code came back from the AS it expected. The MCP spec currently SHOULDs this and a forthcoming revision will upgrade to MUST.

## Bearer Middleware (both modes)

Apply to every MCP transport endpoint (typically `POST /mcp` for Streamable HTTP, plus any session/SSE endpoints).

**Wrap it as a single helper.** Both better-auth (`withMcpAuth(auth, handler)`) and the funda-app's hand-rolled equivalent settled on the same shape: one function that takes the route handler and returns a wrapped handler that runs the bearer check, attaches the principal to the request, and short-circuits to 401 on failure. Use this pattern — it keeps the 401 contract (especially `WWW-Authenticate`) in exactly one place and removes any temptation to forget the audience check in a new route.

```typescript
// Sketch — adapt to the project's framework
type Principal = { userId: string; clientId: string; scopes: string[]; resource: string };
export function withMcpAuth(
  handler: (req: Request, principal: Principal) => Promise<Response>,
) {
  return async (req: Request) => {
    const principal = await validateBearer(req); // returns Principal | { error }
    if ("error" in principal) return unauthorized(principal.error);
    return handler(req, principal);
  };
}
```

**Serverless deployment note:** Frameworks like Next.js App Router build a fresh per-request `McpServer` and connect it to a stateless transport (e.g. `WebStandardStreamableHTTPServerTransport`). That's fine — auth state lives in the DB, not in the server object — but it means the bearer check happens *outside* the MCP server's own session model. Don't try to put auth inside `McpServer.connect()`; do it at the HTTP route boundary before the request reaches the SDK.

Algorithm:

1. Read `Authorization: Bearer <token>` header. If missing or malformed → `401` with `WWW-Authenticate` (see below). No fallback to query string or cookie for MCP endpoints.
2. In **Mode A**: validate the token against the upstream IdP — either by JWT signature verification against its JWKS, or by RFC 7662 introspection. Cache JWKS for 1 hour; cache positive introspection results no longer than 60 seconds.
3. In **Mode B**: SHA-256 the token, look up `OAuthAccessToken` by `tokenHash`. Reject if not found, expired, or revoked.
4. **Audience check (mandatory):** the token's resource/audience MUST equal the MCP server's canonical `resource` URI from PRM. Reject otherwise — this prevents an access token issued for service X from being replayed against this MCP server. See `references/pitfalls/mcp-token-audience.md`.
5. Scope check: if the route declares required scopes, intersect with the token's granted scopes. Missing scopes → `403` with `WWW-Authenticate: Bearer error="insufficient_scope", scope="…"`.
6. Attach the resolved user (and client, in Mode B) to the request context.

**WWW-Authenticate on 401** (RFC 9728 §5.1):

```
WWW-Authenticate: Bearer realm="mcp",
  error="invalid_token",
  error_description="The access token is missing, expired, or invalid",
  resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"
```

The `resource_metadata` parameter is what lets MCP clients discover the authorization server without configuration. Omitting it breaks Claude Desktop, mcp-inspector, and every other compliant client. See `references/pitfalls/mcp-www-authenticate.md`.

## Mode B Endpoints

### POST /oauth/register (RFC 7591 — Dynamic Client Registration)

**Status in the current MCP spec:** RFC 7591 DCR is now **MAY** (was SHOULD in earlier revisions). The preferred path forward is **Client ID Metadata Documents** (`draft-ietf-oauth-client-id-metadata-document`) — the client publishes its own metadata document at an `https://` URL and uses that URL as its `client_id`, eliminating the need for server-side registration. Until CIMD adoption is broad, scaffold DCR as the fallback so existing clients (Claude Desktop, mcp-inspector) keep working.

- Public endpoint, rate-limited (depends on **Rate Limiting** feature — gate at e.g. 10 registrations / hour / IP). Consider gating with an initial access token (RFC 7591 §3) once you're past the bootstrap phase.
- Request body (subset of RFC 7591):
  ```json
  {
    "client_name": "Claude Desktop",
    "redirect_uris": ["http://127.0.0.1:33418/callback", "claudedesktop://oauth"],
    "grant_types": ["authorization_code", "refresh_token"],
    "token_endpoint_auth_method": "none",
    "application_type": "native",
    "scope": "mcp:read mcp:write"
  }
  ```
- **Validation rules:**
  - `redirect_uris` MUST be present, non-empty. Each entry must use HTTPS, or be a loopback URI (`http://127.0.0.1[:port]/…` or `http://localhost[:port]/…` — never `http://0.0.0.0` and never a LAN IP), or a custom scheme containing `.` (reverse-DNS style, e.g. `com.example.app:/oauth`). Reject dangerous schemes outright (`javascript:`, `data:`, `vbscript:`) and any entry containing a fragment (`#…`) — RFC 6749 §3.1.2 forbids fragments in redirect URIs.
  - `application_type` SHOULD be respected (`native` for desktop/CLI/loopback, `web` otherwise). Reject mismatches — a `web` client requesting a loopback redirect URI is suspicious, a `native` client requesting `https://` to a public host is suspicious. The OIDC dynamic-registration spec ties redirect URI shape to `application_type`; following the rule avoids surprises.
  - If `token_endpoint_auth_method` is `none` (public client — the common case for desktop MCP clients), do not issue a `client_secret`. Public clients authenticate solely via PKCE.
  - Reject unknown `grant_types`. Only `authorization_code` and `refresh_token` are allowed.
- Response (200):
  ```json
  {
    "client_id": "...",
    "client_secret": "...optional, only if confidential...",
    "client_id_issued_at": 1716406200,
    "redirect_uris": [...],
    "grant_types": [...],
    "token_endpoint_auth_method": "none"
  }
  ```
- Persist `clientSecretHash = SHA256(client_secret)` — never the plaintext secret.

### GET /oauth/authorize

- Query params: `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state`, `code_challenge`, `code_challenge_method=S256`, `resource` (the MCP server's canonical URI per RFC 8707).
- **Validation order — short-circuit on first failure, and do NOT redirect on errors that occur before `redirect_uri` is validated** (otherwise an attacker can use you as an open redirect):
  1. Look up `client_id` → 400 if unknown.
  2. `redirect_uri` MUST match one of the client's registered URIs **byte-for-byte** (no normalization, no scheme coercion, no trailing-slash forgiveness) → 400 if not.
  3. `response_type=code` and `code_challenge_method=S256` → after this point, errors redirect to `redirect_uri` with `error=`.
  4. `resource` MUST equal the MCP server's canonical resource URI → `error=invalid_target`.
  5. `scope` MUST be a subset of `scopes_supported` and the client's registered scope → `error=invalid_scope`.
- If the user is not signed in, redirect to the project's existing sign-in flow with a `?next=` back to `/oauth/authorize?…`. The MCP server reuses the user's session — this is the whole point of having auth scaffolded by this skill.
- After the user consents (or implicit-consent for first-party clients), generate a 32-byte crypto-random `code`, persist an `OAuthAuthorizationCode` row with a short TTL (10 minutes is the OAuth 2.1 ceiling; 1–2 minutes is fine and tighter is better — production code TTLs of 60 seconds are common), and 302 to `redirect_uri?code=…&state=…&iss=https://mcp.example.com`. The `iss` parameter is RFC 9207 mix-up defense — include it whenever you advertise `authorization_response_iss_parameter_supported: true`.

### POST /oauth/token

Authorization Code grant:

- Body (form-encoded): `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`, `code_verifier`.
- Verify the presented `grant_type` is in the client's registered `grantTypes` — a client registered only for `authorization_code` must not obtain tokens through any other grant.
- Look up the code. **Atomically** mark it consumed (set `consumedAt`) — if it was already consumed, revoke any tokens issued from it and return `invalid_grant`. The code is single-use.
- Verify the code is not expired and that `clientId`, `redirectUri` match what was stored.
- Verify PKCE: `BASE64URL(SHA256(code_verifier)) == codeChallenge`.
- If the client is confidential, also verify `client_secret` via Basic auth — compare `SHA256(presented_secret)` to `clientSecretHash` with a constant-time comparison.
- Issue an `OAuthAccessToken` (15–60 min TTL) and `OAuthRefreshToken` (longer, e.g. 30 days). Both store SHA-256 hashes — never the plaintext.
- Stamp `resource` from the authorization code onto both tokens.
- Response:
  ```json
  {
    "access_token": "...",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "...",
    "scope": "mcp:read mcp:write"
  }
  ```

Refresh Token grant:

- Body: `grant_type=refresh_token`, `refresh_token`, `client_id`, optional `scope` (must be subset of original), optional `resource`.
- Verify `refresh_token` is in the client's registered `grantTypes`, and authenticate confidential clients here exactly as on the code exchange (constant-time compare against `clientSecretHash`) — a stolen refresh token alone must not be enough to act as a confidential client.
- **Rotate** the refresh token: mark the old one consumed, issue a new one, store `replacedById`. If a consumed refresh token is presented again, revoke the entire token family (the chain rooted at the original code) — this signals replay/theft.
- `resource` of the new access token MUST equal the original resource. Do not allow audience downgrade/upgrade on refresh.

### POST /oauth/revoke (RFC 7009)

- Body: `token`, optional `token_type_hint` (`access_token` or `refresh_token`).
- Look up by SHA-256 hash; set `revokedAt`. If a refresh token, also revoke all access tokens descended from it.
- Always return 200, even if the token was unknown — per RFC 7009, to avoid leaking which tokens exist.
- Client authentication is optional for public clients but the request MUST present the same `client_id` the token was issued to.

## Implementation Rules

- **Write all OAuth code by hand.** Do not use `oauth4webapi`, `node-oauth2-server`, `oidc-provider`, `Authlib`, etc. — the same hand-rolled philosophy as the rest of this skill. The flow is small enough to read in one sitting.
- **PKCE is mandatory.** Reject any `/oauth/authorize` request without `code_challenge`, and any `code_challenge_method` other than `S256`. OAuth 2.1 removes the option to skip PKCE.
- **Tokens are hashed at rest.** Store `SHA256(token)` only. The plaintext goes back to the client once. Same rule as API keys.
- **Codes and tokens are single-use where applicable.** Authorization codes: one exchange and they're done. Refresh tokens: rotate on every use; replaying a consumed refresh token revokes the family.
- **Audience binding is non-negotiable.** Every access token has a stored `resource`. The bearer middleware MUST compare it to the MCP server's canonical resource URI. See `references/pitfalls/mcp-token-audience.md`.
- **Redirect URIs are matched exactly.** No prefix matching, no scheme coercion, no port wildcards. Loopback addresses (`127.0.0.1`, `localhost`) MAY allow arbitrary ports per RFC 8252.
- **Never log or echo tokens, codes, or `code_verifier`.** Tokens go in logs in only one form: their SHA-256 prefix for correlation.
- **The MCP endpoint never accepts session cookies.** Bearer header only — this avoids CSRF surface on the MCP transport. (The OAuth UI endpoints — `/oauth/authorize` and the sign-in page — do use the project's session cookie. That's fine; they're not the MCP transport.)
- **Origin header validation on the MCP transport.** For Streamable HTTP, reject requests whose `Origin` header is not in an allowlist — defends against DNS rebinding attacks from a victim's browser. Same rule as any localhost-bound dev server.
- **HTTPS on every AS endpoint, no exceptions.** The MCP spec requires all authorization-server endpoints to be served over HTTPS, and redirect URIs to be HTTPS or loopback. Plaintext HTTP for `/oauth/authorize`, `/oauth/token`, `/oauth/register`, or the discovery documents is non-compliant.
- **Token passthrough is forbidden, not discouraged.** Per the MCP spec: MCP servers **MUST NOT** accept tokens that weren't explicitly issued for them, and **MUST NOT** forward their incoming bearer to upstream APIs. If your MCP tool calls another service, mint a new credential for that service (or use the user's separately-stored credentials). See `references/pitfalls/mcp-token-passthrough.md`.
- **Sessions MUST NOT authenticate the MCP endpoint.** The spec is explicit. Bearer header only. The OAuth UI (`/oauth/authorize`, sign-in pages) does use the session cookie — that's fine; those aren't the MCP transport.

## Dependencies on Other Features

- **Rate Limiting** (`references/features/rate-limiting.md`) — strongly recommended on `/oauth/register`, `/oauth/token`, and `/oauth/authorize`. Public DCR endpoints are a favorite spam target.
- **KV Cache** (`references/features/kv-cache.md`) — handy for caching upstream JWKS (Mode A) and for short-lived `state`/nonce storage if the authorize flow needs it.
- The core User table from the base scaffold — `OAuthAccessToken.userId` references it. The OAuth UI reuses the project's session (cookie) to identify the consenting user.

## Best Practices (Industry Consensus)

- **OAuth 2.1, not 2.0.** OAuth 2.1 (draft) consolidates the security errata: PKCE everywhere, no implicit grant, no password grant, exact redirect URI matching, refresh token rotation. The MCP authorization spec explicitly profiles OAuth 2.1.
- **Resource Indicators (RFC 8707) are mandatory in the MCP profile.** Without them, an access token minted for "the MCP server" is indistinguishable from one minted for any other downstream API at the same issuer — the classic confused-deputy setup. Real-world bug pattern: schemas grow a `resource` column on access tokens but the bearer middleware forgets to compare it to the canonical resource URI — token issuance is bound, token validation isn't. See `references/pitfalls/mcp-token-audience.md`.
- **Protected Resource Metadata (RFC 9728) is what lets MCP clients self-configure.** The 401 → `resource_metadata` URL → discover `authorization_servers` → fetch ASM/OIDC → register (or use CIMD) → authorize → exchange code → call MCP. Every link in that chain has to be there for Claude Desktop or mcp-inspector to connect with zero manual config. **Mount discovery at the root** — not just under your auth prefix — because some clients ignore `WWW-Authenticate` and check root.
- **Client registration: pre-registered first, then CIMD, then DCR.** The current MCP spec ranks them in that order. DCR (RFC 7591) is `MAY` and kept "for backwards compatibility with earlier versions of the MCP authorization spec"; Client ID Metadata Documents is the new SHOULD. Scaffold DCR because today's clients still need it, but plan to add CIMD support and consider gating DCR behind a registration token once your audience is established.
- **`iss` in authorization responses (RFC 9207).** Currently SHOULD, slated to become MUST. Emit it on every `/oauth/authorize` redirect and advertise `authorization_response_iss_parameter_supported: true` in your AS metadata. Cost: 30 seconds. Benefit: mix-up attack defense.
- **Public clients (PKCE-only) are the norm.** Desktop and CLI MCP clients can't keep a secret. Don't pretend otherwise — let them register as `token_endpoint_auth_method=none` and rely on PKCE. Reject `code_challenge_method=plain` outright.
- **Loopback redirect URIs allow arbitrary ports.** RFC 8252 §7.3 — match `127.0.0.1` and `localhost` ignoring the port. This is how desktop apps catch the redirect without reserving a fixed port.
- **Token TTLs.** Authorization code: ≤10 minutes per OAuth 2.1; 60 seconds is reasonable and tighter is fine. Access tokens: 15–60 minutes — short enough that revocation is mostly automatic via expiry, long enough to avoid hammering `/oauth/token`. Refresh tokens: 30–90 days, rotate on every use, revoke the entire family on replay (a refresh token reuse is a theft signal, not a benign retry).
- **Scope namespace is a project convention.** The spec does not mandate `mcp:*`. It mandates a *strategy*: least-privilege grants + step-up via `WWW-Authenticate: scope=...` on 403. Use whatever scope names match your tool surface (`tools:read`, `read:profile`, etc.) as long as `scopes_supported` in PRM/ASM agrees with what `/authorize` accepts.
- **JWT vs opaque tokens.** Opaque tokens (this spec) trade slightly more DB load at the resource for instant revocation and no JWKS infrastructure. JWTs would let the MCP server validate without a DB hit but require JWKS rotation and a denylist for revocation. For a self-hosted single-deployment MCP server, opaque is the right default. If you do choose JWT, embed `aud` matching the canonical resource URI and verify it on every request.
