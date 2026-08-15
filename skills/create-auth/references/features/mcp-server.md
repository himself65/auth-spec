# MCP Server Auth

Authentication for a [Model Context Protocol](https://modelcontextprotocol.io) server. MCP clients (Claude Desktop, mcp-inspector, Cursor, ChatGPT desktop, custom agents) authenticate to the MCP server via OAuth 2.1 bearer tokens. This feature scaffolds the endpoints, schema, middleware, and discovery documents required by the MCP authorization spec.

**Spec reference:** MCP authorization is profiled under `/specification/2026-07-28/basic/authorization` — the current protocol revision is **2026-07-28** (the prior stable was 2025-11-25). As of this revision the authorization doc is split across four pages — `index`, `authorization-server-discovery`, `client-registration`, `security-considerations` — so checking one URL will miss clauses. The `/specification/draft/` copy currently tracks 2026-07-28 with no normative differences (only its internal cross-links differ). The spec is updated frequently; verify any `MUST/MAY` claim against the dated revision, never against `draft` — clauses like Dynamic Client Registration have been re-graded and re-classified between revisions.

**Transport applicability:** This whole feature is for **HTTP-based MCP transports** (Streamable HTTP, the JSON-RPC over HTTP profile). The spec explicitly notes that STDIO transports SHOULD NOT use OAuth and SHOULD pull credentials from the environment — if the project's MCP server is STDIO-only, skip this feature entirely and instead read secrets from `process.env`. Authorization at the MCP layer is OPTIONAL overall; this feature only applies when the user has decided they want it.

## Two Modes

A project can adopt one of two postures. Ask the user which one applies before generating code — the scaffolding differs.

**Mode A — Resource Server only.** The MCP server validates bearer tokens issued by an external authorization server (the project's existing IdP: Google, GitHub, Okta, Auth0, the auth server scaffolded by this skill's other features, etc.). Generate:

- `/.well-known/oauth-protected-resource` (PRM)
- Bearer middleware that validates tokens and rejects with the `WWW-Authenticate` header pointing at the PRM URL
- Resource-indicator (audience) check on every token

**Mode B — Self-hosted Authorization Server.** The MCP server issues its own tokens. Everything from Mode A, plus:

- `/.well-known/oauth-authorization-server` (ASM)
- Client ID Metadata Document (CIMD) resolution — the preferred way to identify a client you have never met
- `POST /oauth/register` (RFC 7591 Dynamic Client Registration — deprecated; scaffold only if today's clients still need it)
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
| clientSecretHash       | string   | nullable (SHA-256; set iff `tokenEndpointAuthMethod` is not `none` — never read as the confidentiality flag) |
| name                   | string   | not null (`client_name`)                                 |
| redirectUris           | string   | not null (JSON array, exact-match)                       |
| grantTypes             | string   | not null (JSON array; typical: `["authorization_code","refresh_token"]`) |
| tokenEndpointAuthMethod| string   | not null (`none` for public, `client_secret_basic` for confidential) |
| scope                  | string   | nullable (space-separated default scopes)                |
| logoUri                | string   | nullable                                                 |
| clientUri              | string   | nullable                                                 |
| softwareId             | string   | nullable (DCR metadata)                                  |
| registrationSource     | string   | nullable (`dcr` \| `managed` \| `cimd`; NULL = legacy/unclassified — never infer it from the id's shape) |
| createdByUserId        | string   | nullable (foreign key -> User; null for self-registered) |
| createdAt              | datetime | default now                                              |

**OAuthAuthorizationCode**

| Field               | Type     | Constraints                                                  |
| ------------------- | -------- | ------------------------------------------------------------ |
| id                  | string   | primary key (surrogate — the lineage root tokens point at)   |
| codeHash            | string   | unique, nullable (SHA-256 of the crypto-random, single-use code; expired-code cleanup clears this, never deletes the row — live tokens still reference `id`) |
| clientId            | string   | foreign key -> OAuthClient, not null                         |
| userId              | string   | foreign key -> User, not null                                |
| sessionId           | string   | nullable (foreign key -> Session; the consenting session)    |
| redirectUri         | string   | not null (echoed back; must match at exchange)               |
| scope               | string   | not null (space-separated; granted scopes)                   |
| resource            | string   | not null (the MCP server's canonical resource URI)           |
| codeChallenge       | string   | not null (PKCE)                                              |
| codeChallengeMethod | string   | not null (must be `S256`)                                    |
| expiresAt           | datetime | not null (10 minute max)                                     |
| consumedAt          | datetime | nullable (set on exchange — must be null when redeemed)      |

**OAuthAccessToken**

| Field               | Type     | Constraints                                              |
| ------------------- | -------- | -------------------------------------------------------- |
| id                  | string   | primary key                                              |
| tokenHash           | string   | unique, not null (SHA-256 of opaque token)               |
| clientId            | string   | foreign key -> OAuthClient, not null                     |
| userId              | string   | foreign key -> User, not null                            |
| authorizationCodeId | string   | not null, **indexed** (foreign key -> OAuthAuthorizationCode.id — the lineage root) |
| sessionId           | string   | nullable (foreign key -> Session; consenting session)    |
| scope               | string   | not null (space-separated)                               |
| resource            | string   | not null (audience — the MCP server's canonical URI)     |
| expiresAt           | datetime | not null                                                 |
| revokedAt           | datetime | nullable                                                 |
| createdAt           | datetime | default now                                              |

**OAuthRefreshToken**

| Field               | Type     | Constraints                                            |
| ------------------- | -------- | ------------------------------------------------------ |
| id                  | string   | primary key                                            |
| tokenHash           | string   | unique, not null (SHA-256)                             |
| clientId            | string   | foreign key -> OAuthClient, not null                   |
| userId              | string   | foreign key -> User, not null                          |
| authorizationCodeId | string   | not null, **indexed** (foreign key -> OAuthAuthorizationCode.id — the lineage root, carried forward unchanged through rotation) |
| sessionId           | string   | nullable (foreign key -> Session; see access token)    |
| scope               | string   | not null                                               |
| resource            | string   | not null                                               |
| expiresAt           | datetime | not null                                               |
| consumedAt          | datetime | nullable (rotation — set on use, must be null at use)  |
| revokedAt           | datetime | nullable (set on `/oauth/revoke`, family revocation, or session sign-out) |
| replacedById        | string   | nullable (forensic chain after rotation)               |
| createdAt           | datetime | default now                                            |

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
- Keep `offline_access` — and any other scope that governs credential lifetime rather than access to this resource — out of `scopes_supported` here and out of the `scope=` value on a `WWW-Authenticate` challenge; refresh-token issuance is the authorization server's decision, not a resource requirement. A client that receives no `scope=` on the 401 falls back to requesting *every* scope listed in PRM `scopes_supported`, so advertising `offline_access` turns each first-time consent into a grant of persistent offline access. The **AS** metadata below is the opposite case — a Mode B AS MAY list `offline_access` in its `/.well-known/oauth-authorization-server` `scopes_supported`, since that is exactly where a client checks before adding it to its own authorization request; the client MUST still treat a missing refresh token as a normal outcome.

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
  "client_id_metadata_document_supported": true,
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
- `client_id_metadata_document_supported: true` is how a client learns it can hand you an `https://` URL as its `client_id` instead of registering. Advertise it only if you actually implement the CIMD rules below — clients that see it will stop calling `registration_endpoint`.
- `grant_types_supported` MUST NOT include `password` or `implicit` — OAuth 2.1 removes them.
- `authorization_response_iss_parameter_supported: true` declares that you emit `iss` in authorization responses (RFC 9207) — defence against authorization-server mix-up, letting a client that talks to several ASes confirm the code came back from the one it expected. Emitting `iss` is still SHOULD, but if you do emit it you **MUST** advertise it here (2026-07-28 §Authorization Response Validation). The `iss` on your redirect must be **byte-identical** to the `issuer` above: clients compare with simple string comparison (RFC 3986 §6.2.1) and are forbidden from normalizing, so one stray trailing slash or `:443` makes every compliant client reject the callback.

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
2. In **Mode A**: validate the token against the upstream IdP — either by JWT signature verification against its JWKS, or by RFC 7662 introspection. Cache JWKS for 1 hour; cache positive introspection results no longer than 60 seconds. If you locate that JWKS by fetching the IdP's discovery document (`/.well-known/oauth-authorization-server` or `/.well-known/openid-configuration`), the document's `issuer` MUST be identical — simple string comparison, no normalization — to the issuer identifier you used to build the URL; reject the document outright on mismatch, before reading `jwks_uri` out of it (RFC 8414 §3.3). Whoever controls `jwks_uri` mints tokens this middleware will accept, so an unchecked discovery document is a full authentication bypass.
3. In **Mode B**: SHA-256 the token, look up `OAuthAccessToken` by `tokenHash`. Reject if not found, expired, or revoked — and if the row carries a `sessionId`, reject when that session row is gone or past its own `expiresAt`. This is not session authentication (the MCP endpoint still refuses cookies); the session is a liveness predicate on a credential minted from it.
4. **Audience check (mandatory):** the token's resource/audience MUST equal the MCP server's canonical `resource` URI from PRM. Reject otherwise — this prevents an access token issued for service X from being replayed against this MCP server. See `references/pitfalls/mcp-token-audience.md`.
5. Scope check: decide **implication, not membership**. If your scope model has any notion of a broader scope subsuming a narrower one (`admin` implies `read`, `files:write` implies `files:read`), resolve that hierarchy before deciding — a plain set-intersection 403s a token that is in fact sufficient, and MCP 2026-07-28 makes accounting for scope hierarchies a server **MUST**. Insufficient → `403` with an `insufficient_scope` challenge (see below). Derive the required scopes from the parsed body (`method`, `params.name`) — never from the `Mcp-Method` / `Mcp-Name` headers. A header-derived scope gate over a body-derived dispatch lets a read-scoped call execute a write tool; see the mirrored-header rule under **Implementation Rules**.
6. Attach the resolved user (and client, in Mode B) to the request context.

**WWW-Authenticate on 401** (RFC 9728 §5.1):

```
WWW-Authenticate: Bearer realm="mcp",
  error="invalid_token",
  error_description="The access token is missing, expired, or invalid",
  resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"
```

The `resource_metadata` parameter is what lets MCP clients discover the authorization server without configuration. Omitting it breaks Claude Desktop, mcp-inspector, and every other compliant client. See `references/pitfalls/mcp-www-authenticate.md`.

**WWW-Authenticate on 403** (RFC 6750 §3.1) — only for a *recoverable* scope gap:

```http
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer error="insufficient_scope",
  scope="files:write files:delete",
  resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource",
  error_description="File write permission required for this operation"
```

`scope` MUST list **every** scope this operation needs and the token does not satisfy, derived from the failed check — not a static configured hint. Challenging incrementally (one missing scope, then the next on the retry) costs a full browser round trip per scope. Do **not** pad it with scopes the token already holds: since 2026-07-28 the server reports only what the current operation requires, and accumulation is the client's job — a client stepping up re-authorizes with the union of what it previously requested and what you challenged, and one that sends the challenged scopes alone silently drops the permissions it already had. `resource_metadata` belongs on the 403 for the same reason it belongs on the 401.

A `403` that re-authorizing **cannot** fix — this user is simply not allowed to call this tool — gets a bare `403` with **no** `WWW-Authenticate` at all. Attaching a challenge to a plain permission denial walks the client into a consent loop for scopes it already holds, which trains users to approve authorization prompts reflexively. See `references/pitfalls/mcp-www-authenticate.md`.

## Mode B Endpoints

### Client ID Metadata Documents (CIMD)

The path the spec wants you on, and the named migration target for DCR: the client publishes its own metadata at an `https://` URL and uses that URL as its `client_id`. Nothing is stored before the first authorization, which is exactly why it works for clients you have never met. Advertise it with `client_id_metadata_document_supported: true`.

AS-side rules (the client-side ones are the client's problem):

- Treat a `client_id` as a metadata document URL only when it uses the `https` scheme **and** carries a path component (`https://app.example.com/client.json`). A bare origin is not a CIMD `client_id`. This shape test only classifies an id you have never seen; once an `OAuthClient` row exists for it, the stored `registrationSource` decides and the shape is ignored (see **Provenance is stored, never inferred** below).
- Fetch the document, then check that the `client_id` **inside** it equals the requested `client_id` byte-for-byte. Reject on mismatch — this is the check that stops one domain publishing another's identity.
- MUST validate the body is JSON and contains `client_id`, `client_name`, `redirect_uris`. Everything else (`logo_uri`, `client_uri`, `grant_types`, `token_endpoint_auth_method`) is optional and gets the same validation you apply on DCR — scheme rules, no fragments, `application_type` sanity.
- MUST validate the authorization request's `redirect_uri` against the document's `redirect_uris`, exact match, exactly as for a registered client.
- Cache the document honouring its HTTP cache headers, clamped by your own floor and ceiling, and revalidate with `ETag` / `If-None-Match`. Never cache a document that failed validation.

**The fetch is an SSRF sink.** You are taking a URL from an unauthenticated stranger and making your server retrieve it — the classic route to your own metadata service or internal admin endpoints. Apply the full egress classifier: `https` only, resolved-IP block-list, connect to the address you resolved, no redirects followed, JSON content type, few-KB body cap, ~5s timeout. See `skills/security-best-practice/rules/input-validation.md`. Any loopback exemption for local development is an explicit flag defaulted off, never a silent carve-out that ships to production.

**A metadata document proves control of a domain, not control of the callback.** Any app on the user's machine can present the legitimate client's metadata URL as its `client_id`, bind a loopback port that the genuine document already lists (your own RFC 8252 rule below ignores the port), and catch the code — while your server fetches the genuine document and your consent screen shows the genuine `client_name` and logo. CIMD cannot detect this on its own, so:

- The consent screen **MUST** display the actual `redirect_uri` hostname, not just `client_name` / `logo_uri`.
- **SHOULD** show a distinct warning when every `redirect_uri` in the document is loopback-only.
- **MAY** apply a domain allowlist (or domain-age / reputation checks) on the `client_id` host if your server is not meant to be open to every client on the internet.

**Provenance is stored, never inferred.** Once DCR, operator/managed registration, and CIMD all write to `OAuthClient`, decide which channel owns a row by reading the stored `registrationSource` — never by pattern-matching the identifier. "The `client_id` starts with `https://`, therefore it is self-published" is an attacker-controllable predicate: an operator-registered first-party client whose id happens to be a URL would have its `redirect_uris`, scopes, and consent settings rewritten by whoever serves that URL. Every write path asserts the existing row's `registrationSource` equals its own channel and refuses on mismatch — put it in the `WHERE` clause of the update, not in an `if` before it — and legacy or administrative rows stay `NULL` until an operator classifies them.

### POST /oauth/register (RFC 7591 — Dynamic Client Registration)

**Status as of MCP 2026-07-28:** RFC 7591 DCR is **MAY**, and as of this revision it is formally **Deprecated**: it stays in the spec for backwards compatibility, new implementations SHOULD NOT adopt it, and it becomes eligible for removal in the first revision released on or after **2027-07-28**. The migration path the spec names is **Client ID Metadata Documents** (above). Until CIMD adoption is broad, scaffold DCR as the fallback so existing clients (Claude Desktop, mcp-inspector) keep working.

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
  - `redirect_uris` MUST be present and non-empty. Reject any entry containing a fragment (`#…` — RFC 6749 §3.1.2 forbids fragments), any entry carrying userinfo credentials (`https://user:pass@rp.example.com/cb`), any host with a trailing dot (`localhost.`, `localhost..` — the DNS-root spelling of the same name, which slips past a string compare against `localhost`), any LAN IP or `http://0.0.0.0`, and any reserved or dangerous scheme (`javascript:`, `data:`, `vbscript:`, `file:`, `ftp:`, `mailto:`).
  - `application_type` is the **sole** driver of redirect policy. MCP 2026-07-28 makes sending it a client MUST, but clients still omit it — when it is absent, default to `web`, the stricter of the two, and never to `native`. Reject any value that is not `web` or `native`.
    - `web`: `https://` on a non-loopback host, and nothing else. No `http://`, and no loopback — `https://localhost:3005/cb` is a `web` rejection.
    - `native`: either `https://` on a non-loopback host (RFC 8252 §7.2 claimed URI — ordinary for desktop and mobile apps, not an anomaly), or `http://` on loopback with any port (§7.3), or a private-use scheme that is a well-formed reverse-domain name with no authority component (`com.example.app:/oauth` — not `myapp:/oauth`, which has no dot, and not `com.example.app://host/oauth`, which has an authority).
  - **The loopback allowance is three literal authorities, and it is tested against the raw request string.** `localhost`, `127.0.0.1`, `[::1]` — not "whatever the URL parser calls loopback". A parser widens that set far past the RFC: `new URL("http://127.1/cb").hostname` is `127.0.0.1`, and so are `http://0x7f.0.0.1/cb` and `http://2130706433/cb`; `http://127.42.7.9:49152/cb` keeps a hostname that is still inside `127.0.0.0/8`; `http://tenant.localhost/cb` resolves to loopback per RFC 6761. Since `/oauth/authorize` will later byte-match the exact string the client registered, that string is what registration has to validate — extract the authority with a raw-text match (`/^http:\/\/([^/?#]*)/`, then take everything after the last `@`), lowercase it, strip a trailing `:<port>` (the bracketed `[::1]:49152` form too), and compare what remains against the three literal hosts — the port is ignored per RFC 8252 §7.3, which is what lets a desktop client bind whatever port it got. It is the mirror image of an SSRF egress check, which tests the *resolved* address: there you are blocking loopback and must catch every spelling, here you are permitting it and must accept only three.
  - **Confidentiality comes from exactly one stored field:** a client is confidential iff `tokenEndpointAuthMethod !== "none"`. Derive every downstream decision from that single read — whether registration issues a `client_secret`, whether `/oauth/token` demands one. Never keep a parallel `public` boolean, and never infer it from `clientSecretHash IS NULL`. Two fields encoding one fact drift, and the permissive reading wins: a client registered `client_secret_basic` whose secret row is missing silently degrades into a public client that skips authentication entirely. Application type and authentication method are orthogonal axes — a `native` client may register `client_secret_basic`, a `web` client may register `none`; never let one field imply the other. When `token_endpoint_auth_method` is `none` (the common case for desktop MCP clients), issue no `client_secret`; PKCE alone authenticates.
  - Reject unknown `grant_types`. Only `authorization_code` and `refresh_token` are allowed.
  - Server-issued columns are never read from the body. Build the row from an explicit allow-list of registerable metadata — never spread the request — and ignore any member naming a field the server owns: `client_id` (the `id` column), `client_secret`/`clientSecretHash`, `client_id_issued_at`/`createdAt`, `registrationSource`, and `createdByUserId`. RFC 7591 §3.2.1 makes those the authorization server's to issue; a self-registering client that can set `createdByUserId` plants its client in another user's account. If you later add an opaque "extra metadata" column, strip the reserved names from its contents too, in **both** spellings — the internal column name and the wire name — because your serializer maps between them and an attacker will send whichever one you forgot.
- Response (**201 Created** — RFC 7591 §3.2.1; not 200):
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
- After the user consents (or implicit-consent for first-party clients), generate a 32-byte crypto-random `code`, persist an `OAuthAuthorizationCode` row storing `codeHash = SHA256(code)` (never the code itself), recording the id of the session that consented and carrying a short TTL (10 minutes is the OAuth 2.1 ceiling; 1–2 minutes is fine and tighter is better — production code TTLs of 60 seconds are common), and 302 to `redirect_uri?code=…&state=…&iss=https://mcp.example.com`. The `iss` parameter is RFC 9207 mix-up defense — include it whenever you advertise `authorization_response_iss_parameter_supported: true`.

### POST /oauth/token

Authorization Code grant:

- Body (form-encoded): `grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`, `code_verifier`.
- Verify the presented `grant_type` is in the client's registered `grantTypes` — a client registered only for `authorization_code` must not obtain tokens through any other grant.
- Look up the row by `codeHash = SHA256(code)`. **Atomically** mark it consumed (set `consumedAt`) — if it was already consumed, revoke every token descended from it (`UPDATE oauth_access_token SET revoked_at = now() WHERE authorization_code_id = $1 AND revoked_at IS NULL`, then `UPDATE oauth_refresh_token SET revoked_at = now() WHERE authorization_code_id = $1 AND revoked_at IS NULL` — `$1` is the code row's `id`; run the two independently and best-effort so a failure on one still clears the other, and log the failure) and return `400` with `error=invalid_grant`. Soft-revoke, never `DELETE` — the family rows are the theft-signal trail. The code is single-use.
- Verify the code is not expired and that `clientId`, `redirectUri` match what was stored.
- Verify PKCE: `BASE64URL(SHA256(code_verifier)) == codeChallenge`.
- If the client is confidential (`tokenEndpointAuthMethod !== "none"` — that one field, not the presence of `clientSecretHash`), also verify `client_secret` via Basic auth — compare `SHA256(presented_secret)` to `clientSecretHash` with a constant-time comparison. A confidential client whose stored hash is missing is a broken row, not a public client: fail closed. Reject any request presenting more than one client-authentication method (a Basic header *and* a body `client_secret`, or a secret *and* a `client_assertion`) — RFC 6749 §2.3 forbids it, and accepting both lets the caller choose which credential you check.
- Issue an `OAuthAccessToken` (15–60 min TTL) and `OAuthRefreshToken` (longer, e.g. 30 days). Both store SHA-256 hashes — never the plaintext.
- Stamp `resource`, **`authorizationCodeId`** (the code row's `id`, never the code itself), and **`sessionId`** from the authorization code onto both tokens. The lineage column is what turns the replay revocation above into one indexed update per table instead of an unanswerable question.
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
- Reject with `invalid_grant` any refresh token whose `revokedAt` is non-null — revocation outranks rotation state, and a family-revoked token must never mint a replacement.
- The refresh token's stored `clientId` MUST equal the authenticated `client_id` — a token is bound to the client it was issued to, and any other client gets `invalid_grant`, never a successful exchange. Use `invalid_grant`, not `invalid_client`: client authentication succeeded, so it is the presented grant that is invalid.
- **Rotate** the refresh token: mark the old one consumed, issue a new one, store `replacedById`, and copy `authorizationCodeId` and `sessionId` onto the replacement **unchanged** — `authorizationCodeId` is the family key, so rotation must never restart it. If a consumed refresh token is presented again, revoke the entire token family — set `revokedAt` on every access and refresh row sharing that `authorizationCodeId`, the same soft revoke as the code-replay path — this signals replay/theft.
- `resource` of the new access token MUST equal the original resource. Do not allow audience downgrade/upgrade on refresh.

### POST /oauth/revoke (RFC 7009)

- Body: `token`, optional `token_type_hint` (`access_token` or `refresh_token`).
- Look up by SHA-256 hash; set `revokedAt`. If a refresh token, also revoke every access token issued under the same grant — match on `authorizationCodeId`, which is exactly RFC 7009 §2.1's "all access tokens based on the same authorization grant".
- Always return 200, even if the token was unknown — per RFC 7009, to avoid leaking which tokens exist.
- Client authentication is optional for public clients but the request MUST present the same `client_id` the token was issued to.

## Implementation Rules

- **Write all OAuth code by hand.** Do not use `oauth4webapi`, `node-oauth2-server`, `oidc-provider`, `Authlib`, etc. — the same hand-rolled philosophy as the rest of this skill. The flow is small enough to read in one sitting.
- **PKCE is mandatory.** Reject any `/oauth/authorize` request without `code_challenge`, and any `code_challenge_method` other than `S256`. OAuth 2.1 removes the option to skip PKCE.
- **Tokens are hashed at rest.** Store `SHA256(token)` only. The plaintext goes back to the client once. Same rule as API keys.
- **Codes and tokens are single-use where applicable.** Authorization codes: one exchange and they're done. Refresh tokens: rotate on every use; replaying a consumed refresh token revokes the family.
- **Token-endpoint status codes: `400` unless client authentication itself failed.** RFC 6749 §5.2 reserves `401` for `invalid_client` when the client tried to authenticate via the `Authorization` header (and that response carries its own `WWW-Authenticate`). Every other `/oauth/token` failure — replayed code, expired code, PKCE mismatch, `client_id` or `redirect_uri` mismatch, unregistered grant type — is `400` with the appropriate `error` code, and a replayed code is `invalid_grant`, never `invalid_client`. A `401` on a grant failure tells a compliant client to retry *client authentication* instead of restarting the authorization flow, so the user loops instead of recovering.
- **Access tokens die with the session that authorized them.** Stamp the signed-in user's session id onto the `OAuthAuthorizationCode` at `/oauth/authorize`, carry it onto every access and refresh token issued from that code, and carry it forward again on refresh rotation. Validate it at *use* time — not only by writing `revokedAt` when the session is deleted. Both, ideally: the sign-out path should set `revokedAt` on that `sessionId`'s tokens, but that write is the part that gets skipped (a missed hook, a queued background job, a cache-backed session store), while a lookup in the bearer middleware cannot be skipped. Without it, sign-out looks like it worked while the integration's token keeps introspecting as active and keeps being served by any userinfo-style route until its own TTL. If you issue JWT access tokens rather than opaque ones, put the session id in a `sid` claim and do the same lookup — a JWT's self-contained validity is exactly what makes the check necessary.
- **Refresh tokens: decide explicitly whether they outlive the session.** OIDC Back-Channel Logout §2.7 draws the line at consent: refresh tokens the user did not grant as offline access are revoked when the session ends; ones they did are preserved. Binding them is the tighter posture and the right default for a first-party MCP server, but it means the MCP client must re-authorize every time the user signs out of the web app — which for a desktop agent holding a 30-day refresh token is a real cost. Pick one, write it down, and make sure `/oauth/revoke` and a "connected apps" UI cover whichever tokens you left unbound.
- **Audience binding is non-negotiable.** Every access token has a stored `resource`. The bearer middleware MUST compare it to the MCP server's canonical resource URI. See `references/pitfalls/mcp-token-audience.md`.
- **Redirect URIs are matched exactly.** No prefix matching, no scheme coercion, no port wildcards. Loopback MAY allow arbitrary ports per RFC 8252, but only for the three literal hosts `localhost`, `127.0.0.1`, and `[::1]`, matched on the raw string with the port stripped before comparison.
- **Repeated form parameters are rejected.** On `POST /oauth/token` and `POST /oauth/revoke`, `client_id`, `client_secret`, `code`, `code_verifier`, `refresh_token`, `token`, and `grant_type` are single-valued — a repeat is `400 invalid_request`. RFC 8707 `resource` is the one field here that MAY repeat. Mechanism and parser caveats: `skills/security-best-practice/rules/input-validation.md`.
- **Never log or echo tokens, codes, or `code_verifier`.** Tokens go in logs in only one form: their SHA-256 prefix for correlation.
- **Credential-bearing responses are `no-store`.** `/oauth/token` (RFC 6749 §5.1) and `/oauth/register` (RFC 7591 §3.2.1) MUST send `Cache-Control: no-store` and `Pragma: no-cache` — on the `invalid_grant` / `invalid_client` error responses as well as on success, since those leave the same endpoint. Attach the headers where the route is declared, not at each `return`, and assert them in a test: a framework's dispatch or serialization layer will silently swallow a status code and headers set at the call site, which is how a freshly minted `client_secret` ends up in a corporate proxy's cache. The two `.well-known` documents are the only cacheable responses here (`max-age=3600`, above).
- **The MCP endpoint never accepts session cookies.** Bearer header only — this avoids CSRF surface on the MCP transport. (The OAuth UI endpoints — `/oauth/authorize` and the sign-in page — do use the project's session cookie. That's fine; they're not the MCP transport.)
- **Origin header validation on the MCP transport.** For Streamable HTTP, reject requests whose `Origin` header is not in an allowlist — defends against DNS rebinding attacks from a victim's browser. Same rule as any localhost-bound dev server.
- **Mirrored headers are a routing hint, never an authorization input.** Protocol revision `2026-07-28` requires clients to mirror body fields into HTTP headers — `Mcp-Method` ← `method`, `Mcp-Name` ← `params.name`/`params.uri`, `Mcp-Param-{Name}` ← tool arguments annotated `x-mcp-header`, `MCP-Protocol-Version` ← `_meta."io.modelcontextprotocol/protocolVersion"` — so gateways can route, rate-limit, and observe without parsing the body. The body stays the source of truth: any component that processes the body **MUST** compare every mirrored header to its body value and reject a mismatch with `400` plus JSON-RPC error `-32020` (`HeaderMismatch`). Decode `=?base64?…?=` sentinel values before comparing (the markers are lowercase and case-sensitive), and compare integers numerically (`42` == `42.0`). A gateway that enforces policy on these headers must also check that `MCP-Protocol-Version` names a revision that mandates this validation — if it is absent or older, nothing downstream is comparing, so reject rather than trust the header. This is the request-smuggling / JWT-header-vs-payload defect class: two parsers, two answers, one authorization check.
- **HTTPS on every AS endpoint, no exceptions.** The MCP spec requires all authorization-server endpoints to be served over HTTPS, and redirect URIs to be HTTPS or loopback. Plaintext HTTP for `/oauth/authorize`, `/oauth/token`, `/oauth/register`, or the discovery documents is non-compliant.
- **Token passthrough is forbidden, not discouraged.** Per the MCP spec: MCP servers **MUST NOT** accept tokens that weren't explicitly issued for them, and **MUST NOT** forward their incoming bearer to upstream APIs. If your MCP tool calls another service, mint a new credential for that service (or use the user's separately-stored credentials). See `references/pitfalls/mcp-token-passthrough.md`.
- **Sessions MUST NOT authenticate the MCP endpoint.** The spec is explicit. Bearer header only. The OAuth UI (`/oauth/authorize`, sign-in pages) does use the session cookie — that's fine; those aren't the MCP transport.

## Dependencies on Other Features

- **Rate Limiting** (`references/features/rate-limiting.md`) — strongly recommended on `/oauth/register`, `/oauth/token`, and `/oauth/authorize`. Public DCR endpoints are a favorite spam target.
- **KV Cache** (`references/features/kv-cache.md`) — handy for caching upstream JWKS (Mode A) and for short-lived `state`/nonce storage if the authorize flow needs it.
- The core User **and Session** tables from the base scaffold — `OAuthAccessToken.userId` and `OAuthAccessToken.sessionId` reference them. The OAuth UI reuses the project's session (cookie) to identify the consenting user.

## Best Practices (Industry Consensus)

- **OAuth 2.1, not 2.0.** OAuth 2.1 (draft) consolidates the security errata: PKCE everywhere, no implicit grant, no password grant, exact redirect URI matching, refresh token rotation. The MCP authorization spec explicitly profiles OAuth 2.1.
- **Resource Indicators (RFC 8707) are mandatory in the MCP profile.** Without them, an access token minted for "the MCP server" is indistinguishable from one minted for any other downstream API at the same issuer — the classic confused-deputy setup. Real-world bug pattern: schemas grow a `resource` column on access tokens but the bearer middleware forgets to compare it to the canonical resource URI — token issuance is bound, token validation isn't. See `references/pitfalls/mcp-token-audience.md`.
- **Protected Resource Metadata (RFC 9728) is what lets MCP clients self-configure.** The 401 → `resource_metadata` URL → discover `authorization_servers` → fetch ASM/OIDC → register (or use CIMD) → authorize → exchange code → call MCP. Every link in that chain has to be there for Claude Desktop or mcp-inspector to connect with zero manual config. **Mount discovery at the root** — not just under your auth prefix — because some clients ignore `WWW-Authenticate` and check root.
- **Client registration: pre-registered first, then CIMD, then DCR.** The current MCP spec ranks them in that order. CIMD has been the `SHOULD` since 2025-11-25; DCR (RFC 7591) is `MAY` and, since 2026-07-28, **Deprecated** with removal eligible from the first revision on or after 2027-07-28. Neither grade moved — the lifecycle state did. Build CIMD as the path you intend to keep, scaffold DCR only for clients that still need it, and gate it behind a registration token.
- **`iss` in authorization responses (RFC 9207).** Emission is still SHOULD (a future revision is expected to make it MUST), but as of the 2026-07-28 spec clients **MUST** validate `iss` before redeeming the code, and an AS that emits it **MUST** advertise `authorization_response_iss_parameter_supported: true`. Emit it on every `/oauth/authorize` redirect including error redirects, byte-identical to your metadata `issuer`. Cost: 30 seconds. Benefit: mix-up attack defense — and a callback that compliant clients will still accept.
- **Public clients (PKCE-only) are the norm.** Desktop and CLI MCP clients can't keep a secret. Don't pretend otherwise — let them register as `token_endpoint_auth_method=none` and rely on PKCE. Reject `code_challenge_method=plain` outright.
- **Loopback redirect URIs allow arbitrary ports.** RFC 8252 §7.3 — match `localhost`, `127.0.0.1`, or `[::1]` ignoring the port. This is how desktop apps catch the redirect without reserving a fixed port. Those three spellings are the whole allowance; anything else that a URL parser happens to normalize into loopback is not covered.
- **Token TTLs.** Authorization code: ≤10 minutes per OAuth 2.1; 60 seconds is reasonable and tighter is fine. Access tokens: 15–60 minutes — short enough that revocation is mostly automatic via expiry, long enough to avoid hammering `/oauth/token`. Refresh tokens: 30–90 days, rotate on every use, revoke the entire family on replay (a refresh token reuse is a theft signal, not a benign retry).
- **Scope namespace is a project convention.** The spec does not mandate `mcp:*`. It mandates a *strategy*: least-privilege grants + step-up via `WWW-Authenticate: scope=...` on 403. Use whatever scope names match your tool surface (`tools:read`, `read:profile`, etc.) as long as `scopes_supported` in PRM/ASM agrees with what `/authorize` accepts.
- **JWT vs opaque tokens.** Opaque tokens (this spec) trade slightly more DB load at the resource for instant revocation and no JWKS infrastructure. JWTs would let the MCP server validate without a DB hit but require JWKS rotation and a denylist for revocation. For a self-hosted single-deployment MCP server, opaque is the right default. If you do choose JWT, embed `aud` matching the canonical resource URI and verify it on every request.
