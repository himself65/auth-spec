# Pitfall: OAuth redirect must not use `request.url` as base URL

In containerized deployments (Docker, Kubernetes), the server often binds on `0.0.0.0` (e.g., `ENV HOSTNAME="0.0.0.0"` in a Dockerfile). This causes `request.url` inside route handlers to resolve to `http://0.0.0.0:3000/...` instead of the public domain. Any `NextResponse.redirect(new URL("/path", request.url))` will redirect users to `0.0.0.0`.

Derive the redirect base from an environment variable (`APP_URL`, `NEXTAUTH_URL`, etc.) instead.

```typescript
// BAD — request.url resolves to http://0.0.0.0:3000 in containers
export async function GET(request: NextRequest) {
  // ...
  return NextResponse.redirect(new URL("/", request.url));
}

// GOOD — use a configured base URL for all redirects
export async function GET(request: NextRequest) {
  const baseUrl =
    process.env.APP_URL ?? "http://localhost:3000";
  // ...
  return NextResponse.redirect(new URL("/", baseUrl));
}
```

This applies to **all** OAuth callback routes (Google, GitHub, etc.) and any auth route that issues redirects. Using `request.url` is only safe for reading query parameters — never as a redirect base in production.

The same rule covers every value the server derives from "its own" URL, not just redirects — and behind a TLS-terminating proxy the wrong answer is not merely ugly but a security fault in one direction and a false rejection in the other:

- **Emailed links** (verify-email, password reset, magic link) built from `Host` or `X-Forwarded-Host` are reset-link poisoning: the attacker requests a reset for the victim with a header naming their own host, and the victim's mail carries the token to it.
- **Self-referential protocol values** — the RFC 9207 `iss` on an authorization response, the `resource` in protected-resource metadata, the callback URL you register with an IdP and send as `redirect_uri`, the URL a DPoP proof's `htu` is compared against — must all be the configured public origin. Computed from the incoming request they come out as `http://0.0.0.0:3000` or the proxy's internal scheme and port, and a valid proof signed against the public discovery URL is rejected.
- **Forwarded headers are opt-in, never a default.** `X-Forwarded-Host` / `X-Forwarded-Proto` are request content until *your* proxy is known to overwrite them (better-auth 1.7 made ignoring them the default for its per-request `allowedHosts` mode for exactly this reason; a static base URL never read them). If the public host genuinely varies per request (multi-tenant hostnames), resolve it against a configured allow-list and **fail closed** — no usable or allow-listed host means the request is refused, never "fall back to whatever the request said".

One helper that canonicalizes the request's scheme and host to the configured base URL at the route boundary, applied wherever a route forwards to the auth code, fixes redirects, emailed links, `iss`/`resource`, and DPoP `htu` together; a per-call-site fix is how one of them stays on `request.url`.
