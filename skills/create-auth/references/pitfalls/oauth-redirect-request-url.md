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
