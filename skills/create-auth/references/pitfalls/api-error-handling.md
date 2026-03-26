# Pitfall: API routes must catch database errors

All API route handlers that touch the database **must** wrap DB calls in try/catch and return a JSON error response on failure. Never let a database error (e.g., missing table, connection failure) propagate as an unhandled exception — many frameworks will return the raw error text, and the client will fail to parse it as JSON.

```typescript
// BAD — raw DB error leaks to client as non-JSON text
export async function GET(request: Request) {
  const session = await findSessionByToken(token); // throws if table missing
  // ...
}

// GOOD — always returns JSON
export async function GET(request: Request) {
  try {
    const session = await findSessionByToken(token);
    // ...
  } catch {
    return jsonResponse({ error: "Internal server error" }, 500);
  }
}
```

This applies to **every** route: sign-up, sign-in, session, sign-out, and all feature routes (passkey, OTP, etc.).
