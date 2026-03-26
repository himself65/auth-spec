# Pitfall: Shared auth helpers must not throw on DB failure

Helper functions like `getAuthenticatedUser()` that query the database should catch errors and return `null` instead of propagating. This prevents a database outage from crashing every authenticated route.

```typescript
// BAD — one DB hiccup crashes all authenticated routes
export async function getAuthenticatedUser(request: Request) {
  const session = await findSessionByToken(token); // throws
  // ...
}

// GOOD — graceful degradation
export async function getAuthenticatedUser(request: Request) {
  try {
    const session = await findSessionByToken(token);
    if (!session || session.expiresAt < new Date()) return null;
    return findUserById(session.userId);
  } catch {
    return null;
  }
}
```
