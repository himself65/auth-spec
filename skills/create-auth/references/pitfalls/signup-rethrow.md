# Pitfall: Sign-up email enumeration catch must not re-throw

The sign-up route catches unique-constraint errors to prevent email enumeration. The catch block **must not** have a `throw err` fallback for other error types — if the database is down or the table doesn't exist, that re-throw produces a raw error response the client can't parse.

Return a generic `500` JSON error instead.

```typescript
// BAD — re-throws non-constraint errors as raw text
} catch (err) {
  if (isUniqueViolation(err)) {
    return jsonResponse({ user: fakeUser, token: fakeToken });
  }
  throw err; // <-- this breaks the client
}

// GOOD — all errors return JSON
} catch (err) {
  if (isUniqueViolation(err)) {
    return jsonResponse({ user: fakeUser, token: fakeToken });
  }
  return jsonResponse({ error: "Internal server error" }, 500);
}
```
