# Pitfall: Client-side session check must handle non-JSON responses

The `AuthProvider`'s session refresh should parse the response body defensively — read as text first, then try `JSON.parse` — so that a server error returning non-JSON text doesn't crash the entire app on page load.

```typescript
// BAD — crashes if server returns non-JSON (e.g. raw error string)
const res = await fetch("/api/auth/session", { headers });
if (res.ok) {
  const data = await res.json(); // throws on non-JSON
  setUser(data.user);
}

// GOOD — safe parsing
const res = await fetch("/api/auth/session", { headers });
if (res.ok) {
  const text = await res.text();
  try {
    const data = JSON.parse(text);
    setUser(data.user);
  } catch {
    clearToken();
    setUser(null);
  }
}
```
