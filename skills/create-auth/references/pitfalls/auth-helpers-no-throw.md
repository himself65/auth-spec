# Pitfall: Shared auth helpers return `null` on every failure — never throw, never a truthy error

Helper functions like `getAuthenticatedUser()` are called from every protected route, usually as an existence check: `const user = await getAuthenticatedUser(req); if (!user) return 401`. That contract has two halves, and each has shipped as an advisory.

**Never throw.** A DB outage, a timeout, a malformed cookie, or a malformed `Authorization` header must all resolve to `null`, not propagate. Auth.js's `getToken()` URL-decoded the bearer value before validating it whenever no session cookie was present, so a single unauthenticated request carrying `Authorization: Bearer %E0%A4%A` — invalid percent-encoding — threw out of every route that called it (GHSA-xmf8-cvqr-rfgj). Attacker-controlled bytes reach this helper before anything has been authenticated: bad base64, bad JSON in a signed cookie, a token of the wrong length, a header with no space after `Bearer` — decode and parse defensively, and treat every failure as "no session".

**Never return anything truthy on failure.** The failure value is exactly `null`/`None`/`nil` — not `{ error }`, not `undefined`-vs-`null` ambiguity, not a user object with an `error` field. Auth.js v5 populated the `auth` object with `{ message: "There was a problem with the server configuration…" }` when configuration was broken; every `if (req.auth)` gate then evaluated true for every visitor, and a deploy that dropped an env var silently turned into "everyone is signed in" (GHSA-8fpg-xm3f-6cx3, CWE-636). Configuration errors fail **closed** at the request boundary and **loudly** at startup — validate secrets and provider config at boot (module load / cold start on serverless), not on first use, and treat a config-error log line as a failed health check.

```typescript
// BAD — one DB hiccup, or one malformed header, crashes all authenticated routes
export async function getAuthenticatedUser(request: Request) {
  const raw = request.headers.get('authorization')?.slice('Bearer '.length) ?? '';
  const token = decodeURIComponent(raw);            // throws on bad %-encoding
  const session = await findSessionByToken(token);  // throws on DB error
  // ...
}

// BAD — truthy on failure: `if (auth)` in every caller now passes
export async function getAuth(request: Request) {
  try { /* ... */ } catch (e) { return { error: e.message }; }
}

// GOOD — graceful degradation, and exactly null on every failure path
export async function getAuthenticatedUser(request: Request): Promise<User | null> {
  try {
    const token = bearerFrom(request);          // returns null when absent or malformed
    if (!token) return null;
    const session = await findSessionByToken(token);
    if (!session || session.expiresAt < new Date()) return null;
    return await findUserById(session.userId);  // null when the row is gone
  } catch (err) {
    logger.error('auth helper failed', err);    // observable, but not to the caller
    return null;
  }
}
```

Callers keep the plain existence check — that is the point of the contract — and authorize on a concrete property when they need more than "signed in" (`if (!user?.emailVerified)`, `if (user.role !== 'admin')`), never on the bare truthiness of a value that could be something other than a user.
