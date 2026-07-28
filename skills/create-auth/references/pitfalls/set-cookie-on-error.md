# Pitfall: Set-Cookie must survive error paths

Auth handlers often stage cookie writes — a helper queues `Set-Cookie` and a wrapper attaches it when the response goes out. If that wrapper only runs on the success path, any exception after a state change produces a response **without** the cookie header, and the database and the browser now disagree about who is signed in:

- Sign-in creates the session row, a later step throws → error response with no cookie → orphaned live session server-side, user retries and accumulates another.
- Session rotation (2FA completion, privilege change) creates the new row and invalidates the old one, then something throws → the browser keeps the dead token → every subsequent request 401s and the user is "randomly" signed out.
- Sign-out deletes the session row, then something throws before the clearing `Set-Cookie` → the browser keeps presenting a token the server already killed, masking the real state from the user.

```typescript
// BAD — cookie attaches only if everything after session creation succeeds
app.post('/api/auth/sign-in', async (req, res) => {
  const { user, token } = await signIn(req.body);   // creates the session row
  await recordLoginEvent(user.id);                  // throws → response has no Set-Cookie
  res.setHeader('Set-Cookie', sessionCookie(token));
  res.json({ user });
});

// GOOD — cookie emission sits adjacent to the state change it reflects;
// best-effort side work cannot take the auth response down with it
app.post('/api/auth/sign-in', async (req, res) => {
  const { user, token } = await signIn(req.body);
  res.setHeader('Set-Cookie', sessionCookie(token));
  try {
    await recordLoginEvent(user.id);
  } catch (err) {
    logger.warn('login event failed', err); // do not lose the signed-in response
  }
  res.json({ user });
});
```

Rules of thumb: keep the DB state change and its cookie emission adjacent, with nothing throwable between them; if cookies are attached by middleware, run it in a layer that wraps **both** success and error responses (a `finally`, not an "after handler returns" hook); and if a handler must fail after creating a session, delete that session before returning the error.
