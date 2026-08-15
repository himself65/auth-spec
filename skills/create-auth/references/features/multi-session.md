# Multi-Session

Allow multiple concurrent sessions per user with session listing and selective revocation.

## Schema Additions

None — the core **Session** table already includes nullable `userAgent` and `ipAddress` columns, captured at session creation. They are what lets users identify their sessions (e.g., "Chrome on macOS"). If this project scaffolded its core auth before those columns existed, add them now as nullable strings and start populating them on sign-in/sign-up.

## Endpoints

**GET /api/auth/sessions**
- Requires valid session (Bearer token)
- Return all active (non-expired) sessions for the current user
- Each session includes: `{ id, createdAt, expiresAt, userAgent, ipAddress, current }`
- `current: true` for the session matching the request token
- Do NOT return session tokens — only metadata

**DELETE /api/auth/sessions/:sessionId**
- Requires valid session (Bearer token)
- Delete the specified session if it belongs to the current user
- Return 404 if the session doesn't exist or doesn't belong to the user
- Cannot delete the current session (use sign-out instead) — return 400
- Return 200 on success

**DELETE /api/auth/sessions**
- Requires valid session (Bearer token)
- Delete all sessions for the current user EXCEPT the current one
- Return `{ revoked: {count} }` with the number of sessions deleted

## Implementation Rules

- Store userAgent and ipAddress on session creation (from request headers)
- Never expose session tokens in the list endpoint — only IDs and metadata
- The "current" flag is determined by comparing session IDs, not tokens
- When deleting a single session, verify ownership (userId matches)
- The "delete all" endpoint preserves the current session for safety
- Session listing should only return non-expired sessions
- Order sessions by createdAt descending (most recent first)
- Implement "delete all" as one set-based delete keyed on userId and excluding the current session id (`DELETE FROM session WHERE user_id = $1 AND id <> $2`), not a loop over the listing results — a listing that comes back short (a bad row, pagination, a stale cache) would leave sessions alive while the response still reports `{ revoked: n }`
- If sessions are also cached or mirrored outside the session table, revoke from every store and report success only once all of them succeeded — a failed read of one store must not skip the delete against the other

## Best Practices (Industry Consensus)

- **Store device fingerprint (userAgent + IP) for identification.** GitHub and Google both display browser name, OS, and approximate location derived from IP so users can recognize their own sessions and spot unauthorized access.
- **Never expose session tokens in the list endpoint — only metadata.** Return id, createdAt, expiresAt, userAgent, ipAddress, and a `current` boolean. Leaking tokens in API responses is a common vulnerability (OWASP Session Management Cheat Sheet).
- **Session list should be paginated** for users with many devices or long-lived sessions. Default page size of 20-50 is typical; return a total count.
- **"Current" detection uses session ID comparison, not the raw token.** Match the session ID associated with the request's bearer token, never compare tokens directly in application logic.
- **Revoke-all should keep the current session** as a safety net so the user does not lock themselves out. Both GitHub and Google follow this pattern. Return the count of revoked sessions.
- **Consider session anomaly detection.** Flag sessions where the IP or userAgent changes dramatically mid-session (possible token theft). Google prompts re-authentication in such cases.
- **Set absolute and idle timeouts.** OWASP recommends both: an absolute max lifetime (e.g., 30 days) and an idle timeout (e.g., 24 hours of inactivity) to limit exposure of stolen tokens.
