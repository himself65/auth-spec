# Rate Limiting

Throttle authentication endpoints to prevent brute-force attacks.

## Schema Additions (if using database-backed rate limiting)

**RateLimitEntry**
| Field     | Type     | Constraints        |
|-----------|----------|--------------------|
| id        | string   | primary key        |
| key       | string   | not null (indexed) |
| count     | integer  | not null, default 0 |
| windowStart | datetime | not null           |
| expiresAt | datetime | not null           |

Alternatively, use in-memory storage (Map/cache) or Redis for rate limiting. The database approach is shown as a fallback.

## Default Limits

| Endpoint                  | Window   | Max Requests |
|---------------------------|----------|-------------|
| POST /api/auth/sign-in    | 15 min   | 5 per IP + email combo |
| POST /api/auth/sign-up    | 1 hour   | 10 per IP   |
| POST /api/auth/sign-out   | 1 min    | 10 per token |
| POST /api/auth/*/send     | 10 min   | 3 per target (email/phone) |
| POST /api/auth/*/verify   | 15 min   | 5 per target |

## Implementation as Middleware

Create a rate-limiting middleware that:
1. Extracts the rate limit key from the request (IP, email, token, or combination)
2. Looks up or creates a rate limit entry for this key + endpoint
3. If window has expired: reset count to 1, update windowStart
4. If count exceeds limit: return 429 with `Retry-After` header
5. Otherwise: increment count and proceed

## Response on Rate Limit

- Status: 429 Too Many Requests
- Headers: `Retry-After: {seconds until window resets}`
- Body: `{ error: "rate_limited", message: "Too many requests. Please try again later.", retryAfter: {seconds} }`

## Implementation Rules

- Rate limit keys should include IP address for unauthenticated endpoints
- For sign-in, key on both IP AND email to prevent credential stuffing while allowing different users from the same IP
- Use sliding window or fixed window (fixed window is simpler and sufficient for auth)
- In-memory rate limiting resets on server restart — acceptable for most deployments
- For distributed deployments, use Redis or database-backed rate limiting
- Always include `Retry-After` header in 429 responses
- Make limits configurable via environment variables or config
- Do not rate limit the session GET endpoint (read-only, already token-protected)

## Best Practices (Industry Consensus)

- **Algorithm choices**: fixed window (simple, resets at interval boundaries), sliding window (smoother, avoids burst at window edges), token bucket (flexible, allows short bursts while enforcing average rate)
- **Fixed window is sufficient for auth endpoints**: the simplicity outweighs edge-case burst issues for login/signup flows; sliding window is better for high-throughput APIs
- **Key composition**: for sign-in, key on IP + email to prevent credential stuffing while still allowing different users from the same IP (e.g., corporate NAT)
- **Always return `Retry-After` header** on 429 responses — OWASP and HTTP spec both require it; include seconds until the window resets
- **In-memory is fine for single-server** deployments (resets on restart — acceptable for auth); use Redis or a distributed store for multi-instance deployments
- **Don't rate limit read-only endpoints** like `GET /session` — they are already token-protected and add unnecessary friction
- **Progressive delays**: consider exponential backoff (1s, 2s, 4s, 8s...) for repeated failures on the same key — this slows automated attacks without hard-locking legitimate users
- **Treat password reset as a login endpoint** in terms of rate limiting and brute-force protection (OWASP guidance)
- **Limit OTP validation attempts**: cap verification tries (e.g., 5 per 15 min) to prevent brute-forcing short codes

Sources: [OWASP API Security — Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/), [OWASP API Security — Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/), [Cloudflare Rate Limiting Best Practices](https://developers.cloudflare.com/waf/rate-limiting-rules/best-practices/)
