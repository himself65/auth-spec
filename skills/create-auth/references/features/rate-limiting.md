# Rate Limiting

Throttle authentication endpoints to prevent brute-force attacks, credential stuffing, and flood-style abuse. Uses the KV cache abstraction (`references/features/kv-cache.md`) as its storage backend.

## How It Works

Rate limiting tracks request counts per key (IP address, email, token, or combination) within a time window. When a client exceeds the limit, the server returns `429 Too Many Requests` with a `Retry-After` header telling the client when to try again.

The rate limiter is implemented as **middleware** that runs before the endpoint handler. It uses the KV cache to store counters, so the storage backend (in-memory, database, Redis) is configurable without changing the rate limiting logic itself.

## Schema Additions

None — rate limiting state is stored in the KV cache, not in dedicated tables. If the user chose "database" as their KV cache backend, the shared `KVEntry` table (defined in `kv-cache.md`) handles storage.

## Algorithm: Fixed Window Counter

Use a fixed-window counter. It's the simplest approach and sufficient for auth endpoints (which handle low-to-moderate traffic compared to data APIs).

**How it works:**
1. Build the rate limit key from the request (see Key Composition below)
2. `GET` the current counter from the KV cache using key `rl:{endpoint}:{identifier}`
3. If no entry exists (or expired): `SET` counter to `"1"` with TTL = window size → allow request
4. If entry exists and count < max: `SET` counter to `count + 1` with **the same remaining TTL** → allow request
5. If entry exists and count >= max: reject with 429

**Remaining TTL matters.** When incrementing, don't reset the TTL to the full window — that would create a sliding window. Read the expiry from the existing entry and preserve it. If your KV backend doesn't expose remaining TTL, store the window start timestamp in the value alongside the count (e.g., `JSON.stringify({ count, windowStart })`), and compute the remaining TTL as `windowSize - (now - windowStart)`.

## Default Limits

| Endpoint                    | Window   | Max Requests | Key                          |
|-----------------------------|----------|-------------|------------------------------|
| `POST /api/auth/sign-in`    | 15 min   | 5           | IP + email                   |
| `POST /api/auth/sign-up`    | 1 hour   | 10          | IP                           |
| `POST /api/auth/sign-out`   | 1 min    | 10          | session token                |
| `POST /api/auth/*/send`     | 10 min   | 3           | target (email or phone)      |
| `POST /api/auth/*/verify`   | 15 min   | 5           | target (email or phone)      |
| `GET  /api/auth/session`    | —        | —           | **Not rate limited** (read-only, token-protected) |

These are defaults. The skill should generate them as configurable constants (environment variables or a config object) so the user can tune without editing middleware code.

## Key Composition

The rate limit key determines what is being throttled. Use the pattern `rl:{endpoint}:{identifier}`:

- **Sign-in**: `rl:sign-in:{ip}:{email}` — keyed on both IP and email. This prevents credential stuffing (many passwords for one email) while still allowing different users from the same IP (e.g., corporate NAT, shared wifi).
- **Sign-up**: `rl:sign-up:{ip}` — keyed on IP only. Email isn't useful here because attackers use different emails.
- **Sign-out**: `rl:sign-out:{token}` — keyed on session token. Prevents abuse of the sign-out endpoint.
- **OTP/magic-link send**: `rl:send:{target}` — keyed on the target (email or phone). Prevents spamming a single recipient.
- **OTP/magic-link verify**: `rl:verify:{target}` — keyed on target. Prevents brute-forcing short codes.

### IP Address Extraction

Extract the client IP from request headers in this order:
1. `X-Forwarded-For` (first value — the client IP before proxies)
2. `X-Real-IP`
3. Direct connection IP (socket remote address)

**Normalize IPv6:** Convert IPv4-mapped IPv6 addresses (like `::ffff:192.168.1.1`) to their IPv4 form. This prevents bypass attacks where the same client appears as two different IPs.

## Middleware Implementation

The rate limiter should be structured as middleware that can be applied to individual routes or groups of routes.

**Pseudocode:**

```
function rateLimitMiddleware(kvCache, config) {
  return async function(request, next) {
    // 1. Build the key
    const key = buildRateLimitKey(request, config.endpoint)

    // 2. Check current count
    const entry = await kvCache.get(key)

    if (entry === null) {
      // First request in this window
      await kvCache.set(key, JSON.stringify({ count: 1, windowStart: now() }), config.windowSeconds)
      return next(request)
    }

    const { count, windowStart } = JSON.parse(entry)

    if (count >= config.max) {
      // Over limit
      const retryAfter = config.windowSeconds - secondsSince(windowStart)
      return respond(429, {
        error: "rate_limited",
        message: "Too many requests. Please try again later.",
        retryAfter: Math.max(retryAfter, 1)
      }, { "Retry-After": String(Math.max(retryAfter, 1)) })
    }

    // Increment — preserve the original window expiry
    const remainingTtl = config.windowSeconds - secondsSince(windowStart)
    await kvCache.set(key, JSON.stringify({ count: count + 1, windowStart }), Math.max(remainingTtl, 1))
    return next(request)
  }
}
```

## Response on Rate Limit

- **Status:** `429 Too Many Requests`
- **Headers:** `Retry-After: {seconds until window resets}`
- **Body:**
  ```json
  {
    "error": "rate_limited",
    "message": "Too many requests. Please try again later.",
    "retryAfter": 42
  }
  ```

The `retryAfter` value in the body mirrors the `Retry-After` header for convenience — clients can use either.

## Custom Rules

Allow per-endpoint overrides of the default limits. The generated code should support a configuration like:

```
rateLimitRules: {
  "sign-in": { window: 900, max: 5 },      // 15 min, 5 requests
  "sign-up": { window: 3600, max: 10 },     // 1 hour, 10 requests
  "sign-out": { window: 60, max: 10 },
  // Add custom rules for any endpoint:
  "two-factor/challenge": { window: 600, max: 3 },
}
```

Setting an endpoint to `false` or `null` disables rate limiting for that endpoint. This is useful for internal/trusted endpoints.

## Implementation Rules

- **Use the KV cache** — read `references/features/kv-cache.md` for the storage interface. Don't create a separate storage mechanism for rate limiting. If the user already selected KV cache features, reuse the same instance.
- **Create the rate limiter as reusable middleware**, not inline in each route handler. Each route applies the middleware with its specific config (window, max, key builder).
- **Always include `Retry-After` header** on 429 responses. This is required by HTTP spec (RFC 6585) and expected by well-behaved clients.
- **Make limits configurable.** Use environment variables or a config object — don't hardcode window sizes and max counts into the middleware.
- **Don't rate limit `GET /session`** — it's read-only and already token-protected. Rate limiting it would add latency to every authenticated page load.
- **Fail open.** If the KV cache is unavailable (Redis down, database timeout), allow the request through. Blocking legitimate users is worse than temporarily losing rate limiting. Log the error for monitoring.
- **Don't use distributed locking.** A few extra requests sneaking through during a race condition between cache read and write is fine. Auth rate limits are approximate by nature.
- **IP behind proxies.** Document that the user must configure their reverse proxy (nginx, Cloudflare, etc.) to set `X-Forwarded-For` correctly. If `X-Forwarded-For` is absent, fall back to the connection IP — but warn that rate limiting may not work correctly behind a proxy without this header.

## Best Practices (Industry Consensus)

- **Fixed window is sufficient for auth endpoints.** The simplicity outweighs the edge-case burst at window boundaries. Sliding window is better for high-throughput data APIs, but auth endpoints don't see that traffic pattern.
- **Key on IP + email for sign-in.** This is the standard approach to prevent credential stuffing while allowing multiple users from the same network (corporate NAT, university wifi).
- **Treat password reset as a login endpoint** in terms of rate limiting. OWASP guidance: password reset is functionally equivalent to authentication and should have the same protections.
- **Limit OTP validation attempts.** Cap verification tries (e.g., 5 per 15 min per target) to prevent brute-forcing short codes. A 6-digit OTP has only ~20 bits of entropy — without rate limiting, it can be brute-forced in seconds.
- **Progressive delays for repeated failures.** Consider exponential backoff (doubling the wait after each failure) for the same key. This slows automated attacks without permanently locking legitimate users. Implementation: track failure count in the KV cache alongside the rate limit counter.
- **Return consistent error shapes.** The 429 response body should match the project's error format for other endpoints (same `error` field name, same structure). Don't introduce a different error format just for rate limiting.
- **Log rate limit hits.** Log when a client is rate-limited (IP, endpoint, count) for security monitoring. Don't log the full request body — it may contain passwords.
- **Normalize IPv6.** Convert `::ffff:x.x.x.x` to plain IPv4. Without this, the same client can trivially bypass IP-based limits by switching address formats.

## Reference Implementations

These open-source projects demonstrate rate limiting patterns across languages and ecosystems. Study their storage interfaces and algorithm choices when implementing.

### Node.js / TypeScript

| Project | Stars | Algorithm | Storage Backends | Key Files |
|---------|-------|-----------|-----------------|-----------|
| [express-rate-limit](https://github.com/express-rate-limit/express-rate-limit) | ~3.2k | Fixed window (dual-map rotation) | In-memory (built-in); Redis, Memcached, MongoDB, PostgreSQL via community stores | `source/memory-store.ts` (store impl), `source/types.ts` (`Store` interface: `increment(key)`) |
| [rate-limiter-flexible](https://github.com/animir/node-rate-limiter-flexible) | ~3.5k | Enhanced fixed window (atomic increments) | Memory, Redis, PostgreSQL, MySQL, MongoDB, Memcached, DynamoDB, SQLite, Prisma, Drizzle | `lib/RateLimiterStoreAbstract.js` (abstract store: `_upsert`, `_get`, `_delete`), `lib/RateLimiterRedis.js`, `lib/RateLimiterPostgres.js` |
| [@upstash/ratelimit](https://github.com/upstash/ratelimit-js) | ~2.0k | Fixed window, sliding window, token bucket (all via Lua scripts) | Upstash Redis (HTTP-based, serverless) | `src/lua-scripts/single.ts` (Lua scripts for all 3 algorithms), `src/single.ts` |
| [better-auth](https://github.com/better-auth/better-auth) | ~8k | Fixed window | In-memory, database, secondary storage, custom `get`/`set` | `docs/content/docs/concepts/rate-limit.mdx` (design), custom storage via `rateLimit.customStorage` |

### Go

| Project | Stars | Algorithm | Storage Backends | Key Files |
|---------|-------|-----------|-----------------|-----------|
| [golang.org/x/time/rate](https://github.com/golang/time) | stdlib | Token bucket | In-memory only | `rate/rate.go` (`Limiter` struct: `Allow()`, `Reserve()`, `Wait()`) |
| [ulule/limiter](https://github.com/ulule/limiter) | ~2.1k | Fixed window | Redis, in-memory | `store.go` (`Store` interface: `Get`, `Peek`, `Reset`, `Increment`), `drivers/store/redis/`, `drivers/middleware/stdlib/` |
| [throttled](https://github.com/throttled/throttled) | ~1.6k | GCRA (Generic Cell Rate Algorithm) | In-memory, Redis (redigo, go-redis v8/v9) | `rate.go`, `store.go` (storage interface), `store/memstore/`, `store/goredisstore.v9/` |
| [sethvargo/go-limiter](https://github.com/sethvargo/go-limiter) | ~715 | Token bucket | In-memory | `store.go` (`Store` interface: `Take`, `Get`, `Set`, `Burst`, `Close`) |
| [Supabase Auth](https://github.com/supabase/auth) | ~2.4k | Token bucket (via tollbooth) | In-memory only | `internal/api/middleware.go` (rate limit middleware), `internal/conf/configuration.go` (per-endpoint limits: email 30/hr, SMS 30/hr, verify 30/hr) |

### Python

| Project | Stars | Algorithm | Storage Backends | Key Files |
|---------|-------|-----------|-----------------|-----------|
| [limits](https://github.com/alisaifee/limits) | ~614 | Fixed window, moving window, sliding window counter | Memory, Redis (standalone/Cluster/Sentinel), Memcached, MongoDB | `limits/strategies.py` (all 3 algorithms), `limits/storage/base.py` (storage interface), `limits/storage/redis.py` |
| [slowapi](https://github.com/laurentS/slowapi) | ~1.9k | Delegates to `limits` library | Inherits from `limits` | `slowapi/extension.py`, `slowapi/middleware.py` (Starlette middleware) |

### Rust

| Project | Stars | Algorithm | Storage Backends | Key Files |
|---------|-------|-----------|-----------------|-----------|
| [governor](https://github.com/antifuchs/governor) | ~898 | GCRA | In-memory (DashMap) | `governor/src/gcra.rs` (GCRA impl), `governor/src/state/keyed.rs` (per-key state) |
| [tower rate_limit](https://github.com/tower-rs/tower) | ~4.2k | Fixed window | In-memory only | `tower/src/limit/rate/service.rs` (`RateLimit` service with `until`/`rem` tracking) |

### Auth Platforms

| Platform | Approach | Notes |
|----------|----------|-------|
| [Supabase Auth](https://github.com/supabase/auth) | In-memory token bucket (tollbooth) | No Redis; each instance handles its own traffic. Per-endpoint limits: email 30/hr, SMS 30/hr, OTP 30/hr, token refresh 150/hr |
| [Unkey](https://github.com/unkeyed/unkey) (~5.2k stars) | Sliding window with distributed replication | `internal/services/ratelimit/window.go` (duration-aligned windows), `janitor.go` (cleanup), `replay.go` (cross-node consistency) |
| [better-auth](https://github.com/better-auth/better-auth) | Fixed window, pluggable storage | 60s window / 100 req default; supports in-memory, database, custom `get`/`set` |

Sources: [OWASP API Security — Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/), [OWASP API Security — Unrestricted Resource Consumption](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/), [Cloudflare Rate Limiting Best Practices](https://developers.cloudflare.com/waf/rate-limiting-rules/best-practices/), [better-auth Rate Limiting](https://www.better-auth.com/docs/concepts/rate-limit)
