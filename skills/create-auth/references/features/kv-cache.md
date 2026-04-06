# KV Cache

A general-purpose key-value cache with TTL (time-to-live) support, used as the storage backbone for rate limiting and other features that need temporary, expiring data (OTP attempts, email verification tokens, lockout counters, etc.).

## Why a KV Cache Abstraction

Auth features repeatedly need the same primitive: "store a value by key, expire it after N seconds." Without a shared abstraction, every feature reinvents this — a Map with `setTimeout` for rate limiting, another Map for OTP attempts, a database table for lockouts. A single KV cache interface keeps things DRY and lets the user swap storage backends (in-memory → Redis → database) in one place.

## Interface

The KV cache exposes three operations. Implementations must be async since database/Redis backends are inherently async.

```
KVCache {
  get(key: string) → Promise<string | null>
  set(key: string, value: string, ttlSeconds: number) → Promise<void>
  delete(key: string) → Promise<void>
}
```

- **`get(key)`** — Returns the stored value, or `null` if the key doesn't exist or has expired.
- **`set(key, value, ttlSeconds)`** — Stores the value with a TTL. If the key already exists, overwrites it and resets the TTL. A `ttlSeconds` of `0` means no expiration (use sparingly).
- **`delete(key)`** — Removes the key immediately. No-op if the key doesn't exist.

Values are always strings. Callers serialize/deserialize as needed (e.g., `JSON.stringify` for structured data). This keeps the interface minimal and avoids type complexity across languages.

## Storage Backends

### 1. In-Memory (Default)

Use a language-native map/dictionary with TTL tracking. This is the zero-dependency default — no external services, no database tables.

**Implementation pattern:**
- Store entries as `{ value: string, expiresAt: number }` (epoch milliseconds)
- On `get`, check `expiresAt` against current time — return `null` if expired
- Lazy cleanup: don't bother with background timers or sweeps. Expired entries get cleaned up on next `get` or `set` for the same key. For long-running servers, optionally sweep every N minutes to prevent unbounded memory growth.

**Tradeoffs:**
- Resets on server restart (acceptable for rate limiting — attackers just get a fresh window)
- Not shared across multiple server instances (fine for single-process deployments)
- Memory grows with number of unique keys (bounded by TTL — entries expire and get cleaned up)

### 2. Database

Use a dedicated table in the project's existing database. Good for multi-instance deployments where in-memory isn't shared.

**Schema:**

**KVEntry**
| Field     | Type     | Constraints          |
|-----------|----------|----------------------|
| key       | string   | primary key          |
| value     | string   | not null             |
| expiresAt | datetime | not null (indexed)   |

**Implementation pattern:**
- `get`: SELECT where key matches AND expiresAt > now. Return `null` if no row.
- `set`: UPSERT (insert or update on conflict) with the new value and expiresAt.
- `delete`: DELETE where key matches.
- **Cleanup**: Periodically delete rows where `expiresAt < now`. This can be a cron job, a background task, or done lazily on write operations (e.g., delete expired rows in the same transaction as the upsert, but only every Nth write to avoid overhead).

**Tradeoffs:**
- Shared across all server instances
- Adds a database query per cache operation (acceptable for auth — low request volume relative to app traffic)
- Requires a migration to create the table

### 3. Custom Storage

Allow the user to provide their own implementation — typically Redis, Memcached, or a managed KV service (Cloudflare KV, Vercel KV, Upstash Redis, etc.).

**Pattern:** Accept a configuration object that implements the `get`/`set`/`delete` interface. The user wires it up to their preferred backend.

```
// Pseudocode — adapt to language idioms
createKVCache({
  get: async (key) => await redis.get(key),
  set: async (key, value, ttl) => await redis.set(key, value, { ex: ttl }),
  delete: async (key) => await redis.del(key),
})
```

## Key Namespacing

To avoid collisions between features sharing the same KV store, prefix keys by feature:

| Feature         | Key pattern                          | Example                          |
|-----------------|--------------------------------------|----------------------------------|
| Rate limiting   | `rl:{endpoint}:{identifier}`         | `rl:sign-in:192.168.1.1:user@ex.com` |
| OTP attempts    | `otp-attempt:{target}`               | `otp-attempt:user@example.com`   |
| Email verify    | `email-verify:{token}`               | `email-verify:abc123`            |
| Lockout         | `lockout:{identifier}`               | `lockout:192.168.1.1`            |

Features are responsible for constructing their own keys. The KV cache itself is agnostic to the key format.

## Implementation Rules

- **Always async.** Even the in-memory backend should use async signatures for interface consistency — it lets users swap backends without changing callsites.
- **TTL is mandatory on `set`.** There is no "store forever" default. Callers must specify a TTL. This prevents accidental memory/storage leaks.
- **Values are strings.** Serialize complex data with `JSON.stringify` / equivalent. Don't add generics or type parameters to the interface — keep it dead simple.
- **Thread/concurrency safety.** The in-memory backend must handle concurrent access correctly (not a concern in single-threaded JS, but important in Go/Rust/Python with threads). Use a mutex/lock or concurrent data structure.
- **No distributed locking.** The KV cache is not a distributed lock. Don't try to build one on top of it. For rate limiting, approximate counts are fine — a few extra requests slipping through during a race is acceptable.
- **Create the KV cache as a standalone module/file.** Don't inline it into the rate limiter or any specific feature. It should be importable by any feature that needs it.
- **Default to in-memory.** If the user doesn't configure a backend, use in-memory. Don't require setup for the simplest case.

## Configuration

The KV cache is configured once and passed (or made available) to features that need it:

```
// Pseudocode
const kvCache = createKVCache({
  storage: "memory" | "database" | { get, set, delete }
})

// Then used by features:
const rateLimiter = createRateLimiter({ kvCache, ... })
```

For the database backend, reuse the project's existing database connection — don't create a separate connection pool.

## Best Practices

- **Keep TTLs short for security data.** Rate limit windows: 1–60 minutes. OTP codes: 5–10 minutes. Don't cache auth data for hours.
- **Don't cache sensitive secrets.** Session tokens, passwords, and encryption keys should not go through the KV cache. It's for counters, temporary tokens, and flags.
- **Monitor memory in production.** For in-memory backends under high traffic, keep an eye on memory usage. If keys accumulate faster than they expire, add a periodic sweep or switch to Redis/database.
- **Graceful degradation.** If the KV backend is unavailable (Redis down, database unreachable), decide per-feature: rate limiting should fail-open (allow the request) to avoid blocking legitimate users. OTP verification should fail-closed (reject) to maintain security.

## Reference Implementations

These open-source projects implement KV cache/storage abstractions with TTL support. Study their interface designs when implementing — our `get`/`set`/`delete` interface is intentionally minimal, but these show how production systems handle the same problem at scale.

### Multi-Backend KV Abstractions (most relevant to our design)

| Project | Lang | Stars | Interface Pattern | TTL Handling | Storage Backends |
|---------|------|-------|-------------------|-------------|-----------------|
| [unstorage](https://github.com/unjs/unstorage) | TS | ~2.6k | `getItem`/`setItem`/`removeItem` with driver mounting | Via `StorageMeta.ttl` — driver-dependent (Redis handles natively, others via metadata) | 34+ drivers: Memory, Redis, Upstash, Cloudflare KV/R2, Vercel Blob, S3, MongoDB, PlanetScale, Deno KV, etc. |
| [Keyv](https://github.com/jaredwray/keyv) | TS | ~3.1k | `get`/`set(key, val, ttl?)`/`delete`/`has` with `KeyvStorageAdapter` interface | Per-call TTL in ms; values wrapped in `{ value, expires }` envelopes; checked on `get()` | 9 official: Redis, PostgreSQL, MySQL, MongoDB, SQLite, DynamoDB, Etcd, Memcache, Valkey |
| [cache-manager](https://github.com/jaredwray/cacheable) | TS | ~2.0k | `get`/`set`/`del`/`wrap` (cache-aside) | Per-call ms + dynamic TTL via `(value) => number` function | Via Keyv adapters (inherits all backends) |

**Key file pointers:**
- unstorage: `src/types.ts` (Driver interface with `hasItem`/`getItem`/`setItem`/`removeItem`), `src/drivers/` (34+ driver implementations)
- Keyv: `core/keyv/src/types/adapters.ts` (`KeyvStorageAdapter` interface), `core/keyv/src/keyv.ts` (main class)
- cache-manager: `packages/cache-manager/src/index.ts` (`Cache` interface with `wrap` pattern)

### High-Performance In-Memory Caches

These are single-backend (in-memory only) but show how to implement efficient TTL expiration, which is relevant for the in-memory backend of our KV cache.

| Project | Lang | Stars | TTL Mechanism | Notes |
|---------|------|-------|--------------|-------|
| [Ristretto](https://github.com/dgraph-io/ristretto) | Go | ~6.8k | `SetWithTTL(key, val, cost, duration)` — per-item expiration timestamps, cleanup ticker | TinyLFU admission + Sampled LFU eviction; sharded concurrent hashmap |
| [FreeCache](https://github.com/coocood/freecache) | Go | ~5.4k | `Set(key, val, expireSeconds)` — checked on `Get()` | Zero-GC design using pre-allocated ring buffers per shard (256 shards) |
| [cachetools](https://github.com/tkem/cachetools) | Python | ~2.7k | `TTLCache(maxsize, ttl)` — entries timestamped at insertion, lazy expiration via linked list | Implements Python's `MutableMapping`; `expire(time)` walks list to remove stale entries |
| [diskcache](https://github.com/grantjenks/python-diskcache) | Python | ~2.9k | `set(key, val, expire=secs)` — SQLite-backed persistent cache | Faster than Redis for single-machine; supports LRU/LFU eviction |
| [moka](https://github.com/moka-rs/moka) | Rust | ~2.5k | Builder: `time_to_live(dur)`, `time_to_idle(dur)`, per-entry `Expiry` trait | Inspired by Java's Caffeine; lazy expiration since v0.12 (no background threads) |
| [cached](https://github.com/jaemk/cached) | Rust | ~2.0k | `TimedCache::with_lifespan(dur)` stores `(Instant, V)` tuples; `IOCached` trait for Redis/disk | `Cached<K,V>` trait (in-memory), `IOCached<K,V>` trait (external backends with `cache_get`/`cache_set`/`cache_remove`) |

**Key file pointers:**
- Ristretto: `cache.go` (public API), `ttl.go` (expiration internals)
- cachetools: `src/cachetools/__init__.py` (`TTLCache` with linked-list expiry)
- moka: `src/sync/cache.rs` (sync cache), `src/future/cache.rs` (async cache)
- cached: `src/lib.rs` (`Cached`/`IOCached`/`CachedAsync` traits), `src/stores/timed.rs` (TTL store)

### Storage Interface Patterns Across Ecosystems

The minimum viable interface for a KV cache with TTL (what we implement):

```
get(key) → value | null       // Read; return null if expired
set(key, value, ttl) → void   // Write with expiration
delete(key) → void             // Remove immediately
```

Comparison with production systems:

| Our Interface | unstorage | Keyv | Ristretto (Go) | cached (Rust) |
|---------------|-----------|------|-----------------|---------------|
| `get(key)` | `getItem(key)` | `get(key)` | `Get(key)` | `cache_get(k)` |
| `set(key, val, ttl)` | `setItem(key, val)` + meta | `set(key, val, ttl)` | `SetWithTTL(k, v, cost, dur)` | `cache_set(k, v)` + lifespan |
| `delete(key)` | `removeItem(key)` | `delete(key)` | `Del(key)` | `cache_remove(k)` |
