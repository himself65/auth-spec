# KV Cache

A general-purpose key-value cache with TTL (time-to-live) support, used as the storage backbone for rate limiting and other features that need temporary, expiring data (OTP attempts, email verification tokens, lockout counters, etc.).

## Why a KV Cache Abstraction

Auth features repeatedly need the same primitive: "store a value by key, expire it after N seconds." Without a shared abstraction, every feature reinvents this — a Map with `setTimeout` for rate limiting, another Map for OTP attempts, a database table for lockouts. A single KV cache interface keeps things DRY and lets the user swap storage backends (in-memory → Redis → database) in one place.

## Interface

The KV cache exposes five operations. Implementations must be async since database/Redis backends are inherently async.

```
KVCache {
  get(key: string) → Promise<string | null>
  set(key: string, value: string, ttlSeconds: number) → Promise<void>
  delete(key: string) → Promise<void>
  getAndDelete(key: string) → Promise<string | null>
  increment(key: string, ttlSeconds: number) → Promise<number>
}
```

- **`get(key)`** — Returns the stored value, or `null` if the key doesn't exist or has expired.
- **`set(key, value, ttlSeconds)`** — Stores the value with a TTL. If the key already exists, overwrites it and resets the TTL. A `ttlSeconds` of `0` means no expiration (use sparingly).
- **`delete(key)`** — Removes the key immediately. No-op if the key doesn't exist.
- **`getAndDelete(key)`** — Returns the stored value and removes it, in **one** operation; `null` if absent or expired. This is how a single-use value kept in the cache whose presented form *is* the key (a WebAuthn challenge, a short-lived OAuth `state`, a hashed magic-link token) is consumed: two concurrent callers get at most one non-`null` answer. `get` followed by `delete` is the find-then-consume race in `references/pitfalls/single-use-token-race.md`. A low-entropy code keyed by its *target* is consumed with it only after the code matched — see that pitfall for the ordering.
- **`increment(key, ttlSeconds)`** — Atomically adds one to the integer counter at `key` and returns the new value. The TTL is applied **only when the key is created** (the call that returns `1`); later increments leave the existing expiry alone, so a window closes when it was opened, not `ttlSeconds` after the last hit. An expired key counts as absent and restarts at `1`. `ttlSeconds` must be `> 0` here — `0` is not "forever" for a counter (Redis `EXPIRE key 0` deletes the key, a database `now() + 0` is already expired); reject it. This is how attempt caps, lockout counters and rate-limit buckets are bumped — the caller decides on the returned value, so check-and-increment is a single step and a burst of concurrent requests cannot all pass the same stale count.

The two atomic operations exist because a plain `get`/`set` cache cannot express "consume once" or "count concurrently"; better-auth 1.7 made the equivalents mandatory for the same reason — `getAndDelete` and `increment` on secondary storage, a single `consume` on custom rate-limit stores, `incrementOne`/`consumeOne` on database adapters — and dropped support for `get`/`set`-shaped rate-limit stores.

Values are always strings (the counter is exposed as a number but may be stored as a string). Callers serialize/deserialize as needed (e.g., `JSON.stringify` for structured data). This keeps the interface minimal and avoids type complexity across languages.

## Storage Backends

### 1. In-Memory (Default)

Use a language-native map/dictionary with TTL tracking. This is the zero-dependency default — no external services, no database tables.

**Implementation pattern:**
- Store entries as `{ value: string, expiresAt: number }` (epoch milliseconds)
- On `get`, check `expiresAt` against current time — return `null` if expired
- `getAndDelete`: read the entry, delete it, return the value (or `null` if absent/expired) — one critical section
- `increment`: if the entry is absent or expired, create `{ value: "1", expiresAt: now + ttl }` and return `1`; otherwise parse, add one, store, and return the new count **without touching `expiresAt`** — one critical section
- Lazy cleanup: don't bother with background timers or sweeps. Expired entries get cleaned up on the next `get`/`set`/`getAndDelete`/`increment` for the same key. For long-running servers, optionally sweep every N minutes to prevent unbounded memory growth.

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
- `getAndDelete`: one statement — `DELETE FROM kv_entry WHERE key = $1 AND expires_at > now() RETURNING value`. No row back means absent, expired, or already consumed by a concurrent caller; all three are `null`.
- `increment`: one statement — an upsert whose conflict branch adds one only while the row is live, and restarts otherwise:
  ```sql
  INSERT INTO kv_entry (key, value, expires_at) VALUES ($1, '1', now() + $2 * interval '1 second')
  ON CONFLICT (key) DO UPDATE SET
    value      = CASE WHEN kv_entry.expires_at > now() THEN (kv_entry.value::bigint + 1)::text ELSE '1' END,
    expires_at = CASE WHEN kv_entry.expires_at > now() THEN kv_entry.expires_at ELSE now() + $2 * interval '1 second' END
  RETURNING value;
  ```
  Under READ COMMITTED the database serializes concurrent upserts on the primary key and re-evaluates the conflicting row on its latest version, so every caller sees a distinct count (at REPEATABLE READ / SERIALIZABLE the loser gets a serialization failure and retries). Adapt the syntax to the engine — MySQL has no `RETURNING`; use `ON DUPLICATE KEY UPDATE value = LAST_INSERT_ID(…)` and read `LAST_INSERT_ID()` in the same round trip, and quote `key`, which is reserved there. The shape — single statement, TTL preserved on the live branch — is what matters.
- **Cleanup**: Periodically delete rows where `expiresAt < now`. This can be a cron job, a platform-guaranteed background task (`waitUntil` / a queue), or done lazily on write operations (e.g., delete expired rows in the same transaction as the upsert, but only every Nth write to avoid overhead). Don't leave the sweep as a bare unawaited promise on the request path — on serverless the instance is frozen once the response returns and the sweep never runs, letting the table grow without bound. Await it when no guaranteed background mechanism is configured. Correctness never depends on the sweep (`get` already filters on `expiresAt > now`); only storage growth does.

**Tradeoffs:**
- Shared across all server instances
- Adds a database query per cache operation (acceptable for auth — low request volume relative to app traffic)
- Requires a migration to create the table

### 3. Custom Storage

Allow the user to provide their own implementation — typically Redis, Memcached, or a managed KV service (Cloudflare KV, Vercel KV, Upstash Redis, etc.).

**Pattern:** Accept a configuration object that implements all five operations. The user wires it up to their preferred backend. `getAndDelete` and `increment` must be genuinely atomic on that backend — a wrapper that fakes them with two round trips reintroduces the race the interface exists to remove.

```
// Pseudocode — adapt to language idioms
const INCR = `local v = redis.call("INCR", KEYS[1])
if v == 1 then redis.call("EXPIRE", KEYS[1], ARGV[1]) end
return v`;  // TTL only on creation; a Lua script keeps INCR + EXPIRE atomic across clients

createKVCache({
  get: async (key) => await redis.get(key),
  set: async (key, value, ttl) => await redis.set(key, value, { ex: ttl }),
  delete: async (key) => await redis.del(key),
  getAndDelete: async (key) => await redis.getDel(key),          // GETDEL, Redis ≥ 6.2
  increment: async (key, ttl) => Number(await redis.eval(INCR, { keys: [key], arguments: [String(ttl)] })),
})
```

On Redis ≥ 7.0 the script can be replaced by `INCR` followed by `EXPIRE key ttl NX` inside a `MULTI`/`EXEC`; below 6.2, `getAndDelete` is a one-line Lua `GET` + `DEL` script rather than two calls. A store that cannot do an atomic read-and-delete **and** an atomic increment (eventually-consistent edge KV such as Cloudflare KV) cannot back this interface at all — use the database backend for the whole cache, or add an explicit hybrid configuration; never fake either operation with two round trips.

## Key Namespacing

To avoid collisions between features sharing the same KV store, prefix keys by feature:

| Feature         | Key pattern                          | Example                          |
|-----------------|--------------------------------------|----------------------------------|
| Rate limiting   | `rl:{endpoint}:{identifier}:{windowStart}` | `rl:sign-in:192.168.1.1:user@ex.com:1755550800` (bumped with `increment`) |
| OTP attempts    | `otp-attempt:{target}`               | `otp-attempt:user@example.com` (bumped with `increment`) |
| Email verify    | `email-verify:{sha256(token)}`       | `email-verify:9f86d0…` (keyed by the token's hash, never the raw token; the lookup and the consume are one `getAndDelete`) |
| Lockout         | `lockout:{identifier}`               | `lockout:192.168.1.1` (bumped with `increment`) |

Features are responsible for constructing their own keys. The KV cache itself is agnostic to the key format.

## Implementation Rules

- **Always async.** Even the in-memory backend should use async signatures for interface consistency — it lets users swap backends without changing callsites.
- **TTL is mandatory on `set`.** There is no "store forever" default. Callers must specify a TTL. This prevents accidental memory/storage leaks.
- **Values are strings.** Serialize complex data with `JSON.stringify` / equivalent. Don't add generics or type parameters to the interface — keep it dead simple.
- **A value that comes back unparseable is not a value.** Entries can be truncated by an eviction, overwritten by other tooling, or hold the literal string `"null"` — which is truthy, so a `if (value)` guard passes it through, and `JSON.parse("null")` then yields `null`. Guard every deserialize: a parse failure, a `null`, or a wrong-shaped result must be handled as the feature's failure case (see **Graceful degradation** below), never allowed to throw out of the caller or flow onward as real data.
- **One segment shape per key prefix.** Key segments are user-controlled (emails, IPs, user IDs), so a prefix that holds an IP for one caller and an email for another collides — an attacker who registers the username `192.168.1.1` then shares a victim IP's `lockout:` counter, and can drain or reset it. Fix one shape per prefix, or hash the variable segment. A charset allow-list is the wrong tool here: the key patterns above legitimately contain `@`, `.`, and `:`.
- **Never enumerate the keyspace.** The interface has no list-by-prefix on purpose. A maintenance sweep or test-only `clear()` in a backend adapter must page with a cursor (Redis `SCAN`, never `KEYS`) and escape `* ? [ ] \` before interpolating into a `MATCH` glob — an unescaped pattern deletes keys this store does not own.
- **Thread/concurrency safety.** The in-memory backend must handle concurrent access correctly (not a concern in single-threaded JS, but important in Go/Rust/Python with threads). Use a mutex/lock or concurrent data structure.
- **No distributed locking — the two atomic operations are the whole concurrency story.** The KV cache is not a distributed lock; don't build one on top of it. Anything that must be exactly-once (`getAndDelete`) or counted under concurrency (`increment`) uses the primitive that is atomic on the backend, and everything else tolerates last-writer-wins. Never emulate either primitive with `get` then `set`/`delete`: that is precisely the read-modify-write race that lets a burst of concurrent requests share one stale count, or two callers redeem one single-use value.
- **Create the KV cache as a standalone module/file.** Don't inline it into the rate limiter or any specific feature. It should be importable by any feature that needs it.
- **Default to in-memory.** If the user doesn't configure a backend, use in-memory. Don't require setup for the simplest case.

## Configuration

The KV cache is configured once and passed (or made available) to features that need it:

```
// Pseudocode
const kvCache = createKVCache({
  storage: "memory" | "database" | { get, set, delete, getAndDelete, increment }
})

// Then used by features:
const rateLimiter = createRateLimiter({ kvCache, ... })
```

For the database backend, reuse the project's existing database connection — don't create a separate connection pool.

## Best Practices

- **Keep TTLs short for security data.** Rate limit windows: 1–60 minutes. OTP codes: 5–10 minutes. Don't cache auth data for hours.
- **Don't cache sensitive secrets.** Passwords and encryption keys never go through the KV cache — it's for counters, temporary tokens, and flags. Session snapshots are a constrained opt-in, not a flat ban: caching one buys a revocation lag equal to its TTL, so the session table stays the default authority and any cached read must satisfy `skills/security-best-practice/rules/session-security.md` (**Cached session snapshots**) — low-consequence reads only, embedded expiry verified, the entry dropped in the same operation that revokes.
- **Monitor memory in production.** For in-memory backends under high traffic, keep an eye on memory usage. If keys accumulate faster than they expire, add a periodic sweep or switch to Redis/database.
- **Graceful degradation.** If the KV backend is unavailable (Redis down, database unreachable), decide per-feature: rate limiting should fail-open (allow the request) to avoid blocking legitimate users. OTP verification should fail-closed (reject) to maintain security.

## Reference Implementations

These open-source projects implement KV cache/storage abstractions with TTL support. Study their interface designs when implementing — our five-operation interface is intentionally minimal, but these show how production systems handle the same problem at scale.

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
get(key) → value | null            // Read; return null if expired
set(key, value, ttl) → void        // Write with expiration
delete(key) → void                 // Remove immediately
getAndDelete(key) → value | null   // Consume once — one atomic read-and-remove
increment(key, ttl) → number       // Atomic counter; TTL set only on creation
```

Comparison with production systems (the general-purpose caches stop at the first three; the atomic pair is what auth-specific stores add):

| Our Interface | unstorage | Keyv | Ristretto (Go) | cached (Rust) | better-auth `SecondaryStorage` |
|---------------|-----------|------|-----------------|---------------|-------------------------------|
| `get(key)` | `getItem(key)` | `get(key)` | `Get(key)` | `cache_get(k)` | `get(key)` |
| `set(key, val, ttl)` | `setItem(key, val)` + meta | `set(key, val, ttl)` | `SetWithTTL(k, v, cost, dur)` | `cache_set(k, v)` + lifespan | `set(key, val, ttl)` |
| `delete(key)` | `removeItem(key)` | `delete(key)` | `Del(key)` | `cache_remove(k)` | `delete(key)` |
| `getAndDelete(key)` | — | — | — | — | `getAndDelete(key)` (required since 1.7) |
| `increment(key, ttl)` | — | — | — | — | `increment(key, ttl)` (required since 1.7) |
