# Username Authentication

Sign in with username as an alternative to email.

## Schema Additions

Add to **User** table:
| Field           | Type   | Constraints         |
|-----------------|--------|---------------------|
| username        | string | unique, nullable (canonical lowercase form — the lookup key) |
| displayUsername | string | nullable (the casing the user typed; cosmetic only — optional, omit if you do not need it) |

Username is nullable because existing email-only users won't have one. `displayUsername` is never a lookup key and never a uniqueness key — every comparison, uniqueness check, and sign-in resolves through the canonical `username`.

## Endpoint Changes

**POST /api/auth/sign-up** — add optional `username` field:
- Body: `{ email, password, name?, username? }`
- Validate username: 3-32 chars, alphanumeric + underscores only, case-insensitive
- Store username in lowercase
- Return 409 if username already taken. Usernames are public handles, so admitting that one exists leaks nothing — unlike the email path, which keeps its enumeration-safe 200. Run the username check before the user insert, and make the insert's constraint-violation handler discriminate by **which** unique index fired (email index → the fake 200, username index → 409) — a handler that maps every violation to the fake 200 turns a username race into a phantom account, and one that maps every violation to 409 turns a duplicate email into an enumeration oracle

**POST /api/auth/sign-in** — accept username OR email:
- Body: `{ email?, username?, password }`
- At least one of `email` or `username` must be provided
- Look up user by the provided identifier
- Return 401 with generic error if not found (do not reveal which field failed)

**PATCH /api/auth/user/username**
- Requires valid session (Bearer token) — and a fresh one if usernames are a sign-in identifier (see the sudo-mode row in `skills/security-best-practice/rules/session-security.md`)
- Body: `{ username }`
- Validate username format (same rules as sign-up)
- If the project runs **immutable usernames** (see Implementation Rules), this endpoint only *sets* a username on a row that has none: return 409 (or 403) when one is already set
- Update username, return 200 with updated user
- Return 409 if username already taken

## Implementation Rules

- Usernames are case-insensitive — always store and compare in lowercase
- Allowed characters: a-z, 0-9, underscore (_)
- Length: 3-32 characters
- Reserved usernames: block "admin", "root", "system", "null", "undefined", "api", "auth" etc.
- Sign-in should work with either email or username — determine which by checking for "@"
- Generic error messages on sign-in — do not reveal whether the username exists
- Username changes should be rate-limited (e.g., once per 24 hours)
- **Decide up front whether usernames are mutable.** If a username is ever used as a stable reference — profile URLs, `@mentions`, ACL entries, API paths, anything another user or system stores — offer an *immutable* mode: it can be set once (at sign-up, or later on a row that has none) and never changed. A rename releases the old handle to whoever registers it next, and every stale reference — bookmarks, mentions, sharing links, an allow-list — silently follows the new owner. If you do allow renames, hold the old handle unavailable for a reclaim window (14–30 days), never re-issue it to another account inside that window, and log the change
- The display form is cosmetic. If you keep a `displayUsername`, it is set from the same input as `username`, validated with the same character rules, and never consulted for lookup, uniqueness, or authorization; drop the column entirely if you have no UI that shows it

## Best Practices (Industry Consensus)

- **Case handling**: GitHub, Discord, and most platforms store usernames case-insensitively. Store a lowercase canonical form for lookups, but optionally preserve display casing separately (`displayUsername`) — better-auth 1.7 lets you disable that separate field entirely, which is the right default when nothing renders it
- **Reserved words**: Block platform-sensitive slugs (`admin`, `root`, `system`, `api`, `auth`, `www`, `mail`, `support`, `help`, `null`, `undefined`, `login`, `signup`). GitHub maintains a list of ~100 reserved names
- **Uniqueness enforcement**: Use a unique index on the lowercase form at the database level, not just application validation
- **Homograph protection**: Consider blocking confusable characters (e.g., Cyrillic "а" vs Latin "a") or restrict to ASCII. GitHub and most platforms restrict to `[a-zA-Z0-9-]`
- **Change policy**: GitHub allows username changes but the old username becomes available to others after a grace period. Rate-limit changes (1 per 24 hours) and consider a 14-day reclaim window — or make usernames immutable (better-auth 1.7 added `immutableUsername`) when they are used as identity references anywhere outside the profile page
- **Enumeration prevention**: The sign-in endpoint must return the same error for wrong username vs wrong password (OWASP). A separate "check username availability" endpoint for sign-up is acceptable but should be rate-limited

Sources: [GitHub Username Policy](https://docs.github.com/en/account-and-profile/setting-up-and-managing-your-personal-account-on-github/managing-user-account-settings/changing-your-github-username), [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
