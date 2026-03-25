# Username Authentication

Sign in with username as an alternative to email.

## Schema Additions

Add to **User** table:
| Field    | Type   | Constraints         |
|----------|--------|---------------------|
| username | string | unique, nullable    |

Username is nullable because existing email-only users won't have one.

## Endpoint Changes

**POST /api/auth/sign-up** — add optional `username` field:
- Body: `{ email, password, name?, username? }`
- Validate username: 3-32 chars, alphanumeric + underscores only, case-insensitive
- Store username in lowercase
- Return 409 if username already taken (same as email conflict)

**POST /api/auth/sign-in** — accept username OR email:
- Body: `{ email?, username?, password }`
- At least one of `email` or `username` must be provided
- Look up user by the provided identifier
- Return 401 with generic error if not found (do not reveal which field failed)

**PATCH /api/auth/user/username**
- Requires valid session (Bearer token)
- Body: `{ username }`
- Validate username format (same rules as sign-up)
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

## Best Practices (Industry Consensus)

- **Case handling**: GitHub, Discord, and most platforms store usernames case-insensitively. Store a lowercase canonical form for lookups, but optionally preserve display casing separately
- **Reserved words**: Block platform-sensitive slugs (`admin`, `root`, `system`, `api`, `auth`, `www`, `mail`, `support`, `help`, `null`, `undefined`, `login`, `signup`). GitHub maintains a list of ~100 reserved names
- **Uniqueness enforcement**: Use a unique index on the lowercase form at the database level, not just application validation
- **Homograph protection**: Consider blocking confusable characters (e.g., Cyrillic "а" vs Latin "a") or restrict to ASCII. GitHub and most platforms restrict to `[a-zA-Z0-9-]`
- **Change policy**: GitHub allows username changes but the old username becomes available to others after a grace period. Rate-limit changes (1 per 24 hours) and consider a 14-day reclaim window
- **Enumeration prevention**: The sign-in endpoint must return the same error for wrong username vs wrong password (OWASP). A separate "check username availability" endpoint for sign-up is acceptable but should be rate-limited

Sources: [GitHub Username Policy](https://docs.github.com/en/account-and-profile/setting-up-and-managing-your-personal-account-on-github/managing-user-account-settings/changing-your-github-username), [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
