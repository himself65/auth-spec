# Password Breach Check

Check passwords against the Have I Been Pwned (HIBP) breached password database.

## Schema Additions

None — this is a validation step during sign-up and password change.

## Integration Point

Add password breach checking as a validation step in:
- **POST /api/auth/sign-up** — before creating the user
- **Password change** — before updating the password (if implemented)

## How It Works (k-Anonymity API)

1. Hash the password with SHA-1
2. Take the first 5 characters of the hex hash (the "prefix")
3. Call `GET https://api.pwnedpasswords.com/range/{prefix}`
4. The API returns a list of hash suffixes and their breach counts
5. Check if the remaining hash suffix appears in the response
6. If found: the password has been breached

## Behavior

- If the password is breached: return 400 with `{ error: "password_compromised", message: "This password has appeared in a data breach. Please choose a different password." }`
- If the HIBP API is unreachable: allow the password (fail-open) but log a warning
- Do NOT send the full password hash to any external service — only the 5-char prefix

## Implementation Rules

- Use SHA-1 for the hash (this is what HIBP requires — it's NOT used for password storage)
- Only send the first 5 characters of the hash to the API (k-anonymity)
- Comparison of hash suffixes should be case-insensitive
- Set a timeout on the HIBP API call (3 seconds)
- Fail-open: if the API is unreachable, allow the password but log a warning
- This check runs BEFORE password hashing (bcrypt/argon2) — it operates on the plaintext
- Make this feature toggleable via configuration
- Cache API responses briefly (5 minutes) to reduce external calls for the same prefix

## Best Practices (Industry Consensus)

- **NIST 800-63B requires it**: verifiers SHALL compare prospective passwords against a list of known compromised values — breached password checking is not optional for NIST compliance
- **k-anonymity preserves privacy**: only the first 5 characters of the SHA-1 hex hash are sent to the API; the full password or full hash never leaves the server
- **API is free and reliable**: the Pwned Passwords range search API requires no authentication or API key; it is backed by Cloudflare's CDN for high availability and low latency
- **Padded responses**: HIBP supports `Add-Padding: true` header, ensuring all responses are 800–1000 entries regardless of actual matches — this prevents response-size analysis by network observers
- **Fail-open if API unreachable**: do not block user registration if the HIBP API is down; allow the password but log a warning for monitoring
- **Cache prefix responses briefly** (5 minutes TTL) to reduce redundant API calls for the same prefix
- **Check runs on plaintext BEFORE hashing**: the breach check operates on the raw password, before bcrypt/argon2 hashing — SHA-1 is used only for the HIBP lookup, never for storage
- **Also block common passwords**: NIST recommends rejecting passwords from commonly-used lists (e.g., "password", "123456") in addition to breach lists
- **Do not disclose match count**: tell the user the password appeared in a breach, but do not reveal how many times — this avoids leaking information

Sources: [NIST SP 800-63B](https://pages.nist.gov/800-63-3/sp800-63b.html), [HIBP Pwned Passwords](https://haveibeenpwned.com/Passwords), [Troy Hunt on k-Anonymity](https://www.troyhunt.com/understanding-have-i-been-pwneds-use-of-sha-1-and-k-anonymity/), [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
