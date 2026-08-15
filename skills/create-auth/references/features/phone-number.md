# Phone Number Authentication

SMS-based OTP authentication using phone numbers.

## Schema Additions

Add to **User** table:
| Field       | Type   | Constraints |
|-------------|--------|-------------|
| phoneNumber | string | nullable, unique |
| phoneVerified | boolean | default false |

**PhoneVerificationCode**
| Field       | Type     | Constraints                    |
|-------------|----------|--------------------------------|
| id          | string   | primary key                    |
| phoneNumber | string   | not null                       |
| codeHash    | string   | not null (salted SHA-256 of the 6-digit code) |
| attempts    | int      | default 0 (failed verifications) |
| expiresAt   | datetime | not null (default: 10 minutes) |
| createdAt   | datetime | default now                    |

Same storage rules as `references/features/email-otp.md`: never persist the raw code, and use a fast hash (SHA-256 with a per-row salt) rather than bcrypt — these are short-lived and low-entropy, so slow hashing buys latency, not brute-force resistance. An SMS code is worth *more* than an email one here, because it is the credential a stolen database turns into account takeover on a channel the owner cannot revoke.

## Endpoints

**POST /api/auth/phone/send**
- Body: `{ phoneNumber }`
- Validate phone number format (E.164: +country code + number)
- Generate a 6-digit numeric code (crypto-random)
- Store the salted SHA-256 hash of the code (never the raw code) with 10-minute expiry
- Send code via SMS (use the project's SMS service)
- Return 200 (always)
- Rate limit: max 3 requests per phone per 10 minutes

**POST /api/auth/phone/verify**
- Body: `{ phoneNumber, code }`
- Look up the most recent unexpired code row for this phone number
- Increment `attempts` atomically; after 5 failures delete the row and require a new send. A 6-digit code is a 20-bit secret — without a cap, an attacker walks the whole keyspace against a live code
- Compare hashes constant-time; on success **consume the row atomically** (conditional delete gated on affected rows — see `references/pitfalls/single-use-token-race.md`) so concurrent verifies mint at most one session
- If consumed and no User has this phone: create User + Account (providerId: "phone") with `phoneVerified = true`, create Session, return token + user
- If consumed and the matched User has `phoneVerified = false`, that row only *claims* the number: when it has never verified any identifier (`emailVerified = false`) claim and strip it in one transaction (see `references/pitfalls/pre-account-hijack-strip.md`) before minting the Session; when it already has a verified email, return the generic 401 instead — an established account may only attach a phone from an authenticated session
- If consumed and the matched User already has `phoneVerified = true`: this is the proven owner — do not strip; upsert the Account on `(providerId, accountId)`, create Session, return token + user
- If invalid or expired: return 401 with generic error

## Implementation Rules

- Phone numbers must be stored in E.164 format (+1234567890)
- Codes MUST be 6 digits, zero-padded
- Generate with crypto-random, not Math.random
- Store only the salted SHA-256 hash of the code; look up by phone number and compare hashes
- Each code is single-use — consume with one conditional write (affected-rows check), never find-then-delete
- Cap failed verifications at 5 per code, then delete the row and require a new send
- Delete all previous codes for the same phone when generating a new one
- Constant-time comparison for code verification
- On successful verification, resolve the User through the shared sign-up gate in `SKILL.md`'s Implementation Rules rather than inserting one here; if it permits a new account, create User + Account (providerId: "phone")
- The core **User** schema requires an email and a phone-only sign-up has none — prefer making `email` nullable. If it must stay non-null, synthesize a non-routable placeholder on the RFC 6761 reserved `.invalid` TLD (`<e164>@phone.placeholder.invalid`), leave `emailVerified` false forever, and never send mail to it or resolve it in an email-keyed "create or find user" lookup. A placeholder on a domain you actually receive mail for lets whoever reads that mailbox drive a magic link or password reset into the phone user's account. A placeholder is never itself a provable identifier: `phoneVerified` is this account's **proven primary identifier**, and every enrolment gate and unverified-account cleanup MUST read it, not the email column — otherwise phone-only users can never enrol a passkey and get reaped as unverified.
- Set `phoneVerified` in one conditional write naming both the proven number and the unproven flag (`UPDATE user SET phone_verified = true WHERE id = $1 AND phone_number = $2 AND phone_verified = false`): the number binding stops a phone-number change racing the SMS round trip from inheriting the proof (`references/pitfalls/async-proof-value-binding.md`), and winning the flip is what authorizes stripping everything that predates it, in the same transaction (`references/pitfalls/pre-account-hijack-strip.md`). Zero rows affected has three causes and only one of them signs in: re-read the row and proceed only if it still holds the proven number and is now verified (a concurrent honest proof). If the row is gone, or its number changed, discard the proof — return the generic 401 and mint nothing (the code stays consumed; a spent code is never revived)
- Any later write that changes `phoneNumber` must set `phoneVerified` to false in the same statement and delete outstanding codes for the old number — the flag proves the number that was verified, not the row

## Best Practices (Industry Consensus)

- **NIST SP 800-63B classifies SMS as a "restricted" authenticator.** It is not prohibited, but agencies/apps using it must offer an alternative, inform users of the risks (SIM swap, interception), and maintain a migration plan toward phishing-resistant methods. Still widely supported because of its ubiquity.
- **E.164 format validation is critical.** Reject any phone number that does not match `^\+[1-9]\d{1,14}$` before processing. Normalize on intake to avoid duplicate accounts from formatting differences.
- **Rate limit: max 3 SMS per phone number per 10 minutes** to prevent SMS pumping fraud, where attackers trigger mass sends to premium-rate numbers for revenue share. This also serves as a cost control since every SMS has a per-message cost.
- **International considerations:** Some countries block short codes or have carrier-level filtering. Support alphanumeric sender IDs where required, and consider geo-rate-limits (stricter limits for high-fraud regions).
- **Cost awareness:** Each SMS costs $0.01-$0.05+ depending on country. Rate limiting is both a security and financial control. Consider CAPTCHA or device attestation before sending.
- **Code parameters:** 6 digits, 10-minute expiry, single use. Delete all prior codes for the same number when issuing a new one. Use constant-time comparison to prevent timing attacks.
