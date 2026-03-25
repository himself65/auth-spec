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
| code        | string   | not null (6-digit numeric)     |
| expiresAt   | datetime | not null (default: 10 minutes) |
| createdAt   | datetime | default now                    |

## Endpoints

**POST /api/auth/phone/send**
- Body: `{ phoneNumber }`
- Validate phone number format (E.164: +country code + number)
- Generate a 6-digit numeric code (crypto-random)
- Store code with 10-minute expiry
- Send code via SMS (use the project's SMS service)
- Return 200 (always)
- Rate limit: max 3 requests per phone per 10 minutes

**POST /api/auth/phone/verify**
- Body: `{ phoneNumber, code }`
- Look up the most recent unexpired code for this phone number
- If valid: create or find User (by phone), create Session, delete code, return token + user
- If invalid or expired: return 401 with generic error
- Delete code after successful verification (single use)

## Implementation Rules

- Phone numbers must be stored in E.164 format (+1234567890)
- Codes MUST be 6 digits, zero-padded
- Generate with crypto-random, not Math.random
- Each code is single-use — delete after verification
- Delete all previous codes for the same phone when generating a new one
- Constant-time comparison for code verification
- If the user does not exist, create a new User + Account (providerId: "phone") on successful verification
- Set phoneVerified to true after successful verification

## Best Practices (Industry Consensus)

- **NIST SP 800-63B classifies SMS as a "restricted" authenticator.** It is not prohibited, but agencies/apps using it must offer an alternative, inform users of the risks (SIM swap, interception), and maintain a migration plan toward phishing-resistant methods. Still widely supported because of its ubiquity.
- **E.164 format validation is critical.** Reject any phone number that does not match `^\+[1-9]\d{1,14}$` before processing. Normalize on intake to avoid duplicate accounts from formatting differences.
- **Rate limit: max 3 SMS per phone number per 10 minutes** to prevent SMS pumping fraud, where attackers trigger mass sends to premium-rate numbers for revenue share. This also serves as a cost control since every SMS has a per-message cost.
- **International considerations:** Some countries block short codes or have carrier-level filtering. Support alphanumeric sender IDs where required, and consider geo-rate-limits (stricter limits for high-fraud regions).
- **Cost awareness:** Each SMS costs $0.01-$0.05+ depending on country. Rate limiting is both a security and financial control. Consider CAPTCHA or device attestation before sending.
- **Code parameters:** 6 digits, 10-minute expiry, single use. Delete all prior codes for the same number when issuing a new one. Use constant-time comparison to prevent timing attacks.
