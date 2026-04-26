# Sections

Defines the organization and priority of security best practice rules.

## Critical Impact

1. **Credential Storage** (`credential-`)
   Password hashing, secret management, breached-password checks, key rotation.

2. **Error Handling & Information Leakage** (`error-`)
   User enumeration, timing attacks, response-size/status symmetry, stack-trace leaks.

## High Impact

3. **Session Security** (`session-`)
   Token generation, cookie flags (`__Host-`, `Partitioned`), session lifecycle, fixation prevention, JWT pitfalls.

4. **Input Validation** (`input-`)
   SQL/NoSQL injection, XSS, header injection, SSRF, open redirect, request body schema.

5. **OAuth 2.0 / OIDC** (`oauth-`)
   Authorization Code + PKCE, `state`/`nonce`, redirect-URI allow-listing, account-linking pre-takeover defense.

6. **MFA, TOTP, Passkeys / WebAuthn** (`mfa-`)
   Factor enrollment, recovery codes, step-up, passkey verification, TOTP replay prevention.

7. **Short-Lived Token Lifecycle** (`token-`)
   Password reset, email verification / change, magic link, OTP — hashing, one-time use, sibling invalidation.

## Medium Impact

8. **Rate Limiting & Brute-Force Protection** (`rate-limiting-`)
   Multi-dimensional throttling (account + IP), SMS pumping, credential stuffing, CAPTCHA placement.

9. **CSRF Protection** (`csrf-`)
   Origin / Fetch-Metadata checks, double-submit token, `SameSite` caveats, CORS pitfalls.

## Lower Priority

10. **HTTP Security Headers** (`http-headers-`)
    HSTS, CSP (nonce), COOP/COEP/CORP, `Clear-Site-Data` on logout, Trusted Types.
