# Sections

Defines the organization and priority of security best practice rules.

## Critical Impact

1. **Credential Storage** (`credential-`)
   Rules for password hashing, secret management, and key handling.

2. **Error Handling & Information Leakage** (`error-`)
   Rules for preventing user enumeration, timing attacks, and stack trace leaks.

## High Impact

3. **Session Security** (`session-`)
   Rules for token generation, cookie flags, session lifecycle, and fixation prevention.

4. **Input Validation** (`input-`)
   Rules for SQL injection, XSS, header injection, and request body validation.

## Medium Impact

5. **Rate Limiting & Brute-Force Protection** (`rate-limiting-`)
   Rules for login throttling, account lockout, and CAPTCHA triggers.

6. **CSRF Protection** (`csrf-`)
   Rules for cross-site request forgery prevention with cookie-based auth.

## Lower Priority

7. **HTTP Security Headers** (`http-headers-`)
   Rules for HSTS, CSP, X-Frame-Options, Referrer-Policy, and Permissions-Policy.
