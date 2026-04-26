---
title: Credential Storage
impact: CRITICAL
tags: password, hashing, secrets, argon2, bcrypt, pepper, hibp
---

## Credential Storage

**Impact: CRITICAL**

Weak password hashing or leaked secrets are the most direct path to mass account compromise. Every auth system must get credential storage right.

### Checklist

| Check | Requirement |
|-------|------------|
| Password hashing algorithm | Prefer **argon2id** (OWASP 2024 top choice). Acceptable: scrypt, bcrypt (cost ≥ 12). Never MD5, SHA-1, SHA-256 alone, PBKDF2-SHA1, or plaintext. |
| Argon2id parameters | Minimum `m=19456` (19 MiB), `t=2`, `p=1`. OWASP 2024 recommends `m=47104` (46 MiB), `t=1`, `p=1` for higher security. |
| Bcrypt parameters | Cost factor ≥ 12 in 2026 (≥ 10 is the old baseline; increase over time). Pre-hash with SHA-256 + base64 if you accept passwords > 72 bytes to avoid the bcrypt 72-byte truncation. |
| Salt handling | Per-password random salt (≥ 16 bytes). Bcrypt/argon2/scrypt handle this — verify no custom salt reuse. |
| Pepper (optional, defense-in-depth) | Application-layer secret HMAC applied before hashing. Stored in env/KMS, not the database. Useful when the password column may leak but secrets won't. |
| Password in logs | Grep for `console.log`, `print`, `log.`, `logger.` near password variables. Must never log passwords, hashes, or JWTs. |
| Password in responses | API responses must never include `passwordHash`, `password`, `hash`, or `salt` fields. Use a DTO / select allow-list. |
| Secrets in source code | No hardcoded JWT secrets, API keys, or database passwords. Use env vars, KMS, Vault, or a secret manager. Run `git-secrets` / `trufflehog` pre-commit. |
| Password minimum length | ≥ 8 characters server-side (NIST SP 800-63B rev.4). Prefer ≥ 12 for admin/privileged accounts. |
| Password max length | Enforce a hard upper bound (e.g. 128, or 64 for bcrypt-only when not pre-hashing) to prevent long-password DoS. |
| Breached password check | At sign-up and password change, reject passwords found in known breach corpora. Use the HIBP Pwned Passwords k-anonymity API (SHA-1 prefix) or an offline bloom filter — **never** send the full password. |
| Password complexity rules | NIST SP 800-63B rev.4 **deprecates** forced complexity/rotation. Do not require uppercase/symbols. Do not force periodic rotation — rotate only on suspected compromise. |
| Key rotation | Rotate JWT/HMAC secrets and DB encryption keys periodically. Support multiple active verifiers during rollover. Document the rotation process. |

### Incorrect

```typescript
// BAD: weak hashing
const hash = crypto.createHash('sha256').update(password).digest('hex');
```

```typescript
// BAD: sending full password to remote breach API
await fetch(`https://api.example.com/check?password=${password}`);
```

```python
# BAD: no max length — attacker can send 1MB password to DoS bcrypt/argon2
password = request.json["password"]
```

### Correct

```typescript
// GOOD: argon2id with reasonable parameters
import argon2 from 'argon2';
const hash = await argon2.hash(password, {
  type: argon2.argon2id,
  memoryCost: 19456, // 19 MiB
  timeCost: 2,
  parallelism: 1,
});
```

```typescript
// GOOD: bcrypt with pre-hash to avoid 72-byte truncation
import bcrypt from 'bcrypt';
import crypto from 'crypto';
const prehashed = crypto.createHash('sha256').update(password).digest('base64');
const hash = await bcrypt.hash(prehashed, 12);
```

```typescript
// GOOD: HIBP k-anonymity — only first 5 SHA-1 chars leave the server
const sha1 = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
const prefix = sha1.slice(0, 5);
const suffix = sha1.slice(5);
const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
const breached = (await res.text()).split('\n').some(line => line.startsWith(suffix));
if (breached) throw new Error('This password appears in known breaches. Please choose another.');
```

```python
# GOOD: enforce bounds
password = request.json["password"]
if not (8 <= len(password) <= 128):
    return jsonify(error="Password must be 8-128 characters"), 400
```

### References

- [OWASP Password Storage Cheat Sheet (argon2id first)](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST SP 800-63B rev.4 — Memorized Secret Verifiers](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [Have I Been Pwned — Pwned Passwords API (k-anonymity)](https://haveibeenpwned.com/API/v3#PwnedPasswords)
- [RFC 9106 — Argon2 Memory-Hard Function](https://datatracker.ietf.org/doc/html/rfc9106)
