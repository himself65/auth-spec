---
title: Credential Storage
impact: CRITICAL
tags: password, hashing, secrets, bcrypt, argon2
---

## Credential Storage

**Impact: CRITICAL**

Weak password hashing or leaked secrets are the most direct path to mass account compromise. Every auth system must get credential storage right.

### Checklist

| Check | Requirement |
|-------|------------|
| Password hashing algorithm | Must use bcrypt (cost >= 10), argon2id, or scrypt. Never MD5, SHA-1, SHA-256 alone, or plaintext. |
| Salt handling | Must use per-password random salt. Bcrypt and argon2 handle this automatically — verify no custom salt reuse. |
| Password in logs | Grep for `console.log`, `print`, `log.`, `logger.` near password variables. Must never log passwords or hashes. |
| Password in responses | API responses must never include `passwordHash`, `password`, or `hash` fields. |
| Secrets in source code | No hardcoded JWT secrets, API keys, or database passwords. Must use environment variables. |
| Password minimum length | Minimum 8 characters enforced server-side (NIST SP 800-63B). |
| Password max length | Set a reasonable maximum (e.g., 72 for bcrypt, 128 general) to prevent long-password DoS. |

### Incorrect

```typescript
// BAD: weak hashing
const hash = crypto.createHash('sha256').update(password).digest('hex');
```

```python
# BAD: no max length — attacker can send 1MB password to DoS bcrypt
password = request.json["password"]
```

### Correct

```typescript
// GOOD: bcrypt with sufficient cost
import bcrypt from 'bcrypt';
const hash = await bcrypt.hash(password, 12);
```

```python
# GOOD: enforce bounds
password = request.json["password"]
if len(password) < 8 or len(password) > 128:
    return jsonify(error="Password must be 8-128 characters"), 400
```

### References

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST SP 800-63B — Memorized Secret Verifiers](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecretver)
