---
title: Error Handling & Information Leakage
impact: CRITICAL
tags: enumeration, timing-attack, stack-trace, generic-errors
---

## Error Handling & Information Leakage

**Impact: CRITICAL**

Verbose error messages and inconsistent response behavior leak whether accounts exist, what tech stack is used, and internal implementation details — all of which help attackers.

### Checklist

| Check | Requirement |
|-------|------------|
| Generic auth errors | Sign-in failure must return generic "Invalid credentials" — never "User not found" or "Wrong password". |
| Sign-up enumeration | Sign-up with existing email must return same status/shape as success (see create-auth skill for details). |
| Stack traces | Production error responses must never include stack traces, SQL errors, or internal paths. |
| Timing attacks | Password comparison must use constant-time comparison (bcrypt/argon2 do this). Auth lookups should hash the password even when user is not found to prevent timing leaks. |
| Password reset enumeration | "If an account exists, we sent a reset email" — never confirm whether the email is registered. |
| Verbose headers | Remove `X-Powered-By`, `Server` version headers that reveal tech stack. |
| Debug mode | Ensure debug/development modes are disabled in production configuration. |

### Incorrect

```typescript
// BAD: leaks whether email exists
if (!user) return res.status(401).json({ error: "User not found" });
if (!validPassword) return res.status(401).json({ error: "Wrong password" });
```

```python
# BAD: stack trace in response
except Exception as e:
    return jsonify(error=str(e)), 500
```

### Correct

```typescript
// GOOD: generic error for both cases
if (!user || !await bcrypt.compare(password, user.passwordHash)) {
  // Hash a dummy password when user is null to prevent timing leaks
  if (!user) await bcrypt.hash(password, 12);
  return res.status(401).json({ error: "Invalid credentials" });
}
```

```python
# GOOD: generic error, log details server-side
except Exception as e:
    logger.error(f"Auth error: {e}")
    return jsonify(error="Internal server error"), 500
```

### References

- [OWASP Authentication Cheat Sheet — Authentication Responses](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#authentication-responses)
- [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)
