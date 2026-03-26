---
title: Input Validation
impact: HIGH
tags: sql-injection, xss, header-injection, path-traversal, validation
---

## Input Validation

**Impact: HIGH**

Unvalidated input is the root cause of SQL injection, XSS, and header injection — all of which can lead to full system compromise.

### Checklist

| Check | Requirement |
|-------|------------|
| SQL injection | All database queries must use parameterized queries or ORM methods. No string concatenation with user input. |
| Email validation | Validate email format server-side before database operations. |
| Request body validation | Validate types and shapes of all incoming request bodies. Reject unexpected fields. |
| Header injection | Never reflect user input directly into response headers (CRLF injection). |
| Path traversal | If auth involves file operations, validate and sanitize file paths. |
| JSON parsing | Catch JSON parse errors and return 400, not 500 with stack trace. |

### Incorrect

```typescript
// BAD: SQL injection
const user = await db.query(`SELECT * FROM users WHERE email = '${email}'`);
```

```go
// BAD: no email validation
email := r.FormValue("email")
```

### Correct

```typescript
// GOOD: parameterized query
const user = await db.query('SELECT * FROM users WHERE email = $1', [email]);
```

```go
// GOOD: validate before use
email := r.FormValue("email")
if !isValidEmail(email) {
    http.Error(w, `{"error":"Invalid email format"}`, http.StatusBadRequest)
    return
}
```

### References

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
