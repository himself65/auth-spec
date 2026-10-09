---
type: llm
weight: 1
---

Context: forgot-password returns 404 "No account with that email" for unknown emails.

PASS if the reply flags user/account enumeration via the forgot-password response.
FAIL otherwise.
