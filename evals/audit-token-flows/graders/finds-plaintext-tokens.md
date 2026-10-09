---
type: llm
weight: 1
---

Context: magic-link, reset tokens and session tokens are stored in the database in plaintext (the raw value is the lookup column).

PASS if the reply flags that single-use/verification tokens (or session tokens) are stored unhashed and should be stored as a hash.
FAIL otherwise.
