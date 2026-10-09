---
type: llm
weight: 1
---

Context: the forgot-password handler builds the emailed link from `req.protocol` and `req.get("host")`.

PASS if the reply flags that the reset link uses the request Host header (reset-link / host-header poisoning) and recommends a configured base URL.
FAIL otherwise.
