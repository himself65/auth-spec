---
type: llm
weight: 3
---

Context: `seal()` uses one key derived from AUTH_SECRET. `/api/auth/sign-in/github` seals a state object that spreads caller-supplied `additionalData` and sets it as a cookie the caller receives; `/api/auth/proxy-callback` trusts any blob that `open()` decrypts as a verified profile. An attacker sends `additionalData: { email: victim }`, takes the cookie value, and passes it as `?profile=` to sign in as the victim.

PASS if the reply identifies that the same key seals attacker-influenced state and verifies proxy profiles, making the state endpoint a forging/encryption oracle, and recommends separate per-purpose keys and/or typing the sealed payload.
FAIL if it only notes generic issues (e.g. the open redirect or that GCM is fine) without this cross-purpose forgery.
