---
type: llm
weight: 2
---

Context: `POST /api/auth/sign-up` (src/password.ts) creates an unverified User with a `passwordHash` for any email, and `POST /api/auth/sign-in` accepts that password without requiring `emailVerified`. Magic-link verify (and the Google callback) then sign into that existing row by email without stripping its `passwordHash` (and without marking it verified). An attacker who signs up first with the victim's email keeps password access after the victim starts using the account via magic link or Google (pre-account hijacking).

PASS if the reply flags that passwordless/OAuth sign-in adopts an existing unverified account without stripping credentials set by whoever created it (or otherwise describes pre-account takeover / implicit linking onto unverified accounts).
FAIL otherwise.
