---
type: llm
weight: 2
---

Context: magic-link verify (and the Google callback) sign into an existing User found by email even when that row's `emailVerified` is false, leaving any `passwordHash` an earlier registrant set in place. An attacker who pre-registered the victim's email with a password keeps access after the victim signs in by link (pre-account hijacking).

PASS if the reply flags that passwordless/OAuth sign-in adopts an existing unverified account without stripping credentials set by whoever created it (or otherwise describes pre-account takeover / implicit linking onto unverified accounts).
FAIL otherwise.
