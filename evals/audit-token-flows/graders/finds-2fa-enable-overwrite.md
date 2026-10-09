---
type: llm
weight: 2
---

Context: `POST /api/auth/two-factor/enable` does a Prisma `upsert` on the user's TwoFactor row, so calling it when 2FA is already enabled replaces the active TOTP secret and backup codes using only a session.

PASS if the reply flags that /two-factor/enable overwrites an existing (enabled) authenticator / backup codes, e.g. a stolen session can swap in the attacker's authenticator or the owner gets locked out.
FAIL otherwise.
