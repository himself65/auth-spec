---
description: 'Audit of user-registrable OIDC SSO plus an OAuth preview proxy that shares the state-cookie key.'
expected_outcome: 'Reports that SSO accounts are keyed on the attacker-choosable issuer (GHSA-mx9r shape) and that the sealed state cookie is an encryption oracle for proxy-callback profiles (GHSA-r4xp shape).'
tags: [audit, security-best-practice, sweep-2026-10]
max_turns: 40
timeout_seconds: 900
allowed_tools: [Read, Glob, Grep, Skill]
---

Please review the sign-in code in src/ (GitHub login with a preview-deployment proxy, plus bring-your-own OIDC SSO) for security issues before we launch. Full scope, don't ask me to pick areas, and don't modify files. Give me a prioritized list of findings with the attack and the fix for each.
