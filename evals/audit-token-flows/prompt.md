---
description: 'Natural-language audit request over an Express+Prisma app with planted short-lived-token bugs.'
expected_outcome: 'Loads security-best-practice and reports the cross-purpose Verification table (OAuth state redeemable as a magic link), the 2FA enable overwrite, pre-account hijack, Host-header reset links, plaintext tokens and reset enumeration.'
tags: [audit, security-best-practice, sweep-2026-10]
max_turns: 40
timeout_seconds: 900
allowed_tools: [Read, Glob, Grep, Skill]
---

我们的 API 代码在 src/ 下（Express + Prisma）。上线前帮我做一次认证相关的安全审计：范围就是全部，不用问我选哪些。只读代码、不要改。最后给我一份按严重程度排序的问题清单，每条写清楚文件、攻击方式和修复建议。
