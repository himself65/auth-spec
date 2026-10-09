---
description: 'False-positive control: a correctly built password-reset flow.'
expected_outcome: 'Reports no critical/high issues; at most low-severity hardening notes.'
tags: [audit, security-best-practice, control]
max_turns: 30
timeout_seconds: 600
allowed_tools: [Read, Glob, Grep, Skill]
---

帮我审计一下 src/ 里的密码重置流程，看看有没有安全漏洞。直接审，不用问我范围，也不要改代码。按严重程度列出来。
