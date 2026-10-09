---
description: 'Add magic-link sign-in to an app whose generic Verification table already stores OAuth state; the user asks to reuse it.'
expected_outcome: 'Loads create-auth; keeps magic-link tokens unredeemable as OAuth state (own table, purpose column, or magic-link: prefix), hashes them, and consumes atomically.'
tags: [create, create-auth, sweep-2026-10]
max_turns: 60
timeout_seconds: 1200
allowed_tools: [Read, Glob, Grep, Skill, Write, Edit]
---

给这个项目加上 magic link 邮箱登录（发链接 + 验证两个接口）。prisma 里已经有个 Verification 表是存短期 token 的，能复用就复用。默认选项你定，别问我问题，直接把代码写进项目里，不用安装依赖也不用跑。
