---
description: 'Scaffold email/password auth with verification and reset into a bare Express app.'
expected_outcome: 'Loads create-auth and writes Prisma schema + routes: password hashing, hashed single-use tokens with a purpose, atomic consumption, links from a configured base URL.'
tags: [create, create-auth]
max_turns: 80
timeout_seconds: 1500
allowed_tools: [Read, Glob, Grep, Skill, Write, Edit]
---

Add email + password sign-up and sign-in to this Express API, including email verification and password reset. Use Prisma with Postgres. Pick sensible defaults yourself and don't ask me any questions — just write the code into this repo (no need to install packages or run anything).
