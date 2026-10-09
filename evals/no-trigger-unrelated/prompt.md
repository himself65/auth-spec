---
description: 'Control: an unrelated coding request must not load either auth skill.'
expected_outcome: 'Answers with a debounce implementation; no Skill call to create-auth or security-best-practice.'
tags: [trigger, control]
max_turns: 4
timeout_seconds: 180
allowed_tools: [Read, Glob, Grep, Skill]
---

写一个 TypeScript 的 debounce 函数，支持 leading 和 trailing 选项，带上类型。直接在回复里给代码就行。
