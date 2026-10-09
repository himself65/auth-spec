---
type: regex
target: trace
pattern: '"file_path"\s*:\s*"[^"]*\.(?:prisma)"\s*,\s*(?:"old_string"\s*:\s*"(?:[^"\\]|\\.)*"\s*,\s*"new_string"|"content")\s*:\s*"(?:[^"\\]|\\.)*?\bpurpose\b'
flags: i
weight: 2
---

The token table carries a purpose discriminator so a reset token cannot confirm an email (and vice versa).
