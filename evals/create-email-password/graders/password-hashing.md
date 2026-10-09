---
type: regex
target: trace
pattern: '"file_path"\s*:\s*"[^"]*\.(?:ts)"\s*,\s*(?:"old_string"\s*:\s*"(?:[^"\\]|\\.)*"\s*,\s*"new_string"|"content")\s*:\s*"(?:[^"\\]|\\.)*?\b(?:argon2|bcrypt|scrypt)'
flags: i
weight: 1
---

Written TypeScript uses a slow password hash (argon2/bcrypt/scrypt).
