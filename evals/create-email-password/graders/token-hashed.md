---
type: regex
target: trace
pattern: '"file_path"\s*:\s*"[^"]*\.(?:ts)"\s*,\s*(?:"old_string"\s*:\s*"(?:[^"\\]|\\.)*"\s*,\s*"new_string"|"content")\s*:\s*"(?:[^"\\]|\\.)*?(?:createHash|subtle\.digest|sha256)'
flags: i
weight: 2
---

Verification/reset tokens are hashed before storage (SHA-256).
