---
type: regex
target: trace
pattern: '"file_path"\s*:\s*"[^"]*\.(?:ts)"\s*,\s*(?:"old_string"\s*:\s*"(?:[^"\\]|\\.)*"\s*,\s*"new_string"|"content")\s*:\s*"(?:[^"\\]|\\.)*?(?:(?:deleteMany|updateMany)\((?:[^"\\]|\\.)*?\.count|RETURNING)'
flags: i
weight: 2
---

Single-use tokens are consumed with one conditional write gated on the affected-row count.
