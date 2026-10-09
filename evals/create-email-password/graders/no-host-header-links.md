---
type: regex
target: trace
pattern: '"file_path"\s*:\s*"[^"]*\.(?:ts)"\s*,\s*(?:"old_string"\s*:\s*"(?:[^"\\]|\\.)*"\s*,\s*"new_string"|"content")\s*:\s*"(?:[^"\\]|\\.)*?req\.(?:get\((?:\\"|\x27)host|headers\.host|hostname)'
flags: i
weight: 1
match: not_contains
---

Emailed links are not built from the request Host header.
