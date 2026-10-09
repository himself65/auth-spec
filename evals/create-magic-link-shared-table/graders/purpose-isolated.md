---
type: regex
target: trace
pattern: '"file_path"\s*:\s*"[^"]*\.(?:ts|prisma)"\s*,\s*(?:"old_string"\s*:\s*"(?:[^"\\]|\\.)*"\s*,\s*"new_string"|"content")\s*:\s*"(?:[^"\\]|\\.)*?(?:magic-?link:|\bpurpose\b|model\s+MagicLink)'
flags: i
weight: 3
---

Magic-link tokens are kept apart from OAuth state: a dedicated table, a purpose column, or a consumer-supplied magic-link: prefix (cross-purpose-token-confusion pitfall).
