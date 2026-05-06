---
decision: 9
title: Replace illustrative credential regex with maintained scanners
triggers_when: System Prompt Design skill fired and the credential-regex pattern is in use (annotation references LLM02 credential scanning)
type: scaffold
---

## Replace illustrative credential regex with maintained scanners

The template's credential regex is illustrative — it flags obvious examples and misses most real-world secret shapes. Production detection should delegate to maintained scanners with active detector sets.

**Two different jobs, two different tools:**

| Need | Tool | License |
|---|---|---|
| Runtime scanning of LLM output before returning to user | `detect-secrets` (Python library) | Apache 2.0 |
| Pre-commit and repo-history scanning | `trufflehog` (CLI) | AGPL-3.0 |

> **License note:** `trufflehog` is AGPL-3.0 — fine for use as a standalone CLI / pre-commit hook. Avoid linking it into a proprietary codebase.

**Scaffold — runtime scan with `detect-secrets`:**

```bash
pip install detect-secrets
```

```python
from detect_secrets.core.scan import scan_line

def contains_credentials(llm_output: str) -> bool:
    for line in llm_output.splitlines():
        if any(scan_line(line)):
            return True
    return False

if contains_credentials(response_text):
    raise OutputValidationError("Credential pattern detected in LLM output")
```

**Scaffold — pre-commit hook with `trufflehog`:**

```bash
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/trufflesecurity/trufflehog
    rev: main
    hooks:
      - id: trufflehog
        entry: trufflehog filesystem --directory=. --fail
```

Both tools ship and update their own detector catalogs, so you are not maintaining regexes by hand as new credential formats appear.
