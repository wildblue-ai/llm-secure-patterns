---
decision: 2
title: Switch from len/4 heuristic to real token counting
triggers_when: LLM Endpoint Hardening skill fired with the len/4 heuristic (any LLM10 annotation from that skill)
type: advisory
---

## Switch from the len/4 heuristic to `client.messages.count_tokens()`

**Status:** Action required before serving non-English traffic or billing/quota reliance.

The template uses `len(text) // 4` as a token estimate. This underestimates CJK, emoji, and many non-Latin scripts by 2–4x — a 10,000-character Japanese payload can be closer to 8,000 tokens than 2,500. Anything that bills, rate-limits, or budgets against this count will drift under real traffic.

**Do this:**

```python
from anthropic import Anthropic

client = Anthropic()

count = client.messages.count_tokens(
    model="claude-sonnet-4-6",
    messages=[{"role": "user", "content": request.message}],
).input_tokens

if count > MAX_INPUT_TOKENS:
    raise HTTPException(413, "Input exceeds token budget")
```

**Do NOT** use `tiktoken` — that is OpenAI's tokenizer. It will give you a wrong number for Claude.

**When the heuristic is acceptable:** early prototypes, English-only traffic, coarse guardrails where a 4x error is tolerable. Document the assumption in code.
