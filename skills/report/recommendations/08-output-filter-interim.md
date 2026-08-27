---
decision: 8
title: System-prompt leakage output filter — interim guidance, template arriving in v1.0.1
triggers_when: System Prompt Design skill fired at Level C (annotation records Level C for LLM07)
type: advisory
---

## Output filter for system-prompt leakage — interim

A full Level C output filter template with adversarial-evasion caveats is planned for **v1.0.1**. For v1.0.0, the skill ships a keyword blocklist helper (`scan_for_prompt_leakage`) that matches known system-prompt fragments.

**Use the blocklist as a starting point, not a finish line:**

- Seed it with distinctive phrases from your actual system prompt — long, unique strings rather than short common words.
- Add entries after every known leak. Treat this file like a WAF signature set.
- Review on every system-prompt edit.

**Known limits of the interim pattern:**

- **Exact-match only.** Paraphrase, translation, rot13, base64, and "spell the first letter of each line" extractions all bypass it.
- **False negatives are the default mode**, not the exception. Do not rely on it as a sole control.
- **False positives happen** when users legitimately reference a phrase that also appears in your prompt. Tune severity accordingly.

**When the v1.0.1 filter template ships, expect this caveat to remain:** the filter itself is an LLM call and is susceptible to the same adversarial techniques it's designed to catch. Defense in depth matters — pair the filter with rate limiting per user, prompt-leakage monitoring in logs, and periodic red-team runs against your current system prompt.
