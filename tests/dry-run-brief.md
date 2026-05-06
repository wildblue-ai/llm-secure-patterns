# `/report` Dry-Run Brief

Drop this file into an empty throwaway project, start a Claude Code session there with the llm-secure-patterns plugin loaded, and hand Claude this brief. The session will create the fixtures, run `/report`, and verify both generated files against the expected result.

**Purpose:** validate that `/llm-secure-patterns:report` generates `SECURITY_POSTURE.md` *and* `DEVELOPER_RECOMMENDATIONS.md` correctly, with the right recommendation files fired (positive triggers) and the right ones omitted (negative triggers).

**Run from:**
```bash
# Replace <plugin-repo> with your local clone of llm-secure-patterns
mkdir -p /tmp/dry-run-report && cd /tmp/dry-run-report
cp <plugin-repo>/tests/dry-run-brief.md .
claude --plugin-dir <plugin-repo> --dangerously-skip-permissions
# then paste: "Follow dry-run-brief.md"
```

---

## Step 1 — Create 3 fixture files

Create these files exactly. The `# SECURITY:` annotations are what the `/report` skill scans for.

### `app.py`

```python
# Fake FastAPI endpoint — fires LLM Endpoint Hardening + Secure External Ingestion triggers

from fastapi import FastAPI, HTTPException

app = FastAPI()

MAX_INPUT_CHARS = 40_000

# SECURITY: LLM10 (Unbounded Consumption) — Level A input-size guard
#   Pattern: llm-endpoint-hardening / input-size-heuristic
#   Confidence: MODERATE
#   Applied-by: llm-secure-patterns v0.9.0
#   Date: 2026-04-23

# SECURITY: LLM01 (Prompt Injection) — Level B delimiter-based input separation
#   Pattern: secure-external-ingestion / untrusted-content-delimiters
#   Confidence: MODERATE
#   Applied-by: llm-secure-patterns v0.9.0
#   Date: 2026-04-23
USER_INPUT_TEMPLATE = "<untrusted>{message}</untrusted>"

@app.post("/chat")
def chat(message: str):
    # WARNING: len/4 is a rough heuristic, underestimates CJK/emoji 2-4x
    approx_tokens = len(message) // 4
    if approx_tokens > 10_000:
        raise HTTPException(413, "Too large")
    return {"ok": True}
```

### `agent.py`

```python
# Fake agent pipeline — fires Agent Action Surface triggers (Level C + MCP + audit log)

MCP_SERVERS = ["github-readonly", "internal-kb"]

# SECURITY: LLM06 (Excessive Agency) — Level C pipeline stage isolation
#   Pattern: agent-action-surface / stage-isolation-with-audit-log
#   Confidence: MODERATE
#   Level: Level C
#   Declined: none — highest level selected
#   MCP: allowlist + hash-pinning applied
#   Audit: redact_for_audit_log enabled
#   Applied-by: llm-secure-patterns v0.9.0
#   Date: 2026-04-20
def build_pipeline():
    return {
        "stage_1": {"tools": ["get_issue", "list_repos"], "trusts_input_from": "user"},
        "stage_2": {"tools": ["create_pr", "comment_issue"], "trusts_input_from": "stage_1_output"},
    }
```

### `prompt.py`

```python
# Fake system-prompt builder — fires System Prompt Design triggers (Level C + credential scan)

SYSTEM_PROMPT = "You are a helpful assistant. Follow policy v4.2."

# SECURITY: LLM07 (System Prompt Leakage) — Level C dual-prompt split
#   Pattern: system-prompt-design / dual-prompt-with-output-filter
#   Confidence: LOW
#   Level: Level C
#   Applied-by: llm-secure-patterns v0.9.0
#   Date: 2026-04-20
# SECURITY: LLM02 (Sensitive Information Disclosure) — credential regex scan on output
#   Pattern: system-prompt-design / credential-regex-scan
#   Confidence: LOW
#   Applied-by: llm-secure-patterns v0.9.0
#   Date: 2026-04-20
def build_prompt():
    return SYSTEM_PROMPT
```

---

## Step 2 — Run `/report`

Invoke `/llm-secure-patterns:report`. Let the skill run end-to-end, including the disposition prompt at the end.

When asked about detailed view, answer **yes**.

When asked about disposition (A/B/C), answer **B (gitignore)** — this is a throwaway.

---

## Step 3 — Verify output

Check each item. Report PASS / FAIL for each.

### Both files exist

- [ ] `SECURITY_POSTURE.md` written to project root
- [ ] `DEVELOPER_RECOMMENDATIONS.md` written to project root

### `DEVELOPER_RECOMMENDATIONS.md` content

The file should contain **exactly these 9 recommendations** (in numeric order):

- [ ] `01-trust-tier-credentials` — "Trust-tier credential isolation (scaffold)"
- [ ] `02-token-counting` — "Switch from the len/4 heuristic to `client.messages.count_tokens()`"
- [ ] `07-dual-prompt-split` — "Dual-prompt split (scaffold)"
- [ ] `08-output-filter-interim` — "Output filter for system-prompt leakage — interim"
- [ ] `09-secret-scanners` — "Replace illustrative credential regex with maintained scanners"
- [ ] `12-allowlist-extension` — "Review and extend `SAFE_READ_PREFIXES` for your environment"
- [ ] `13-write-permission-enforce` — "Stage 1 write-permission enforcement"
- [ ] `14-mcp-trust-scaffolds` — "MCP server trust (scaffolds)"
- [ ] `15-audit-log-deployment` — "Audit log deployment checklist"

### Negative-trigger check (must NOT appear)

This one should be absent from `DEVELOPER_RECOMMENDATIONS.md`:

- [ ] `04-sql-shell-reminder` is **absent** (Output Validation did not fire — no LLM05 annotation)

### Verbatim-reproduction check

- [ ] At least one scaffold (e.g., rec #07 or #09) has its fenced code blocks reproduced character-for-character, not paraphrased

### Disposition prompt

- [ ] Prompt offered three options: **A (commit both)**, **B (gitignore both)**, **C (mixed)**

### CTO posture report regression check

- [ ] `SECURITY_POSTURE.md` still has the COVERAGE SUMMARY section
- [ ] LLM01, LLM02, LLM06, LLM07, LLM10 show as MITIGATED (direct-annotation semantics — a category is MITIGATED only if an annotation directly references its OWASP ID)
- [ ] LLM03, LLM04, LLM08 show as NOT ADDRESSABLE BY CODE-TIME GUIDANCE
- [ ] LLM05, LLM09 show as NOT ADDRESSED

---

## Step 4 — Report back

Summarize:
1. PASS / FAIL per checkbox above.
2. Any recommendation that was included but shouldn't have been, or omitted but should have been.
3. Any scaffold that was paraphrased instead of reproduced verbatim.
4. Any other unexpected behavior.

If everything passes, the Developer Recommendations Report is ready for Run 4 adversarial review.
