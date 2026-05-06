# Adversarial Review Audit Log

Append-only record of each cross-model adversarial review run. One entry per run. Never edit past entries.

For per-finding detail, see [findings-plan.md](findings-plan.md).
For how the harness works, see [tests/adversarial-review/README.md](../../tests/adversarial-review/README.md).

---

## Run 1 — 2026-04-07

**Harness:** commit `f22a67f` (`feat: add cross-model adversarial review harness`)
**Skills reviewed:** all 5 (secure-external-ingestion, llm-endpoint-hardening, output-validation, system-prompt-design, agent-action-surface)
**Reviewers:** claude-sonnet-4-6, gpt-4o, gemini-2.5-pro
**Triage model:** claude-opus-4-6
**Raw output:** `tests/adversarial-review/results/2026-04-07/` (gitignored — local copy only)

### Results

| Skill | Fix-now | v1.0.1 | Won't-fix | Rejected |
|---|---|---|---|---|
| secure-external-ingestion | 10 | 8 | 8 | 4 |
| llm-endpoint-hardening | 8 | 10 | 10 | 3 |
| output-validation | 10 | 9 | 7 | 2 |
| system-prompt-design | 8 | 11 | 6 | 4 |
| agent-action-surface | 11 | 8 | 7 | 2 |
| **Total** | **47** | **46** | **38** | **15** |

### Cross-skill patterns identified

1. **Delimiter injection** — `</UNTRUSTED_*>` wrapping is exploitable in 3 of 5 skills (secure-external-ingestion, system-prompt-design, agent-action-surface). Content isn't escaping delimiter strings before wrapping.
2. **Indirect prompt injection (RAG / tool output) unaddressed** — flagged in all 5 skills. The dominant real-world LLM01 vector is never named.
3. **Language violations** — `prevent` / `protects` / `comprehensive` / `critical defense` slipped into multiple skills and templates.
4. **Empty Effectiveness fields** — several skills have blank "Effectiveness:" bullets (rendering bug or unfilled placeholders).
5. **Unicode tag-character smuggling (U+E0000–U+E007F)** — flagged in 4 of 5 skills as a bypass of zero-width character stripping.
6. **Multi-turn / context priming** — flagged in all 5 skills (mostly v1.0.1, but pervasive).

### Notes

- Gemini API key initially had no billing connected; first partial run (secure-external-ingestion only) got 2-reviewer data. After billing fix, Gemini re-queried successfully.
- Gemini required `max_output_tokens` bump from 2000 to 16000 due to thinking-model token budget (thinking tokens count against output limit).
- `google-generativeai` SDK is deprecated; `google-genai` migration tracked as future cleanup.
- Triage layer rejected several reviewer hallucinations — GPT misreading `html.escape()` behavior, Claude's `\n\nHuman:` token-smuggling claim against structured Messages API, GPT inverting sentence meaning in a rewrite suggestion.

---

## Run 2 — 2026-04-13

**Harness:** commit `933d2e9` (includes all Run 1 fixes + permanent limitations docs)
**Skills reviewed:** all 5
**Reviewers:** claude-sonnet-4-6, gpt-4o, gemini-2.5-pro
**Triage model:** claude-opus-4-6 (4 skills); **manual triage** (secure-external-ingestion — see Notes)
**Raw output:** `tests/adversarial-review/results/2026-04-13/` (gitignored — local copy only)
**Fixes applied between Run 1 and Run 2:** commit `bdc66ba` (47 fix-now items addressed), commit `933d2e9` (permanent limitations documented)

### Results

| Skill | Fix-now | v1.0.1 | Won't-fix | Rejected |
|---|---|---|---|---|
| secure-external-ingestion | 6 | 8 | 6 | 3 |
| llm-endpoint-hardening | 9 | 9 | 9 | 6 |
| output-validation | 10 | 8 | 12 | 5 |
| system-prompt-design | 6 | 7 | 7 | 3 |
| agent-action-surface | 8 | 6 | 8 | 2 |
| **Total** | **39** | **38** | **42** | **19** |

### Delta from Run 1

- Run 1: 47 fix-now → Run 2: 39 fix-now (−8)
- Many Run 1 items were fixed but reviewers found deeper issues in the fixes (e.g., delimiter escape is now present but case-sensitive and missing opening tag)
- New findings not seen in Run 1: broken HTML parser skip-depth logic, undefined `max_chars` variable, Base64 decoding helping attackers, kill switch as DoS vector, information disclosure in error messages
- Permanent limitations (indirect injection, heuristic detection, NFKC coverage) correctly classified as documented limitations in SEI triage; other skills' triage models partially applied the new triage prompt guidance

### Notes

- **secure-external-ingestion triage refusal:** Claude Opus 4.6 refused (stop_reason: refusal) to triage the SEI reviewer content. The combined reviewer files contained explicit attack payloads and exploit descriptions that triggered the safety filter. Triage was performed manually using the same criteria as the automated prompt. Safety preamble was added to triage prompt but did not resolve the refusal. See `docs/TROUBLESHOOTING.md` for details.
- **Triage prompt updated** between runs: added "known permanent limitations" section so the triage model classifies documented inherent limitations as won't-fix rather than fix-now.
- **Triage `max_tokens` increased** from 3000 to 8000 after the expanded triage prompt caused truncation.
- **`google-generativeai` migrated to `google-genai`** — deprecated SDK warning resolved.
- **Run 2 fix-now items are a mix of:** (a) deeper refinements of Run 1 fixes, (b) genuinely new code bugs, (c) scope/language issues the updated triage prompt should have downgraded but didn't consistently apply across all skills.

---

## Run 2 Fix Session — 2026-04-06 (continued)

**Scope:** Inline caveats and snippet warnings — surfacing known limitations directly in SKILL.md at point-of-use
**Files modified:** 3 SKILL.md files (llm-endpoint-hardening, output-validation, secure-external-ingestion)
**Fix log:** [fix-log-2026-04-10.md](fix-log-2026-04-10.md) Phase 3

### Changes applied

- **llm-endpoint-hardening:** Added `# WARNING` comments to Level A (`len()` counts chars not tokens) and Level B (`estimate_tokens` underestimates for CJK; `check_budget`/`record_usage` TOCTOU race) Python snippets. Limitations already documented in Inherent limitations field — warnings now also appear inline where developer copies the code.
- **output-validation:** Added `html.escape()` context caveat (text-node context only, not safe for attribute/JS/CSS/URL). Added prompt leakage caveat (detects cooperative/accidental disclosure only — silent injection passes clean scan). Added `validate_llm_output` snippet caveat (simplified illustration — callers must check warnings list; full fail-closed logic is in the complete template).
- **secure-external-ingestion:** Added encoding normalization trade-off caveat to Level B — decoding converts encoded content the model might ignore into readable plaintext the model will follow; decoded text remains untrusted and must be checked.

### Notes

- Safety filter triggered on Claude Code (Opus 4.6) during an edit attempt mid-session — security-adjacent content in SKILL.md files (attack technique descriptions, encoding bypass examples) triggered the filter while editing `skills/secure-external-ingestion/SKILL.md`. Remaining caveats were completed in the subsequent session.

---

## Run 3 — 2026-04-14

**Harness:** commit `2e6600b` (`fix: address Run 2 adversarial review findings — inline caveats and code quality`)
**Skills reviewed:** all 5
**Reviewers:** claude-sonnet-4-6, gpt-4o (full 3-reviewer set only on output-validation, which additionally included gemini-2.5-pro — see Notes)
**Triage model:** claude-opus-4-6
**Raw output:** `tests/adversarial-review/results/2026-04-14/` (gitignored — local copy only)
**Fixes applied between Run 2 and Run 3:** commit `2e6600b` (partial Run 2 fix session — inline caveats in 3 of 5 SKILL.md files; session interrupted by safety filter on `secure-external-ingestion` edit)

### Results

| Skill | Fix-now | v1.0.1 | Won't-fix | Rejected |
|---|---|---|---|---|
| secure-external-ingestion | 8 | 8 | 10 | 5 |
| llm-endpoint-hardening | 6 | 7 | 12 | 4 |
| output-validation | 9 | 7 | 8 | 5 |
| system-prompt-design | 6 | 7 | 7 | 4 |
| agent-action-surface | 8 | 6 | 8 | 3 |
| **Total** | **37** | **35** | **45** | **21** |

### Delta from Run 2

- Run 2: 39 fix-now → Run 3: 37 fix-now (−2)
- Run 2: 38 v1.0.1 → Run 3: 35 v1.0.1 (−3)
- Run 2: 42 won't-fix → Run 3: 45 won't-fix (+3) — more items correctly classified against permanent-limitation guidance as the triage prompt matured
- Run 2: 19 rejected → Run 3: 21 rejected (+2)
- New findings surfacing in Run 3 (partial list): kill switch orphaned from endpoint template (no wiring); TypeScript `req.body.message.length` missing type guard (500 on missing/non-string); middleware ordering not documented as security invariant; URL-safe Base64 (`base64url`) missed by `BASE64_PATTERN`; CSS Color Level 4 syntax / `hsl()` / named colors missed by `HIDDEN_STYLE_PATTERNS`; `validate_json_schema` does not reject extra/unexpected fields (prototype-pollution-style payloads pass); React JSX encoding presented as XSS protection without the URL-attribute caveat (`href={userContent}` + `javascript:` is live XSS); CSV/formula injection not covered despite "databases/documents" in trigger; ambient authority in tool-call arguments not addressed; TOCTOU on HITL approval; sensitive data exposure in credential-scan output (matched patterns printed unredacted).

### Architectural decisions split

- Of the 37 Run 3 fix-now items, **16 were reclassified as architectural / design decisions** requiring user judgment before implementation (reframing guidance, breaking API changes, API primitives that do not exist, etc.). These were captured in [architectural-decisions.md](architectural-decisions.md) / [architectural-decisions.html](architectural-decisions.html) (interactive decision page).
- Decisions recorded in [decisions.json](decisions.json) — 5 Accept, 11 Modify, 0 Defer to v1.0.1.
- The remaining 21 Run 3 fix-now items are direct code/language fixes and will be addressed in the standard fix pass alongside the 16 accepted/modified architectural items.

### Cross-skill patterns identified

1. **False-confidence artifacts in demo output** — `CLEAN` binary pass signals, imperative "NEVER has write permissions" language, overclaim adjectives ("significantly reduces," "most robust"). Tightened in architectural decisions #11 and #13.
2. **Incomplete denylists** — `DESTRUCTIVE_TOOL_PREFIXES` (agent-action-surface), `sk-[A-Za-z0-9]{20,}` credential regex (system-prompt-design), CSS hidden-content patterns (secure-external-ingestion). Architectural decisions #9 and #12 pivot to allowlist + external tool delegation (detect-secrets / truffleHog) where appropriate.
3. **Trigger scope vs. template coverage mismatch** — output-validation says "SQL, shell, code execution" in trigger but ships HTML-only templates. Architectural decision #4 narrows the trigger and adds explicit cross-context warning.
4. **Recommendations without implementation path** — "separate inference pools" (SEI Level C), "dual-prompt architecture" (SPD Level C), "+1 LLM output filter" (SPD Level C), "audit logging with full context" (AAS Level C). Architectural decisions #1, #7, #8, #15 reframe or demote each.
5. **MCP schema-trust gap** — tool names, descriptions, parameter schemas not treated as attacker-controlled. Architectural decision #14 adds six-control subsection with schema-drift framing.
6. **Silent-suppression defaults** — `trusts_input_from: str | None = None` defaults to no-declared-trust-source, suppressing downstream warnings. Architectural decision #16 makes the field required.

### Notes

- **2-reviewer coverage for 4 of 5 skills** — only `output-validation` has `gemini.md`; the other four skills have `claude.md` + `gpt.md` only. Gemini reviewer dropped from 4 skills; root cause not yet diagnosed (possible rerun needed or API/quota issue mid-run). Future runs should verify all three reviewers returned before triage proceeds.
- **Between-run fixes were incomplete** — commit `2e6600b` landed inline caveats in only 3 of 5 SKILL.md files (llm-endpoint-hardening, output-validation, secure-external-ingestion) before the safety filter interrupted edits to `secure-external-ingestion`. The remaining 2 SKILL.md files (system-prompt-design, agent-action-surface) still need the same inline-caveat pass applied.
- **Architectural decision session** — Run 3 triage surfaced design-level questions (not just line-level fixes), prompting the creation of `architectural-decisions.html` as an interactive decision page. Initial form lost state (no localStorage or export); decisions were recovered from the open tab via DevTools console snippet before closure. HTML form persistence (localStorage + Export/Import JSON) to be patched before any future decision session.
- **Three-tier output model established** — (a) skill templates = drop-in code, (b) posture/CTO report scaffolds = starter code with TODOs, (c) Developer Recommendations Report = advisories for developer-only decisions. Developer Recommendations Report will extend the existing `/llm-secure-patterns:report` command. See [decisions.json](decisions.json) `design_principles_established` for full list.

---

## Run 4 — 2026-04-24

**Harness:** commit `1fa18ed` (`feat: add Developer Recommendations Report to /llm-secure-patterns:report` — extended `driver.py` to bundle `skills/<name>/recommendations/*.md` into reviewer payloads)
**Skills reviewed:** all 5
**Reviewers:** claude-sonnet-4-6, gpt-4o, gemini-2.5-pro (full trio on all 5 skills — first run with full Gemini coverage)
**Triage model:** claude-opus-4-6
**Raw output:** `tests/adversarial-review/results/2026-04-24/` (gitignored — local copy only)
**Fixes applied between Run 3 and Run 4:**
- 16 architectural decisions implemented (commits `d6ab805..bd7bfb6`, 2026-04-16)
- 20 direct code/language fixes (commits `a4ecc4f..e0fb9d5`, 2026-04-20)
- Run 2 partial-session caveats completed (commit `e0fb9d5`)
- Developer Recommendations Report build (commits `1fa18ed`, `c3b444e`, 2026-04-23)
- Submission-workflow cleanup, positioning text, plugin.json description (commits `6f8dd10..60959fe`, 2026-04-23 to 2026-04-26)

### Results

| Skill | Fix-now | v1.0.1 | Won't-fix | Rejected |
|---|---|---|---|---|
| secure-external-ingestion | 8 | 9 | 7 | 4 |
| llm-endpoint-hardening | 9 | 8 | 6 | 4 |
| output-validation | 12 | 12 | 9 | 3 |
| system-prompt-design | 10 | 9 | 13 | 4 |
| agent-action-surface | 8 | 9 | 11 | 5 |
| **Total** | **47** | **47** | **46** | **20** |

### Delta from Run 3

- Run 3: 37 fix-now → Run 4: 47 fix-now (**+10**)
- Run 3: 35 v1.0.1 → Run 4: 47 v1.0.1 (+12)
- Run 3: 45 won't-fix → Run 4: 46 won't-fix (+1)
- Run 3: 21 rejected → Run 4: 20 rejected (−1)

The fix-now count went up, not down. This counters the documented "exponential decay" convergence pattern of iterative review and is the headline finding of Run 4. Three contributing factors identified:

1. **Full Gemini coverage on all 5 skills** (Run 3 had Gemini on only 1 of 5). Roughly 10 of the 47 fix-now items came from Gemini-solo findings (NFKC homoglyph enumeration, Level C classifier framing, Jinja2 context-aware misframing, OWASP scope narrowing, ReDoS-adjacent concerns).
2. **Run 3 fix work introduced new code with its own bugs.** Documented "fix-injected regression" pattern (Mozilla 2022 study). Specific examples: `redact_for_audit_log` credential pattern misses `sk-ant-api03-` and `sk-proj-` (decision #15), `SAFE_READ_PREFIXES` defeated by compound names like `read_and_exfiltrate` (decision #12), `wrap_cross_model_output` regex fails at end-of-string (decision #14 work), `source_model` parameter not sanitized in cross-model wrappers.
3. **Reviewers picked up overclaim language slips that crept in during Run 3 fix cycles.** "prevent" / "significantly reduce" / "catches" / "Safe for ..." appeared in templates edited during the Run 3 fix pass. Suggests Run 3 verification did not include a final language-standard grep before claiming completion.

### Cross-skill patterns identified

1. **Fix-injected regressions** — listed above. The pattern itself is the most actionable finding: future fix cycles need a final verification step before claiming completion (language grep, regex re-test on edge cases, cross-skill annotation review).
2. **Production-readiness caveats missing on demo code** — in-memory rate limiter, single-process spend monitor, hardcoded model strings, hardcoded `cost_per_1k_tokens` defaults all need stronger "demo only" framing or opt-in gating.
3. **OWASP scope overclaims** — multiple skills frame OWASP coverage broader than implementation supports (LLM01 in System Prompt Design, LLM05/LLM02 in Output Validation). Documented as v1.0.1 narrowing work.
4. **Unicode coverage gaps** — BiDi overrides (U+202A–U+202E, U+2066–U+2069), U+E0000 tag characters, zero-width joiners, and partial NFKC homoglyph coverage flagged across skills. Some are existing documented limitations needing enumeration; BiDi is a genuine gap.
5. **Multi-turn / context priming surfaces** — flagged in all 5 skills as v1.0.1. Already a documented permanent limitation in SCOPE.md, but cross-references and per-skill notes need strengthening.
6. **Rec files for the Developer Recommendations Report** — first run with reviewers seeing them. Substantive critique was minimal; most fix-now items target existing SKILL.md and template code, not the new rec files. Rec content held up well under review.

### Notes

- **First Run with full Gemini coverage on all 5 skills** — closes the gap from Run 3 (where only `output-validation` had Gemini reviews). Future runs should continue verifying all three reviewers returned before triage proceeds.
- **Triage layer rejected ~20 findings** — including overclaim restatements, vague restatements, misreadings of code architecture, and one verdict-level claim that the skill was "not safe to ship" (rejected as an overall framing rather than an actionable issue).
- **The 47 count is misleading on its face.** Composition: roughly 12-15 truly exploitable code bugs, 7 language violations (mechanical fixes), and 25+ scope-overclaim / framing / caveat-strengthening items. Gross count alone overstates severity.
- **Recommended next step: focused Run 5 fix cycle on a branch.** Per documented "5-6 review round cap" guidance: one more disciplined fix cycle (real bugs + language violations + scope-narrowing on a branch), Run 5 to validate convergence, then ship with v1.0.1 carry-overs documented. If Run 5 stabilizes near or above 47, the research advice is to ship rather than do Run 6 — diminishing returns exceed regression risk beyond round 5.
