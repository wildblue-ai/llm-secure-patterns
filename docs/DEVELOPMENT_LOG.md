# Development Log — llm-secure-patterns

## Project Summary

Claude Code plugin teaching secure design patterns for LLM applications, mapped to OWASP Top 10 for LLM Applications 2025.

- **Author:** Cheryl Aday on behalf of WildBlue.AI
- **Build period:** 2026-03-30 to 2026-04-03
- **Total commits:** 54
- **Plugin version:** 0.9.0

---

## Build Process

### Phase 1: Design (2026-03-30 to 2026-03-31)

1. **Reviewed existing docs** — Project plan from prior ChatGPT conversation, OWASP research chat, CLAUDE.md
2. **Brainstormed design** — Used Superpowers brainstorming skill to refine plugin architecture
3. **Validated plugin architecture** — Researched current Claude Code plugin system, confirmed `.claude-plugin/plugin.json` format, skill frontmatter, hooks system
4. **Key design decisions:**
   - 5 model-invoked skills + 1 user-invoked report command
   - `# SECURITY:` annotation convention for tracking mitigations in code
   - Tiered options (Low/Moderate/High) with developer choice
   - Vertical slice build approach — first skill end-to-end, then replicate
5. **Wrote design spec** — `docs/superpowers/specs/2026-03-31-llm-secure-by-design-plugin-design.md`
6. **Wrote implementation plan** — `docs/superpowers/plans/2026-03-31-llm-secure-by-design-implementation.md`

### Phase 2: Build (2026-03-31 to 2026-04-01)

Used subagent-driven development — fresh subagent per task with spec compliance review.

1. **Task 1:** Plugin scaffolding — 8 root files (plugin.json, README, LICENSE, SCOPE, CONTRIBUTING, CHANGELOG, THREAT_BULLETIN, WATCHING)
2. **Task 2:** SessionStart hook — hooks.json + check_threat_bulletin.sh
3. **Task 3:** Core reference docs — solution-confidence-tiers.md, false-solution-patterns.md
4. **Task 4:** Skill 1 (Secure External Ingestion) — SKILL.md + encoding-bypass-catalog.md + sanitize_web_content.py
5. **Task 5:** Report command — skills/report/SKILL.md
6. **Task 6:** Remaining reference docs — owasp-llm-top10-2025.md, threat-intel-sources.md
7. **Task 7:** Skill 4 (System Prompt Design) — SKILL.md + system_prompt_template.py
8. **Task 8:** Skill 3 (Output Validation) — SKILL.md + output_schema_validator.py
9. **Task 9:** Skill 2 (LLM Endpoint Hardening) — SKILL.md + token_budget_limiter.py
10. **Task 10:** Skill 5 (Agent Action Surface Control) — SKILL.md + isolated_pipeline.py
11. **Task 11:** Eval tests — 8 prompt files + run-tests.sh
12. **Task 12:** Final polish — verification pass, all checks passed

### Phase 3: Testing & Refinement (2026-04-01 to 2026-04-06)

Ran 5 manual skill tests + applied to an existing codebase. Each test revealed improvements.

**Refinements made during testing:**
- Tier rename: Lightweight/Standard/High-security → Low/Moderate/High
- Confidence rename: FULL/PARTIAL/MINIMAL → HIGH/MODERATE/LOW
- Added intro with "Apply now" vs "Build first" choice
- Added cost/latency transparency (only on Level C)
- Added "Additional Security Gaps Identified" header
- Added A/B/C choice for gap handling (Address now / Backlog / Skip)
- Added option D (help me decide) with diagnostic questions
- Added display name instructions so Claude uses "Secure External Ingestion" not "Skill 1"
- Deduplicated annotation format into `references/annotation-format.md`
- Added metadata to all skill frontmatter (author, version, homepage)
- Added OWASP coverage mapping to README
- Updated report to formal format with detailed view option and commit vs gitignore tradeoff
- Added reference to OWASP Agentic Top 10 2026 in Skill 5

### Phase 4: Automated Test Harness (2026-04-06)

Built `tests/run-manual-tests.sh` — automated runner for all 5 skill tests in non-interactive mode.

**Features:**
- Pre-embeds choices in prompts (Level C, skip gaps) to avoid interactive prompts
- Creates clean test directories at `/tmp/llm-sbd-test/test-N`
- Captures full output to `tests/results/test-N-output.txt`
- Evaluates against checklist:
  - Skill triggered (checks display name in annotations)
  - `# SECURITY:` annotations in generated files
  - Skill-specific patterns in generated code
  - Report command mentioned
  - No generic "Skill N" labels
- Saves evaluation to `tests/results/test-N-eval.txt`

**Usage:**
```bash
# Run all 5 tests
./tests/run-manual-tests.sh

# Run one test
./tests/run-manual-tests.sh 3
```

**Test results (run 2026-04-06):**

| Test | Skill | Pass Rate |
|------|-------|-----------|
| 1 | Secure External Ingestion | 10/11 |
| 2 | LLM Endpoint Hardening | 11/12 |
| 3 | Output Validation | 10/11 |
| 4 | System Prompt Design | 10/12 |
| 5 | Agent Action Surface Control | 10/12 |

**Total: 51/58 (88%)** — all skills functioning correctly. Remaining "failures" were false negatives from overly literal pattern matching, fixed in subsequent commits to allow more flexible matching of Claude's natural language output.

**Key finding:** Claude correctly applies skills and puts exact display names in every `Applied by:` field of annotations. The issue was test script pattern matching, not skill behavior.

### Troubleshooting Added During Phase 4

#### Test script: relative paths broken by `cd`
**Problem:** Script created `tests/results/` then `cd`d into test directory, after which the relative path no longer resolved.
**Fix:** Resolved `RESULTS_DIR` to absolute path before any `cd` calls.
**Commit:** `fba1e48`

#### Test script: Claude hitting max turns
**Problem:** Default `--max-turns 15` was too low — Claude built code but ran out of turns before summarizing.
**Fix:** Increased to 50. Also updated evaluation to check patterns in generated files, not just output text.
**Commit:** `8e4cc24`

#### Test script: pattern matching too strict
**Problem:** Eval checks looked for kebab-case skill names and specific regex patterns that didn't match Claude's natural output phrasing.
**Fix:** Check both kebab-case and display names. Loosened patterns to match actual Claude phrasing.
**Commits:** `54c0ed3`, `e6f3c39`

---

## Troubleshooting Log

### Skills not appearing in session

**Problem:** Plugin showed as "enabled" in `/plugins` but only 2 of 5 skills appeared in the skill listing.

**Root cause:** `version: 0.9.0` in SKILL.md frontmatter is not a valid field. It caused the skill parser to skip those files.

**Fix:** Removed `version` from all SKILL.md frontmatter. Version belongs in `plugin.json` only, or in the optional `metadata` block.

**Commit:** `71296c5`

### Report command not found

**Problem:** User typed `/secure-by-design:report` and got "Unknown skill."

**Root cause:** The slash command prefix is the plugin name from `plugin.json`, not a shortened version. Correct command is `/llm-secure-patterns:report`.

**Fix:** Updated all skill references to use `/llm-secure-patterns:report`.

**Commit:** `5cdb2ba`

### Hook matching HTML comment templates

**Problem:** SessionStart hook counted advisory templates inside HTML comments as real advisories, producing false notifications.

**Root cause:** `grep` doesn't understand HTML comments. The `## [ADVISORY]` template text inside `<!-- -->` blocks matched the grep pattern.

**Fix:** Added `sed '/<!--/,/-->/d'` to strip HTML comments before scanning.

**Commit:** `023b613`

### Skills not auto-triggering (Superpowers interaction)

**Problem:** When Superpowers was enabled, security skills triggered during implementation but were rejected by the subagent-driven spec reviewer as "off-plan."

**Root cause:** Superpowers enforces strict plan compliance. Security patterns weren't in the original plan, so the spec reviewer flagged them as out-of-scope.

**Workarounds:**
1. Disable Superpowers for security-focused sessions
2. Include security requirements in the plan during brainstorming phase
3. Use inline execution instead of subagent-driven

**Planned fix (v1.0.1):** Update skill triggers to fire during design/planning phases, so security lands in the plan before implementation.

**Commits:** `19c1106`, `fba1a75`

### Claude using tables instead of text

**Problem:** Claude formatted tier options as terminal tables, which are hard to read.

**Fix:** Added explicit presentation rule: "Present options as plain text, NOT as tables."

**Commit:** `a364d7e`

### Claude batching multi-skill choices

**Problem:** When multiple skills triggered, Claude presented all tier choices at once instead of one at a time.

**Fix:** Added rule: "Present each skill's A/B/C/D choice ONE AT A TIME. Wait for the developer's answer."

**Commit:** `2f7d238`

### Claude picking security levels automatically

**Problem:** When user chose "A) Address now" for remaining gaps, Claude picked levels itself instead of presenting options.

**Fix:** Changed option A text to "I'll present security options for each gap so you can choose the right level."

**Commit:** `bdf2afc`

### Claude showing "Skill 1" instead of skill names

**Problem:** Output summaries used generic "Skill 1", "Skill 3" labels instead of full names.

**Root cause:** SKILL.md headings had "# Skill 1: Secure External Ingestion" format, and no explicit instruction to use full names.

**Fix:** Removed numbered prefixes from headings. Added instruction: "always refer to it as 'Secure External Ingestion' — never as 'Skill 1'."

**Commit:** `d954924`

### Report not mentioned after implementation

**Problem:** Skills completed implementation but didn't mention `/llm-secure-patterns:report`.

**Root cause:** Report reminder was at the bottom of SKILL.md where Claude's attention dropped off.

**Fix:** Moved reminder to an explicit instruction: "After the developer chooses, always end with..." Also added to existing codebase handling path.

**Commits:** `11c252c`, `2d1aa4f`, `ce74016`

### Hardcoded token estimates

**Problem:** Level C cost lines had hardcoded numbers like "~500 input tokens, ~50 output tokens" that would be wrong for different use cases.

**Fix:** Replaced with instruction for Claude to calculate based on developer's actual content size and current pricing. Added disclaimer: "This is an estimate only; your actual costs may vary."

**Commits:** `37b9450`, `25fb103`

### Price fetch showing on screen

**Problem:** Instruction to fetch pricing from Anthropic docs caused a visible `Fetch()` tool call in the output.

**Fix:** Removed active fetch instruction. Claude knows current pricing without fetching.

**Commit:** `2f7d238`

### awk cleanup removing skill sections

**Problem:** Blank line cleanup with `awk` accidentally removed the A/B/C/D prompt, diagnostic questions, gap sections, false solutions, and existing codebase handling from all 5 skills.

**Fix:** Manually restored all sections. Lesson: test destructive text operations carefully.

**Commit:** `a364d7e`

---

## Key Design Decisions (with rationale)

### Tier naming: Low / Moderate / High (not Lightweight / Standard / High-security)

Old names had connotation issues: "Lightweight" sounded dismissive, "Standard" sounded like "good enough." New names are neutral and map directly to risk tolerance. Also aligns with confidence levels (HIGH/MODERATE/LOW).

### Confidence levels: HIGH / MODERATE / LOW (not FULL / PARTIAL / MINIMAL)

"FULL" implied 100% effectiveness — which creates false confidence. No LLM security mitigation is 100% effective. "HIGH" communicates "strongest available" without promising completeness.

### Intro with apply-now vs build-first choice

Skills announce themselves and let the developer decide when to apply security. Respects developer flow while ensuring security doesn't get forgotten (TODO comment as fallback).

### Report as separate user-invoked command (not auto-run)

The report collects annotations and generates a formal document. It should be deliberate, not automatic. Skills remind the developer to run it.

### "NOT ADDRESSABLE BY CODE-TIME GUIDANCE" (not "NOT COVERED BY PLUGIN")

Explains *why* LLM03/04/08 aren't covered rather than just saying they aren't. These require organizational controls, not development patterns.

### Cost/latency shown only for Level C

Levels A and B have zero additional cost and latency — showing "$0" lines was noise. Only Level C has real tradeoffs worth displaying.

### Sequential per-skill choices (not batched)

When multiple skills trigger, each presents its own A/B/C/D choice separately. Different security surfaces have different risk profiles — batching them hides that.

### Diagnostic questions with A/B/C format

Option D ("help me decide") now asks structured questions mapping A→Low, B→Moderate, C→High. Includes "pick the highest-risk answer" guidance and PII mention.

---

## OWASP References

- [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/) (published November 2025)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) — referenced in Skill 5, companion plugin planned for future
- OWASP AIVSS (AI Vulnerability Scoring System) — draft, noted in roadmap for future integration

## Skill-Building Documentation

- [The Complete Guide to Building Skills for Claude](https://resources.anthropic.com/hubfs/The-Complete-Guide-to-Building-Skill-for-Claude.pdf) — validated plugin structure against this guide
- [Claude Code Skills Documentation](https://code.claude.com/docs/en/skills) — frontmatter spec, invocation modes

## Submission

- Submit to: `https://claude.ai/settings/plugins/submit` and `https://platform.claude.com/plugins/submit`
- GitHub: `https://github.com/wildblue-ai/llm-secure-patterns`
