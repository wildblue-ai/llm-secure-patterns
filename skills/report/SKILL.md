---
name: report
description: Generate OWASP LLM Top 10 security posture report from codebase annotations
user-invocable: true
allowed-tools: [Read, Grep, Glob, Write]
metadata:
  author: WildBlue.AI
  version: 0.9.0
  homepage: https://github.com/wildblue-ai/llm-secure-patterns
---

# /report — LLM Security Posture Report

## Purpose

This command scans the current project for `# SECURITY:` and `// SECURITY:` annotations placed by llm-secure-patterns skills, maps them to the OWASP Top 10 for LLM Applications 2025 (published November 2025), and generates a `SECURITY_POSTURE.md` at the project root.

The report is the payoff of the annotation system: an audit-ready document that shows exactly which OWASP LLM risks have verified mitigations, which have gaps, and what risk tradeoffs were accepted.

---

## Instructions

Follow these steps in order when the user invokes `/report`.

### Step 1 — Collect annotations

Use Grep to search for `SECURITY:` across all files in the project.

- Pattern: `SECURITY:`
- Exclude these directories: `node_modules`, `.git`, `venv`, `__pycache__`, `.env`, `dist`, `build`
- Search all file types (the annotation format is `# SECURITY:` in Python/YAML/shell and `// SECURITY:` in JS/TS/Go/Java/etc.)

For each match, extract the following fields from the structured annotation comment block:

| Field | Description |
|---|---|
| **OWASP ID** | e.g., `LLM01`, `LLM02` |
| **Confidence level** | `HIGH`, `MODERATE`, or `LOW` |
| **Pattern name** | The name of the mitigation pattern applied |
| **Level chosen** | The protection level selected (e.g., `Low`, `Moderate`, `High`) |
| **Declined options** | Any stronger level that was offered but not selected |
| **File path** | Absolute or project-relative path to the annotated file |
| **Line number** | Line number of the annotation |
| **Date applied** | Date the annotation was placed |
| **OWASP version** | Which OWASP LLM Top 10 version the annotation references (e.g., `2025`) |
| **Plugin version** | Version of llm-secure-patterns that placed the annotation |

If any field is missing from an annotation, note it as `[not recorded]` in the report.

Read several lines of context around each annotation to capture the full structured comment block (annotations may span multiple comment lines).

### Step 2 — Map to OWASP LLM Top 10 categories

Organize all collected annotations by OWASP category. The canonical list is:

| ID | Category |
|---|---|
| LLM01 | Prompt Injection |
| LLM02 | Sensitive Information Disclosure |
| LLM03 | Supply Chain |
| LLM04 | Data and Model Poisoning |
| LLM05 | Improper Output Handling |
| LLM06 | Excessive Agency |
| LLM07 | System Prompt Leakage |
| LLM08 | Vector and Embedding Weaknesses |
| LLM09 | Misinformation |
| LLM10 | Unbounded Consumption |

**For each category WITH annotations:** list verified mitigations including file paths, line numbers, confidence levels, and risk tradeoffs (level chosen, options declined).

**For each category WITHOUT annotations:** flag as a gap and suggest which skill addresses it, using this mapping:

| Category | Addressed by |
|---|---|
| LLM01: Prompt Injection | Secure External Ingestion, LLM Endpoint Hardening, System Prompt Design, Agent Action Surface Control |
| LLM02: Sensitive Information Disclosure | Output Validation, System Prompt Design |
| LLM03: Supply Chain | NOT ADDRESSABLE BY CODE-TIME GUIDANCE |
| LLM04: Data and Model Poisoning | NOT ADDRESSABLE BY CODE-TIME GUIDANCE |
| LLM05: Improper Output Handling | Output Validation |
| LLM06: Excessive Agency | Agent Action Surface Control |
| LLM07: System Prompt Leakage | System Prompt Design |
| LLM08: Vector and Embedding Weaknesses | NOT ADDRESSABLE BY CODE-TIME GUIDANCE |
| LLM09: Misinformation | Partially addressable via Output Validation (PII scanning, HTML escaping — does not address hallucination root cause) |
| LLM10: Unbounded Consumption | Secure External Ingestion, LLM Endpoint Hardening |

**Important — this is a gap-suggestion mapping, not a transitive-credit mapping.** A category is MITIGATED only when an annotation directly references its OWASP ID. Do not mark LLM01 MITIGATED just because a skill listed under "Addressed by LLM01" fired for a different category. Example: if only an LLM10 annotation from LLM Endpoint Hardening is present, LLM10 is MITIGATED and LLM01 is NOT ADDRESSED — even though that skill also addresses LLM01 at a different level with a different pattern. A skill's presence in the Addressed-by list means it **can** mitigate that category when applied with an appropriate pattern; it does not mean every application of that skill mitigates every category it could address. This preserves the project's "report mitigations applied, not security achieved" methodology.

### Step 3 — Handle unannotated codebases

If **zero** `# SECURITY:` or `// SECURITY:` annotations are found, perform a best-effort LLM analysis of the codebase:

1. Use Glob to discover source files across the project.
2. Use Grep to search for common security patterns:
   - Rate limiters (e.g., `rate.limit`, `rateLimit`, `throttle`, `RateLimiter`)
   - Input sanitizers (e.g., `sanitize`, `escape`, `DOMPurify`, `bleach`, `strip_tags`)
   - Auth middleware (e.g., `authenticate`, `authorize`, `requireAuth`, `jwt.verify`, `passport`)
   - Schema validators (e.g., `Joi`, `zod`, `pydantic`, `jsonschema`, `ajv`, `validate`)
   - Output encoding (e.g., `encodeURI`, `html.escape`, `markupsafe`)
   - Prompt injection defenses (e.g., `system_prompt`, `instruction_hierarchy`, `delimiter`, `canary`)
   - Token/cost limits (e.g., `max_tokens`, `maxTokens`, `token_limit`, `budget`)
3. For each detected pattern, record the file path, line number, and a brief description.
4. **Clearly label** all such findings as: *"Possible mitigations (detected by analysis, unverified)"* — these are **separate from** *"Verified mitigations (annotated)"*.
5. Suggest running the relevant skills to review, verify, and annotate these patterns.

### Step 4 — Staleness detection

Check each annotation for staleness using these rules:

| Condition | Flag |
|---|---|
| OWASP version older than `2025` | Flag as referencing an outdated OWASP version |
| Plugin version older than the currently installed version (`0.9.0`) | Flag as placed by an older plugin version |
| "Date applied" more than 6 months before today's date | Flag as potentially stale |

For every stale annotation, recommend re-running the relevant skill to refresh the mitigation and update the annotation.

### Step 5 — Include risk tradeoffs

For each annotated mitigation:

1. Show the **level chosen** (e.g., Low, Moderate, High).
2. If a stronger option was declined, show **what was declined** and **why** (from the annotation).
3. Include **"To upgrade"** guidance: which skill to re-run and which level to select for stronger protection.

**Also aggregate by skill.** Group all annotations by their `Applied by:` field (which names the originating skill, e.g., "LLM Endpoint Hardening"). For each skill that fired, determine the tier(s) applied:

- If all annotations from a given skill are at the same tier: report as `Tier applied: A (Low)` / `B (Moderate)` / `C (High)`.
- If annotations from a given skill span multiple tiers: report as `Tier applied: mixed (A: 3, B: 2)` listing the count per tier.

This skill-level tier rollup feeds the **Skill Coverage Summary** table in Step 6.

### Step 6 — Generate SECURITY_POSTURE.md

Write the report to the project root (`SECURITY_POSTURE.md`) using the Write tool.

**The report has two sections: a Summary and an optional Detailed view.**

Use this format:

```markdown
═══════════════════════════════════════════════════════════════════
          LLM SECURITY POSTURE REPORT
═══════════════════════════════════════════════════════════════════

  Project:    [project directory path]
  Date:       [today's date]
  Generated:  llm-secure-patterns v0.9.0
  Framework:  OWASP Top 10 for LLM Applications 2025 (Nov 2025)

═══════════════════════════════════════════════════════════════════

  COVERAGE SUMMARY: [N] of 7 addressable categories mitigated

  [Table with two columns: Category and Status]

  For each category, use one of these status values:
  - MITIGATED (high|moderate|low) — [brief description]
  - PARTIALLY MITIGATED — [brief description]  (use ONLY for LLM09 when
    Output Validation annotations exist; LLM09 is partially addressable
    by design, so even with annotations applied, full coverage is not
    achievable via code-time guidance)
  - NOT ADDRESSED — apply [skill name]
  - NOT ADDRESSED (only partially addressable in general) — for LLM09
    when no Output Validation annotations exist; reads as: not addressed
    in this codebase, and even if addressed, max coverage is partial.
  - NOT ADDRESSABLE BY CODE-TIME GUIDANCE

  NOT ADDRESSABLE BY CODE-TIME GUIDANCE:
  LLM03 (Supply Chain), LLM04 (Data/Model Poisoning), and LLM08
  (Vector/Embedding Weaknesses) require organizational controls:
  verified model sources, training data integrity, dependency
  scanning, and vector database security. These cannot be addressed
  by development-time guidance.

  ─────────────────────────────────────────────────────────────────
  SKILL COVERAGE SUMMARY

  [Table with four columns: Skill | Tier applied | OWASP IDs | Files]

  For each llm-secure-patterns skill that fired in this codebase,
  show one row with:
  - Skill name (e.g., "LLM Endpoint Hardening")
  - Tier applied: A (Low) / B (Moderate) / C (High) / mixed (counts)
    — computed per Step 5
  - OWASP IDs the skill's annotations cover in this codebase
  - File paths where annotations were placed

  Skills that did NOT fire are omitted from this table — see the
  Coverage Summary above for unaddressed categories and which
  skills would address them.

  [If zero annotations found, add:]
  POSSIBLE MITIGATIONS (UNVERIFIED):
  The following patterns were detected by analysis but have not been
  verified. Run the relevant skills to review and annotate.
  [list detected patterns with file paths]

───────────────────────────────────────────────────────────────────
  METHODOLOGY

  This report was compiled by collecting structured # SECURITY:
  comments placed by llm-secure-patterns skills at the time each
  mitigation was implemented. Comments are mapped to the OWASP Top
  10 for LLM Applications 2025 framework, which addresses
  AI/LLM-specific security risks. This report does not address
  general application security (see OWASP Top 10 for traditional
  web application risks). Gap analysis (categories with no
  annotations) was performed by LLM analysis of the codebase and
  should be verified by a qualified reviewer.

  Automated security guidance is not a substitute for human review
  of code. This report documents mitigations applied, not security
  achieved. See SCOPE.md for full limitations.

  Generated by llm-secure-patterns v0.9.0
  For comprehensive AI security assessment: hello@wildblue.ai
═══════════════════════════════════════════════════════════════════
```

**Formatting rules:**
- Use "mitigates" not "prevents" throughout the report.
- For NOT ADDRESSABLE categories (LLM03, LLM04, LLM08), use that exact status and omit mitigation/confidence/staleness fields.
- For NOT ADDRESSED categories, set status to NOT ADDRESSED and include the skill suggestion.
- For MITIGATED categories, include the confidence level in parentheses.
- For LLM09 specifically, distinguish "partially addressable" (capability — what the plugin can ever do) from "partially mitigated" (status — what was actually applied here). Never say "partially addressed" alone — it conflates the two.
- The coverage fraction counts only the 7 addressable categories (excludes LLM03, LLM04, LLM08). LLM09 counts as mitigated when PARTIALLY MITIGATED, since the partial coverage is the maximum achievable.

### Step 7 — Offer detailed version

After displaying the summary on screen, ask:

> "Would you like the detailed version showing file paths, confidence levels, and risk tradeoffs for each mitigation?"

If the user says yes, display the detailed format for each MITIGATED category:

```
LLM01: Prompt Injection — MITIGATED (partial)
  Verified mitigations:
    - [description of mitigation]
      → [file:line] | Level: [chosen] | Confidence: [level]
    - [next mitigation]
      → [file:line] | Level: [chosen] | Confidence: [level]
  Risk acceptance: [what was declined and why, or "None — highest level selected"]
  To upgrade: [which skill and level to re-run]
  Gaps: [remaining unaddressed risks within this category]
  Staleness: [if applicable]
```

For NOT ADDRESSED categories in the detailed view:
```
LLM05: Improper Output Handling — NOT ADDRESSED
  Suggested: Apply Output Validation and Sanitization skill
  Risk: [brief description of what's at risk without this mitigation]
```

For NOT ADDRESSABLE categories in the detailed view:
```
LLM03: Supply Chain — NOT ADDRESSABLE BY CODE-TIME GUIDANCE
  Requires: Verified model sources, signed packages, dependency scanning
  See: SCOPE.md for full explanation
```

Append the detailed section to `SECURITY_POSTURE.md` below the summary, separated by a clear heading:

```markdown
═══════════════════════════════════════════════════════════════════
          DETAILED FINDINGS
═══════════════════════════════════════════════════════════════════
```

The detailed section goes in the same file — one document is easier to share with auditors or management.

### Step 8 — Generate DEVELOPER_RECOMMENDATIONS.md

Generate a second file, `DEVELOPER_RECOMMENDATIONS.md`, alongside `SECURITY_POSTURE.md`. The two files serve different audiences:

| File | Audience | Content |
|---|---|---|
| `SECURITY_POSTURE.md` | CTO / auditor | Strategic posture — what was applied, where, gaps, risk tradeoffs |
| `DEVELOPER_RECOMMENDATIONS.md` | Developer | Follow-up scaffolds and advisories for decisions that only the developer can make |

The Developer Recommendations Report is assembled from per-decision files in `skills/report/recommendations/`. **Only load the files whose trigger condition is satisfied by the annotations found in Step 1.** Unfired recommendations stay out of context and out of the report.

#### Trigger mapping

| Rec file | Fires when |
|---|---|
| `recommendations/01-trust-tier-credentials.md` | Any annotation from **Secure External Ingestion** (pattern name references secure-external-ingestion or the annotation OWASP ID set {LLM01, LLM10} with a pattern matching external ingestion) |
| `recommendations/02-token-counting.md` | Any annotation from **LLM Endpoint Hardening** referencing token counting or input size (Level A/B) |
| `recommendations/04-sql-shell-reminder.md` | Any annotation from **Output Validation** (LLM05) |
| `recommendations/07-dual-prompt-split.md` | Any annotation from **System Prompt Design** recording Level C for LLM07 |
| `recommendations/08-output-filter-interim.md` | Any annotation from **System Prompt Design** recording Level C for LLM07 |
| `recommendations/09-secret-scanners.md` | Any annotation from **System Prompt Design** referencing credential scanning (LLM02) |
| `recommendations/12-allowlist-extension.md` | Any annotation from **Agent Action Surface Control** (LLM06) |
| `recommendations/13-write-permission-enforce.md` | Any annotation from **Agent Action Surface Control** (LLM06) |
| `recommendations/14-mcp-trust-scaffolds.md` | Any annotation from **Agent Action Surface Control** at Level B or higher with MCP servers configured |
| `recommendations/15-audit-log-deployment.md` | Any annotation from **Agent Action Surface Control** at Level C referencing audit logging |

When in doubt about whether a trigger is satisfied, include the recommendation. False positives (an irrelevant advisory) are cheaper than false negatives (a missing one).

#### Assembly procedure

1. From the annotations collected in Step 1, determine the set of fired recommendation files per the trigger mapping above.
2. For each fired file, use the **Read** tool to load its contents. Strip the YAML frontmatter. Keep the rest verbatim — do not paraphrase scaffolds or advisories.
3. Write `DEVELOPER_RECOMMENDATIONS.md` to the project root with this structure:

```markdown
═══════════════════════════════════════════════════════════════════
          LLM SECURITY — DEVELOPER RECOMMENDATIONS
═══════════════════════════════════════════════════════════════════

  Project:    [project directory path]
  Date:       [today's date]
  Generated:  llm-secure-patterns v0.9.0
  Companion:  SECURITY_POSTURE.md (CTO posture report)

═══════════════════════════════════════════════════════════════════

  This report lists follow-up items for the developer based on which
  skills actually fired in this codebase. Each entry is either a
  scaffold (drop-in starter code) or an advisory (a decision only the
  developer can make). Items for skills that did not fire are
  omitted — run the relevant skill first if coverage is missing.

  See SCOPE.md for what this plugin does and does not cover.

───────────────────────────────────────────────────────────────────

[Inlined contents of each fired recommendation file, in numeric
order by decision number, separated by a horizontal rule.]

═══════════════════════════════════════════════════════════════════
  Generated by llm-secure-patterns v0.9.0
  For comprehensive AI security assessment: hello@wildblue.ai
═══════════════════════════════════════════════════════════════════
```

4. If **zero** recommendation files fire (no skills fired at all, or only skills with no dev-report items), still write the file with a short body: "No developer follow-ups to report — no annotated mitigations were found in this codebase. Run the llm-secure-patterns skills to apply mitigations, then re-run `/report`."

### Step 9 — Prompt user about file disposition

After generating both reports, explain the tradeoff and ask:

> "Two reports generated:
>
> - `SECURITY_POSTURE.md` — strategic posture for CTO / auditors.
> - `DEVELOPER_RECOMMENDATIONS.md` — follow-up scaffolds and advisories for the developer.
>
> Both document your AI-related security architecture, including gaps and risk tradeoffs. Choose how to handle them:
>
> - **A) Commit both** — Visible to collaborators and auditors. Recommended for private repos. For public repos, be aware this exposes which security categories are not yet addressed.
> - **B) Gitignore both** — Local reference only. Recommended for public repos or if your gap analysis is sensitive.
> - **C) Mixed** — e.g. commit `SECURITY_POSTURE.md`, gitignore `DEVELOPER_RECOMMENDATIONS.md` (keeps the posture auditable without publishing the dev to-do list).
>
> Which would you prefer?"

Wait for the user's response before taking any action on the files.
