---
name: report
description: Review or audit an existing codebase's security posture against the OWASP LLM Top 10. Reads `# SECURITY:` annotations placed by this plugin and falls back to a best-effort source scan when none are present; writes SECURITY_POSTURE.md and DEVELOPER_RECOMMENDATIONS.md. Use when asked to check, review, audit, scan, or report on the security of LLM/AI integration code.
user-invocable: true
allowed-tools: [Read, Grep, Glob, Write]
metadata:
  author: WildBlue.AI
  version: 1.0.0
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

Use Grep to search for `SECURITY:` across all files in the project to find **candidate** annotations.

- Pattern: `SECURITY:`
- Exclude these directories: `node_modules`, `.git`, `venv`, `__pycache__`, `.env`, `dist`, `build`
- Search all file types (the annotation format is `# SECURITY:` in Python/YAML/shell and `// SECURITY:` in JS/TS/Go/Java/etc.)

For each candidate match, read several lines of surrounding context to capture the full structured comment block (annotations span multiple comment lines).

**Attribution filter — required.** The bare `SECURITY:` token is a common ad-hoc comment, so treat the grep as a candidate finder, not the authority. Count a block as one of *this plugin's* annotations ONLY if it contains an `Applied by: llm-secure-patterns` line. A `# SECURITY:` / `// SECURITY:` comment WITHOUT that signature is not ours: do not map it to OWASP coverage, do not count it toward any tier, and do not include it in the per-skill aggregation. If unattributed `SECURITY:` comments are present, you may note them once under a brief "Unattributed security comments (not placed by this plugin)" heading so the developer knows they exist — nothing more.

For each **attributed** annotation, extract the following fields from the structured comment block:

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

If a field is missing from an attributed annotation, note it as `[not recorded]` in the report.

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

If **zero attributed** annotations are found (no block carries an `Applied by: llm-secure-patterns` line — unattributed `SECURITY:` comments do not count), perform a best-effort LLM analysis of the codebase:

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
| Plugin version older than the currently installed version (`1.0.0`) | Flag as placed by an older plugin version |
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

**`SECURITY_POSTURE.md` always contains two sections: a Summary and a Detailed view. Both are written to the file by default — the Detailed view is NOT optional and is never gated behind a question.**

Use this format:

```markdown
═══════════════════════════════════════════════════════════════════
          LLM SECURITY POSTURE REPORT
═══════════════════════════════════════════════════════════════════

  Project:    [project directory path]
  Date:       [today's date]
  Generated:  llm-secure-patterns v1.0.0
  Framework:  OWASP Top 10 for LLM Applications 2025 (Nov 2025)

═══════════════════════════════════════════════════════════════════

  COVERAGE SUMMARY: [N] of 7 code-time-addressable categories mitigated

  [Table with two columns: Category and Status. List ONLY the 7
   code-time-addressable categories: LLM01, LLM02, LLM05, LLM06, LLM07,
   LLM09, LLM10. Do NOT list LLM03, LLM04, or LLM08 in this table — they
   have their own section at the end of the report.]

  Use the OWASP category title as the row label (e.g., "LLM05: Improper
  Output Handling"). For each category, use one of these status values:
  - MITIGATED (high|moderate|low) — [brief description]
  - PARTIALLY MITIGATED — [brief description]  (use ONLY for LLM09 when
    Output Validation annotations exist; LLM09 is partially addressable
    by design, so even with annotations applied, full coverage is not
    achievable via code-time guidance)
  - NOT ADDRESSED — for any of the 7 addressable categories with no
    attributed annotation. Keep the status word NOT ADDRESSED in the
    table; the detailed view explains why (see "NOT ADDRESSED wording"
    in Step 7). Never downgrade a category to "not applicable" — the
    status stays a flag even when the surface appears absent.
  - For LLM09 with no Output Validation annotations, append "(only
    partially addressable in general)": not addressed here, and even if
    addressed, max coverage is partial.
  - If the applied pattern carries a documented reference-implementation
    gap or deployment-topology caveat (check the fired skill's own
    SKILL.md — a "Known reference-implementation gap" note or similar,
    e.g. in-memory state that does not survive multi-process deployment),
    append a short parenthetical to the brief description in THIS table.
    Do not defer the caveat solely to the detailed Gaps field below — the
    summary table is what gets skimmed. Example: "MITIGATED (moderate) —
    token-budget limiter (single-process only)".

  After the table, add this pointer line:
  "3 categories are not addressable by code-time guidance (LLM03, LLM04,
  LLM08) — see the section at the end of this report."

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

  Generated by llm-secure-patterns v1.0.0
  For comprehensive AI security assessment: hello@wildblue.ai
═══════════════════════════════════════════════════════════════════
```

**Formatting rules:**
- Use "mitigates" not "prevents" throughout the report.
- LLM03, LLM04, and LLM08 do NOT appear in the coverage table or the detailed findings — they go only in the "NOT ADDRESSABLE BY CODE-TIME GUIDANCE" section at the end of the file (Step 7b).
- For NOT ADDRESSED categories, keep the status NOT ADDRESSED and add the best-effort explanation per Step 7 (surface found → name the gap + skill; surface absent → "it does not currently appear…"; unknown → conditional). Never downgrade NOT ADDRESSED to "not applicable."
- For MITIGATED categories, include the confidence level in parentheses.
- For LLM09 specifically, distinguish "partially addressable" (capability — what the plugin can ever do) from "partially mitigated" (status — what was actually applied here). Never say "partially addressed" alone — it conflates the two.
- The coverage fraction counts only the 7 addressable categories (excludes LLM03, LLM04, LLM08). LLM09 counts as mitigated when PARTIALLY MITIGATED, since the partial coverage is the maximum achievable.
- A topology- or deployment-dependent caveat on a MITIGATED control (e.g. in-memory state, single-process assumptions) must appear inline in the summary-table description, not only in the detailed Gaps field — an unqualified MITIGATED badge next to a control whose core guarantee depends on an unstated deployment assumption misrepresents what was verified.

### Step 7 — Always append the detailed findings

`SECURITY_POSTURE.md` is a document, not a chat message — the brevity / one-screen rule does NOT apply to it. Always write the detailed findings into the file, below the summary. Do NOT ask the user whether to include detail; include it by default. (The on-screen chat summary stays brief; the file carries the full detail.)

Write the detailed format into the file for each MITIGATED category:

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

For NOT ADDRESSED categories in the detailed view, keep the OWASP category title and the NOT ADDRESSED status, then add a best-effort explanation. Run a quick surface scan for that category (reuse the Step 3 pattern greps — they apply per-category here even when other categories are annotated) and pick ONE of the three forms below. Never change the status; only state "it does not currently appear…" when the scan actually ran and found nothing.

```
# surface NOT detected
LLM05: Improper Output Handling — NOT ADDRESSED — it does not currently appear that your app renders, stores, or forwards LLM output.

# surface detected but unsecured (a confirmed gap)
LLM05: Improper Output Handling — NOT ADDRESSED — LLM output appears to be rendered/stored at app/views.py:42 without validation. Apply Output Validation.

# could not determine
LLM05: Improper Output Handling — NOT ADDRESSED — if your app renders, stores, or forwards LLM output, apply Output Validation.
```

The surface phrase is category-specific — describe what that OWASP category actually covers (e.g., LLM06 Excessive Agency → "grant the LLM tools, function-calling, or autonomous actions"; LLM01 Prompt Injection → "fetch or ingest untrusted external content into the model context").

LLM03, LLM04, and LLM08 are NOT listed per-category in the detailed findings — they have a dedicated section at the end of the report (see Step 7b below).

Append the detailed section to `SECURITY_POSTURE.md` below the summary, separated by a clear heading:

```markdown
═══════════════════════════════════════════════════════════════════
          DETAILED FINDINGS
═══════════════════════════════════════════════════════════════════
```

The detailed section goes in the same file — one document is easier to share with auditors or management.

### Step 7b — Append the NOT ADDRESSABLE section at the end of the file

After the detailed findings, always append this final section. It lists the three OWASP categories the plugin cannot address at code time, each with one to two sentences of guidance and the OWASP link. Always include all three:

```markdown
═══════════════════════════════════════════════════════════════════
          NOT ADDRESSABLE BY CODE-TIME GUIDANCE
═══════════════════════════════════════════════════════════════════

  Real OWASP LLM risks, but outside what code-time patterns can
  mitigate — handle these through process and infrastructure controls.

  LLM03: Supply Chain — Requires organizational controls: model
    provenance verification, dependency auditing, signed artifacts, and
    trusted registries.
  LLM04: Data and Model Poisoning — Requires controls at the training
    and fine-tuning stages: data provenance, anomaly detection in
    training metrics, and access controls on model artifacts.
  LLM08: Vector and Embedding Weaknesses — Requires controls at the
    retrieval layer: access control on vector stores, embedding
    integrity verification, and retrieval result filtering.

  Full guidance: https://owasp.org/www-project-top-10-for-large-language-model-applications/ (published November 2025)
```

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
  Generated:  llm-secure-patterns v1.0.0
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
  Generated by llm-secure-patterns v1.0.0
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
