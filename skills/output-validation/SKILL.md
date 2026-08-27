---
name: output-validation
description: Use when designing or implementing code where LLM responses are rendered as HTML or markup in a frontend, written to a database, passed to another service, or used to generate emails or documents — fire this skill during architecture/planning discussions, not just implementation. Not for SQL or shell command construction — those require parameterized queries and argument arrays, not string escaping (see the Scope section in SKILL.md)
metadata:
  author: WildBlue.AI
  version: 1.0.0
  homepage: https://github.com/wildblue-ai/llm-secure-patterns
---

> **Note:** This skill provides development guidance, not security guarantees. Patterns mitigate risk; they do not eliminate it. See [SCOPE.md](../../SCOPE.md) for limitations and the threats this plugin is known not to cover.

**When summarizing actions taken using this skill, always refer to it as "Output Validation and Sanitization" — never as "Skill 1" or any generic label.**
**PRESENTATION CONTRACT — brief by default for the ENTIRE interaction, not just the tier list.**
**Goal: every message this skill emits fits on ONE screen — about 15 lines of text or fewer.** If a message runs longer than that, you have added chatter; cut it back to the block itself.

- **No preamble.** Do not explain what the skill does, restate the threat, or paraphrase the "What this skill does" / OWASP sections into chat. Lead with the block for the current step. (If the developer asks "why," then explain.)
- **One step per message.** Emit the intro block; stop; wait for A/B. After A, emit the brief picker block; stop; wait for the pick. Never merge the two; never preview the tiers in the intro message.
- **Question tools obey the same pacing.** If presenting a decision through a structured question tool (e.g. AskUserQuestion): exactly one question per tool call, in the same order — intro A/B first, tier picker only after A is chosen. Never batch the intro and the tier picker into one call. A tier-picker question must keep the D) help-me-decide option and say in its question text that "details" / "verbose" expand the tier descriptions.
- **No closing restatement.** After a block ends in its question/action line, stop. Do not re-list or re-ask the options.
- The only thing that expands this is "details" or the `llm-secure-patterns: verbose` preference.
- **The post-build completion obeys this too — and it is the turn's FINAL message.** When the work is done, emit the single completion block defined in "Before completing this skill" — a short comma list of controls (no parentheticals), files, a one-line gap disposition, the adjacent-surface A/B/C inline, then the report line. One block, ≤ one screen. Emit it as the last message of the turn and add nothing after it: no overall recap, no run instructions, no architecture restatement. The block itself satisfies any end-of-turn summary requirement.

**Before presenting any security options, always start with this intro:**

> **llm-secure-patterns** has detected code that would benefit from LLM security guidance (Output Validation and Sanitization, OWASP LLM Top 10 2025).
>
> - **A) Apply security now** — I'll walk you through security options before writing code
> - **B) Build first, secure later** — I'll build the code now and add a `TODO: SECURITY` reminder. Run `/llm-secure-patterns:report` when you're ready to add security layers.

**Emit only this intro — no threat explanation, no tier preview, nothing else — then stop and wait for A or B.**

If the developer picks A, proceed with the tiered options below. If they pick B, build the code without security patterns but add a `# TODO: SECURITY — run llm-secure-patterns to apply LLM security patterns` comment at the top of the relevant file(s).

# Output Validation and Sanitization

## What this skill does

This skill mitigates improper output handling and sensitive information disclosure risks when LLM responses leave the model and enter downstream systems. Model output is untrusted data — it can contain malicious HTML/JavaScript, fabricated URLs, leaked system prompt fragments, PII, or malformed structures that crash downstream parsers. This skill applies zero-trust validation patterns to common LLM output channels (HTML rendering, JSON APIs, downstream services).

## OWASP mapping

- **LLM05 (Improper Output Handling — partial):** Model output used without validation in frontends, databases, or code execution. This skill specifically covers HTML rendering (text-node escaping, URL-attribute scheme allowlisting), JSON structural validation, CSV formula-injection escaping, and pattern-based scans. It does **not** address YAML/TOML config injection, GraphQL response handling, PDF/DOCX macro vectors, code-execution sinks (`eval`/`exec`), or every output sink an application may write to — see Scope below.
- **LLM02 (Sensitive Information Disclosure — illustrative only):** Model leaking PII, credentials, or system prompt fragments in responses. This skill ships an illustrative scanner: US-format email, SSN, phone, and a starter set of API key shapes (Anthropic `sk-ant-`, OpenAI `sk-`, AWS `AKIA`). Comprehensive data-loss prevention requires dedicated tooling (e.g., Microsoft Presidio, Google Cloud DLP, or `detect-secrets` for credentials) — these regexes are a smoke alarm, not a DLP system.
- For the full OWASP mapping, read `references/owasp-llm-top10-2025.md`

**Note on indirect prompt injection:** Output validation alone cannot catch outputs corrupted by upstream injection (e.g., tool results or RAG retrieval containing injected instructions that the model faithfully echoes). Pair with input-side mitigations from Secure External Ingestion and System Prompt Design to address the root cause.

## Scope — what this skill does NOT cover

This skill covers HTML/markup rendering, JSON schema validation, and pattern-based scans for PII, URLs, and prompt leakage. It does **NOT** provide SQL or shell escaping, and string-escaping is the wrong approach for those contexts. If LLM output will reach SQL or a shell, use the right primitive instead:

- **SQL:** parameterized queries — `cursor.execute(sql, params)`. Never interpolate LLM output into an SQL string, and never rely on escaping functions to "sanitize" it. Use your database driver's parameter binding.
- **Shell:** argument arrays — `subprocess.run([cmd, arg1, arg2])`. Never use `shell=True` with LLM output, and never concatenate LLM output into a shell command string.
- **Code execution (`eval`, `exec`, `Function(...)`):** do not pass LLM output to these. If you need dynamic behavior, design a restricted DSL with an allowlist — not free-form code.

These are not limitations this skill aims to fix — they are the wrong tool for those jobs. The HTML escaping patterns below will give a false sense of safety if applied to SQL or shell contexts.

## Tiered mitigation options

**Present these three levels as a BRIEF picker by default — one line per tier (level name + added cost + the single most important thing it does NOT catch), then an action line. Do NOT read out the full descriptions below by default.** The detailed subsections that follow are reference detail: use them to fill the picker's one-liners and to answer "details" requests, not as a script to recite. See "IMPORTANT — Presentation rules" below for the exact picker format and the verbose opt-in. Each level includes everything from the previous level. Let the user choose — do not silently pick a level.

**BRIEF PICKER — by default, emit exactly this block. Do NOT expand the per-level subsections below unless the developer asks for "details" or has set the verbose preference (see "IMPORTANT — Presentation rules"):**

```
Output Validation and Sanitization — OWASP LLM05/LLM02. Pick a level (each builds on the last):

A) Low — no added cost. JSON schema validation, fail-closed on mismatch, reject unexpected fields.
   Structure only — not content-level attacks.
B) Moderate (recommended) — no added cost. + context-aware HTML/URL/Markdown/CSV escaping + PII/credential scan + prompt-fragment scan.
   Flags known patterns; novel encoding / semantic exfiltration may evade.
C) High — +1 classifier call/req (estimated). + CSP headers + output classifier + sandboxed rendering + review of action-triggering output.
   No single layer is sufficient; classifiers are evadable.

Reply A / B / C to apply · D if you're not sure · "details" (one tier) or "verbose" (all tiers) for the full breakdown.
```

---

### A: Low

- JSON schema validation on all structured LLM responses before downstream use
- Fail closed on schema mismatch (reject the response, don't attempt to fix it)
- Null/empty field checking on required fields

- **Effectiveness:** Reduces risk by rejecting responses that don't match the expected schema — flags structural problems only, not content-level attacks. Only active when a schema is explicitly provided; unstructured prose responses are not validated. When `validate_llm_output` is called without a schema, it now emits a `schema_validation_skipped` warning finding so callers can detect the omission instead of silently passing.
- **Tradeoff:** Flags structural problems only, not content-level attacks

**Depth and strictness caveat.** The bundled `validate_json_schema()` is a Level A starter: it checks top-level required keys, top-level type hints, and (as of v1.0.0) **rejects unexpected top-level fields by default**. So payloads like `{"expected": "foo", "__proto__": {"admin": true}}` or `{"expected": "foo", "extra_data": {...}}` are rejected with `Unexpected top-level field: '__proto__'` errors — this mitigates prototype-pollution / class-pollution attacks where downstream code dereferences attacker-controlled keys. The starter does **not** validate nested structures. For production, use the [`jsonschema`](https://pypi.org/project/jsonschema/) library (Python) or [Zod](https://zod.dev) (TypeScript) and ensure unknown keys are rejected at every nested level: `"additionalProperties": false` on every object in your JSON schema, or `z.object({...}).strict()` on every Zod object schema (NOT `.passthrough()` — that re-opens the pollution gap). Layer both: structural rejection at the boundary, content-level scans from Level B before the value is rendered or stored.

Python example — **Level A starter, top-level only**:
```python
import json

def validate_json_schema(response: str, schema: dict) -> tuple[bool, dict | None, list[str]]:
    """Level A starter — checks top-level required keys only. Does NOT validate
    nested structures and does NOT reject unexpected top-level fields. For
    production, use jsonschema library with additionalProperties: False.
    """
    try:
        data = json.loads(response)
    except json.JSONDecodeError as e:
        return False, None, [f"Invalid JSON: {e}"]
    errors = []
    for key in schema.get("required", []):
        if key not in data or data[key] is None or data[key] == "":
            errors.append(f"Missing or empty required field: {key}")
    return (len(errors) == 0, data if not errors else None, errors)
```

TypeScript example:
```typescript
import { z, ZodSchema } from "zod";

// Use .strict() on every object schema. Without it, Zod silently STRIPS
// unknown keys instead of rejecting them — payloads like
// {"expected": "foo", "__proto__": {...}} parse cleanly but the unknown
// key is dropped from the parsed value, hiding evidence of an injection
// attempt. Pass .strict() so unknown keys raise a ZodError.
const userSchema = z.object({
  name: z.string(),
  age: z.number(),
}).strict();

function validateJsonSchema(response: string, schema: ZodSchema): {
  valid: boolean; data: unknown | null; errors: string[]
} {
  try {
    const data = schema.parse(JSON.parse(response));
    return { valid: true, data, errors: [] };
  } catch (e) {
    return { valid: false, data: null, errors: [String(e)] };
  }
}
```

---

### B: Moderate (recommended)

Everything in Level A, plus:

- **HTML/JS escaping on all LLM output rendered in frontends.** Match the escaping to the rendering context — there is no "context-aware" auto-escaper that just works everywhere:
    - **HTML text nodes:** `html.escape()` (Python), Jinja2's default `|e` filter, or React JSX child interpolation `{value}` are all safe here. Jinja2's auto-escape applies HTML-entity escaping uniformly — safe for text nodes, NOT safe for the contexts below. React JSX child interpolation likewise escapes text content but does not handle URL attributes (see next item).
    - **HTML attribute values:** require attribute-value escaping (also entity-based, but the disallowed character set differs and unquoted attributes need extra care). `html.escape(..., quote=True)` covers quoted attributes.
    - **URL-typed attributes (`href`, `src`, `action`, `formaction`, `xlink:href`):** entity escaping is NOT enough — validate the URL scheme against an allowlist (`https:`, `http:`, `mailto:`, plus whatever else your app actually needs) and reject the rest. `<a href={userContent}>` with `userContent = "javascript:alert(1)"` is live XSS in React, Vue, Angular, and Svelte alike — auto-escaping handles text, not URL schemes.
    - **JavaScript string literals:** require JS string escaping (different rules; e.g. backslash and `</script>` handling). Do not interpolate model output into `<script>` blocks at all if avoidable.
    - **CSS values, URL path components, and `style` attributes:** require CSS escaping and URL percent-encoding respectively.
    - **Bottom line:** never render raw model output as HTML, and never assume one escaping function "covers" all contexts. The `escape_html_text_node()` helper in the template is safe for HTML text nodes only.

  **URL attributes specifically.** React JSX auto-escapes text content, but it does **not** sanitize URL-typed attributes. `<a href={userContent}>` with `userContent = "javascript:alert(1)"` is live XSS — the `javascript:` scheme executes on click. Before assigning LLM output to `href`, `src`, `action`, `formaction`, `xlink:href`, or any other URL attribute, validate the scheme against an allowlist (`https:`, `http:`, `mailto:`, and whatever else your app actually needs) and reject the rest. Same rule in Vue, Angular, and Svelte — auto-escaping handles text, not URL schemes.
- **Markdown rendering:** If you render LLM output as Markdown, standard Markdown allows links and images with arbitrary URI schemes — `[click](javascript:alert(1))` and `![x](javascript:alert(1))` execute on click or render. Strip dangerous URI schemes before rendering: use a sanitizing renderer like [DOMPurify](https://github.com/cure53/DOMPurify) on the rendered HTML, or a Markdown parser with an explicit URI scheme allowlist (e.g., `marked` + a custom link filter; `markdown-it` with `validate`). Raw-HTML blocks in Markdown also need HTML escaping applied downstream.
- **CSV / spreadsheet output:** When LLM output is written to CSV, TSV, or any file Excel / Google Sheets / LibreOffice can open, a value starting with `=`, `+`, `-`, or `@` executes as a formula on open — this is [formula injection / CSV injection](https://owasp.org/www-community/attacks/CSV_Injection). Before writing LLM-sourced values into CSV, prefix any cell starting with those characters with a single-quote escape (`"'=..."`, `"'+..."`, etc.) or reject the row. Same defense in any export path that ends in a spreadsheet.
- **URL detection in rendered output:** Scan for URLs and warn before rendering as clickable links. Note: the template's `scan_for_urls` function detects URLs but does not block them — callers must check warnings and decide whether to render.
- **PII/credential scanning in output before it reaches the user:** Email addresses, API key patterns, SSN patterns, phone numbers
- **System prompt fragment detection:** Check if output contains strings that match known system prompt patterns. **Caveat:** This detects cooperative/accidental disclosure only (e.g., "my instructions are..."). A successfully injected model follows instructions silently without self-disclosure — a clean scan result does not indicate safety.

- **Effectiveness:** Flags known dangerous patterns (XSS, PII, URLs) via regex and escaping — novel encoding, semantic exfiltration, and polyglot payloads may evade detection
- **Evidence:** OWASP LLM05 recommended controls, standard web security XSS prevention practices
- **Known bypasses:** Novel encoding in output, semantic exfiltration that doesn't match patterns, polyglot payloads
- **Inherent limitations (will not be fixed — see SCOPE.md):** PII and prompt leakage detection is keyword/regex-based — paraphrasing, encoding, or obfuscation trivially bypasses it. Output validation alone cannot detect outputs corrupted by upstream indirect injection. Schema validation confirms structure, not semantic safety — validated values remain untrusted data.
- **Requires layering with:** Input sanitization (Skill 1), system prompt design (Skill 4), Content Security Policy headers (Level C)

**Tradeoff:** Moderate complexity, good coverage for most applications. Flags known dangerous patterns and common leakage; novel attack patterns may evade detection.

**Escaping parsed field values.** `validate_llm_output()` returns a `sanitized` string that is the entire raw response with HTML text-node escaping applied. That is only useful when you render the response as a single text block. Callers that follow the schema path (`validate_json_schema` → use `data["field"]`) get **unescaped** field values back — the previous version of the template silently disconnected these two code paths, which meant a payload like `{"summary": "Safe text</script><script>alert(1)//"}` passed every check and the `<script>` tag survived intact when the caller interpolated `data["summary"]` into HTML. The template now ships an `escape_json_field_values(data)` helper that walks the parsed structure and HTML-text-node escapes every string value:

```python
from output_schema_validator import (
    validate_json_schema, escape_json_field_values, escape_html_text_node,
)

ok, data, errors = validate_json_schema(response, schema)
if not ok:
    fail_closed(errors)

# Escape BEFORE interpolating into HTML; escape only what you'll render,
# not values consumed by code (e.g. id lookups, numeric comparisons).
safe_for_html = escape_json_field_values(data)
return template.render(user=safe_for_html)
```

This is HTML-text-node escaping only — for attribute, JS, CSS, or URL contexts, see the rendering-context list above and apply the right escape per sink.


Python example — fail-closed pipeline (matches `templates/python/output_schema_validator.py`):
```python
# Scan functions return list[Finding] — structured dicts shaped as
# {"type": str, "severity": "critical"|"warning", "match": str, "message": str}.
# Fail closed on any critical finding; match on "type" (stable ID), not
# on message text (message wording can change without notice).
def validate_llm_output(response: str, schema: dict | None = None) -> tuple[bool, str, list[dict]]:
    """Validate LLM output: schema check, scan for PII/URLs, fail closed on critical,
    then sanitize HTML for rendering. Returns (ok, sanitized_or_empty, findings)."""
    if schema:
        ok, _data, errors = validate_json_schema(response, schema)
        if not ok:
            return False, "", [{"type": "schema_error", "severity": "critical",
                                "match": "", "message": e} for e in errors]
    findings: list[dict] = []
    findings.extend(scan_for_pii(response))
    findings.extend(scan_for_urls(response))
    if any(f["severity"] == "critical" for f in findings):
        return False, "", findings  # fail closed; don't render
    sanitized = escape_html_text_node(response)
    return True, sanitized, findings
```

Consuming findings:
```python
# Fail closed on any critical finding:
if any(f["severity"] == "critical" for f in findings):
    block_response()

# Or filter by specific type (stable IDs — match on "type", not message text):
if any(f["type"] == "pii_ssn" for f in findings):
    redact_and_log()
```

**Findings are detections, not verdicts.** Severity reflects a default policy the template ships with — `critical` (PII, prompt leakage, `javascript:`/`data:` URLs) fails closed in `validate_llm_output`; `warning` (plain http/https URLs) passes through. Review whether the defaults match your app: a customer support bot may legitimately return user emails, so demote `pii_email` to `warning` there; a public Q&A bot should probably keep it `critical`. Credentials (`api_key_*`) are almost always real leaks — keep those blocking.

TypeScript example:
```typescript
function validateLlmOutput(response: string, schema?: ZodSchema): {
  valid: boolean; sanitized: string; warnings: string[]
} {
  if (schema) {
    try {
      schema.parse(JSON.parse(response));
    } catch (e) {
      return { valid: false, sanitized: '', warnings: [String(e)] };
    }
  }
  const warnings = [...scanForPii(response), ...scanForUrls(response)];
  const sanitized = escapeHtml(response);
  return { valid: true, sanitized, warnings };
}
```

See `templates/python/output_schema_validator.py` for a complete Level B (Moderate) implementation.

---

### C: High

Everything in Level B (Moderate), plus:

- **Content Security Policy headers** for any page rendering LLM output
- **Output classifier checking** for injection success indicators (unexpected tool calls, data exfiltration attempts, content that shouldn't appear in the response)
- **Sandboxed rendering environment** for LLM-generated content (iframe sandbox, shadow DOM)
- **Separate output review** for any LLM output that triggers actions (emails sent, database writes, API calls)

- **Effectiveness:** Reduces risk across multiple validation layers (CSP, classifier, sandboxing, action review) — no single layer is sufficient alone
- **Tradeoff:** Significant infrastructure complexity, recommended for high-stakes applications

- **Cost:** +1 LLM call per request for classifier. Calculate approximate per-request cost based on the developer's expected content size and current Claude model pricing. Show a concrete estimate with "(estimated)" after the number. Always add: "Your actual cost depends on content size, provider pricing, etc."
- **Latency:** +1 round-trip to classifier model (estimated). Estimate based on the developer's chosen model — faster models like Haiku add less latency than Sonnet. Always add: "Latency varies by model and content size."
  - For current per-token pricing, refer to https://docs.anthropic.com/en/docs/about-claude/models — costs vary by model choice and content size. This is an estimate only; your actual costs may vary.

---

**IMPORTANT — Presentation rules:**

1. Present options as plain text, NOT as tables. Tables are hard to read in a terminal.

2. **Default to a BRIEF picker — do not dump all three full tier descriptions.** This is the default for every skill, every time, including the first skill in a session. Format the picker as: a one-line header naming the skill and its OWASP IDs, then exactly ONE line per tier, then a single action line. Each tier line carries three things and nothing more — (a) the letter + level name, with the recommended tier marked; (b) the tier's added cost (see rule 3); (c) the single most important thing that tier still does NOT catch (the "misses" clause). The "misses" clause is REQUIRED on every tier and must never be dropped, however terse the picker — it is what keeps the brief presentation honest. Hold all supporting detail (full control list, Effectiveness, Evidence, Known bypasses, Requires-layering, Inherent limitations, and the full Cost/Latency breakdown) for "details" (rule 4). Shape to follow, filled with this skill's real tiers:

```
<Skill name> — OWASP <IDs>. Pick a level (each builds on the last):

A) Low — <added cost>. <what it adds, one line>. Misses <key gap>.
B) Moderate (recommended) — <added cost>. <what it adds>. <key gap remains>.
C) High — <added cost>. <what it adds>. <key gap remains>.

Reply A / B / C to apply · D if you're not sure · "details" (one tier) or "verbose" (all tiers) for the full breakdown.
```

3. **Added-cost column.** Each tier line states the added cost of that tier's security controls — the cost of turning this level on — NOT the base cost of the LLM call itself. For a tier that adds no LLM call and no material token overhead, write "no added cost." For a tier that adds an LLM call, summarize briefly (e.g. "+1 classifier call/req (estimated)"); for a tier that only adds tokens or wrapping, say so briefly. Draw the specifics from the "Cost:" / "Latency:" lines in the tier sections above. Any figure shown in the brief line MUST carry "(estimated)"; the full figure and the pricing caveat ("Your actual cost depends on content size, provider pricing, etc.") belong in details, not in the brief line.

4. **Details on demand — per tier, never a wall.** If the developer asks for "details," expand only the recommended tier's full breakdown and note that naming a tier ("details A", "details C") expands the others. If they name a tier, expand just that one. Show all three full breakdowns at once only if the developer explicitly asks for all of them, or has the verbose preference set (rule 6). When you expand a tier that has "Cost:" / "Latency:" lines (Level C), those lines are REQUIRED in the detail view.

5. When multiple skills trigger at once, present each skill's brief picker ONE AT A TIME. Wait for the developer's answer before presenting the next skill's options. Do not batch them.

6. **Verbose preference (opt-in).** The default is brief (rules 2–4). If the developer has set a verbose preference — a line such as `llm-secure-patterns: verbose` in their project or user instructions (for example in CLAUDE.md), or a request earlier in this session to always show full detail — then skip the brief picker and show the full detail for all three tiers instead. Explicit user preference always beats this default. Typing `verbose` at the picker is the one-time form — render the full detail for all three tiers now, without changing any persistent setting (it is `details` applied to every tier at once).

**The brief picker's action line (rule 2) already asks which level to apply — do not add a separate "which level?" prompt, and do not append any sentence restating or re-asking the options after the picker. The action line is the last thing in the message.**

**If the developer picks D**, ask these diagnostic questions one at a time. Preface with: "Pick one per question. If multiple apply, pick the highest-risk answer — it's safer to over-protect than under-protect."

1. Who will be calling this?
   - A) Internal users only
   - B) Authenticated customers
   - C) Public internet

2. What happens if this is compromised?
   - A) Read-only data exposure (no PII)
   - B) PII exposure, or can modify records / send messages
   - C) Can spend money, delete data, or access financial records

3. What is your risk tolerance?
   - A) Move fast with basic coverage
   - B) Balanced — solid coverage without over-engineering
   - C) Invest in strongest available defenses

Then recommend a level based on their answers (mostly A's → Low, mostly B's → Moderate, mostly C's → High) and explain why.

## `# SECURITY:` comment instruction

When you apply any mitigation pattern from this skill, follow the annotation format in `references/annotation-format.md`. Use these skill-specific values:

- **OWASP ID:** `LLM05 (Improper Output Handling)`
- **Pattern:** `output_schema_validator`
- **Applied by:** `llm-secure-patterns v1.0.0 / Output Validation and Sanitization`

## What this skill does NOT cover (additional security layers suggested)

- **Input sanitization before content reaches the model** — see Secure External Ingestion
- **System prompt design that reduces leakage** — see System Prompt Design
- **Endpoint-level output controls** — see LLM Endpoint Hardening
- **Inter-agent output validation** — see Agent Action Surface Control

**Additional Security Gaps Identified**

Surface this as ONE line — the adjacent surfaces from the list above, then the choice inline. No preamble about attack surface or OWASP:

> Adjacent surfaces not covered (defense in depth): <surfaces from the list above>. A) Address now · B) Add to backlog (TODO: SECURITY) · C) Skip.

After the developer chooses, always end with: "Run `/llm-secure-patterns:report` for full OWASP LLM Top 10 coverage and gaps."


## False solutions warning

- **Do NOT** trust model output because "the system prompt says to only return safe content" — the model is an untrusted data source, exactly like user input in traditional web security (see `references/false-solution-patterns.md` Pattern 1)
- **Do NOT** assume JSON output is safe because it's structured — the values within the JSON can still contain malicious content

## Existing codebase handling

When this skill triggers on existing code that already handles LLM output:

1. Review the existing implementation against the patterns above
2. Annotate existing mitigations with `# SECURITY:` tags at the appropriate level
3. Flag gaps — for each gap, present the A/B/C/D tier choices and wait for the developer to choose before applying. Do not pick a level automatically.
4. If no mitigations exist, present the full A/B/C/D tier choices as if building new code — wait for the developer to choose before applying.

After completing the review and applying any changes, always end with: "Run `/llm-secure-patterns:report` for full OWASP LLM Top 10 coverage and gaps."

## Before completing this skill

Treat this as a hard checklist. The skill is not done until all of these items are satisfied:

**Emit the completion as ONE block — ≤ one screen, no control-by-control essay, no parentheticals.** Shape:

> Applied **<tier>** to <surface> — <controls as a short comma list>. Files: <list>. All `# SECURITY:` annotated. Deferred: <one key gap, or "none">.
>
> Adjacent surfaces not covered (defense in depth): <surfaces from "What this skill does NOT cover" above>. A) Address now · B) Add to backlog (TODO: SECURITY) · C) Skip.
>
> Run `/llm-secure-patterns:report` for full OWASP LLM Top 10 coverage and gaps.

- [ ] **Annotations written.** Every applied mitigation has a `# SECURITY:` / `// SECURITY:` comment in the code (OWASP ID, level, pattern, applied-by, date — see `references/annotation-format.md`).
- [ ] **Gap disposition stated.** The developer knows which gaps were skipped (option C) or deferred (option B), and what file marker they should look for if deferred.
- [ ] **Report-mention surfaced.** End the pass with this exact line:
  > Run `/llm-secure-patterns:report` for full OWASP LLM Top 10 coverage and gaps.

The last item is non-optional. It is the safety net for adjacent LLM surfaces (ingestion, output rendering, system prompt design, agent action wiring) where this skill does not fire. Skipping the report-mention strands the developer without the means to discover gaps the model missed.
