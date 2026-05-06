# `# SECURITY:` Annotation Format

When applying any mitigation pattern from a skill, add a structured comment at the top-level mitigation point (e.g., the sanitization function, not every line inside it) using this format:

## Python / Shell / YAML

```python
# SECURITY: LLM01 (Prompt Injection) — [specific mitigation applied]
# OWASP: Top 10 for LLM Applications 2025 (v2025.1, published November 2025)
# Confidence: [HIGH|MODERATE|LOW] — [brief reason]
# Level: [Low|Moderate|High]
# Declined: [stronger option not selected] — [brief reason]
# Pattern: [template/pattern name]
# Requires layering: [what else is needed]
# Applied by: llm-secure-patterns v0.9.0 / [Skill Name]
# Date applied: [YYYY-MM-DD]
```

## TypeScript / JavaScript / Go / Java

```typescript
// SECURITY: LLM01 (Prompt Injection) — [specific mitigation applied]
// OWASP: Top 10 for LLM Applications 2025 (v2025.1, published November 2025)
// Confidence: [HIGH|MODERATE|LOW] — [brief reason]
// Level: [Low|Moderate|High]
// Declined: [stronger option not selected] — [brief reason]
// Pattern: [template/pattern name]
// Requires layering: [what else is needed]
// Applied by: llm-secure-patterns v0.9.0 / [Skill Name]
// Date applied: [YYYY-MM-DD]
```

## Field Rules

- **SECURITY:** `<OWASP ID> (<Name>) — <what was done>`
- **OWASP:** which publication version the pattern is based on
- **Confidence:** HIGH | MODERATE | LOW — with a brief "why"
- **Level:** which tier was chosen (Low, Moderate, High)
- **Declined:** stronger option(s) not selected, with brief reason. **Omit this line if the highest level was chosen.**
- **Pattern:** which template or pattern was applied
- **Requires layering:** what else is needed for defense in depth. **Omit if confidence is HIGH.**
- **Applied by:** plugin version + skill name
- **Date applied:** when this annotation was written

## Conventions

- **Language-agnostic:** Use `#` for Python/Shell/YAML, `//` for JS/TS/Go/Java. The report command greps for `SECURITY:` regardless of comment syntax.
- **Top-level only:** Annotate the top-level mitigation point, not every line inside it.
- **User-approved:** All annotations are part of the code shown to the user for approval. No surprise changes.
