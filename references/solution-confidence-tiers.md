# Solution Confidence Tiers

This document defines the source hierarchy and confidence tagging framework used by all 5 skills in the llm-secure-patterns plugin. Every mitigation recommended by this plugin carries a confidence tag — no exceptions.

## Confidence Levels

### HIGH

The mitigation architecturally eliminates the risk. No known bypasses in the current threat landscape. The defense operates at a structural level — the vulnerable condition cannot exist when the mitigation is correctly applied.

**Example:** Storing credentials in a secrets manager instead of the system prompt. Either the credential is present in the prompt text or it is not. There is no encoding trick, semantic attack, or multi-step chain that can extract a credential that was never included.

**Criteria for HIGH rating:**
- The mitigation removes the precondition for the attack, rather than detecting or filtering the attack itself
- No published bypasses exist in peer-reviewed literature, OWASP advisories, or responsible disclosures
- The defense does not depend on model behavior — it operates at the architectural layer

### MODERATE

The mitigation significantly reduces risk but has known bypasses or limitations. The defense raises the cost and complexity of a successful attack but does not eliminate the attack surface.

Most LLM security mitigations fall here. This is honest, not defeatist.

**Example:** Input sanitization with encoding normalization — catches naive injection and common encoding tricks (Base64, ROT13, Unicode homoglyphs), but sophisticated semantic attacks that express malicious intent through natural language paraphrasing can bypass it.

**Criteria for MODERATE rating:**
- The mitigation blocks a documented class of attacks with evidence (red-team results, CVE references, or peer-reviewed research)
- At least one known bypass category exists and is documented
- The defense benefits meaningfully from layering with other MODERATE mitigations

### LOW

The mitigation provides some defense but is easily bypassed or addresses only a narrow attack vector. Better than nothing, but creates dangerous false confidence if relied upon alone.

**Example:** Basic HTML tag stripping without encoding normalization — trivially bypassed by Base64-encoded payloads, Unicode homoglyph substitution, zero-width character insertion, or whitespace manipulation.

**Criteria for LOW rating:**
- The mitigation blocks only the most naive form of an attack
- Multiple well-documented bypass techniques exist
- Relying on this mitigation alone would be worse than having no mitigation, because it creates a false sense of security

## Source Hierarchy

Solutions recommended by this plugin must be backed by evidence from the following hierarchy. Higher tiers carry more weight; lower tiers require explicit caveats.

### Tier 1 — Include

Primary authoritative sources. Mitigations backed by Tier 1 evidence can be recommended with high confidence.

- **OWASP GenAI Project** — Top 10 for LLM Applications, Cheat Sheet Series, and associated guidance
- **NIST AI RMF** — AI Risk Management Framework and supplementary publications
- **Peer-reviewed papers** with reproducible results and published methodology
- **Major AI lab research** — Anthropic, OpenAI, Google DeepMind research blogs and technical reports with disclosed methodology

### Tier 2 — Include with Citation

Strong supporting evidence. Mitigations backed by Tier 2 evidence should include the specific citation so practitioners can evaluate the evidence themselves.

- **CVEs** — Published Common Vulnerabilities and Exposures with technical detail
- **Responsible disclosures** with proof-of-concept demonstrations
- **Incident postmortems** with technical detail (not just "we were breached")

### Tier 3 — Include Cautiously

Useful but requires caveats about the evidence quality.

- **Community-tested open-source tools** with published red-team results
- **Conference talks** with demonstrated exploits (DEF CON AI Village, Black Hat, etc.)
- **Bug bounty reports** with sufficient technical detail to reproduce

### Disqualified — Do Not Use as Evidence

The following sources are explicitly excluded from this plugin's evidence base:

- **Vendor blogs selling their own product as the fix** — Conflict of interest disqualifies the evidence regardless of technical quality
- **Posts with no testing methodology** — Claims without reproducible evidence are not evidence
- **AI-generated security advice without human verification** — Circular reasoning; LLMs advising on LLM security without expert review is not a valid source
- **Marketing whitepapers** framed as research but authored by product teams

## Tag Format

Every mitigation pattern in every skill uses this exact format:

```
- **Effectiveness:** HIGH | MODERATE | LOW
- **Evidence:** [Source — OWASP ref, research paper, CVE, or red-team result]
- **Known bypasses:** [What this doesn't catch]
- **Requires layering with:** [Other patterns needed for defense-in-depth]
```

All four fields are mandatory. If a field does not apply (e.g., no known bypasses for a HIGH-rated mitigation), state that explicitly rather than omitting the field.

**Example — MODERATE-rated mitigation:**

```
- **Effectiveness:** MODERATE
- **Evidence:** OWASP Top 10 for LLM Applications (LLM01: Prompt Injection); Simon Willison's prompt injection research (2022-2024)
- **Known bypasses:** Semantic injection via natural language paraphrasing; multi-step chains that build context across turns; translation-based attacks
- **Requires layering with:** Untrusted content delimiters, output validation, action surface restriction
```

**Example — HIGH-rated mitigation:**

```
- **Effectiveness:** HIGH
- **Evidence:** OWASP Top 10 for LLM Applications (LLM01: Prompt Injection) — architectural elimination of credential exposure
- **Known bypasses:** None — the credential is never present in the model's context
- **Requires layering with:** Access control on the secrets manager itself; rotation policies
```

## Important Notes

1. **Confidence ratings reflect the state of the art, not a guarantee.** A HIGH rating means no known bypasses exist today. The threat landscape evolves — ratings must be revisited as new attack research emerges.

2. **Most LLM security mitigations are MODERATE.** This is an honest assessment of the current state of LLM security, not a deficiency of this framework. The field is young; architectural eliminations are rare.

3. **MODERATE + MODERATE + MODERATE across multiple layers is stronger than any single HIGH.** Defense in depth works because each layer forces the attacker to solve a different problem. Three independent MODERATE mitigations covering input, processing, and output stages create compounding difficulty for attackers.

4. **A mitigation rated MODERATE with known bypasses documented is more valuable than one rated HIGH without evidence.** Transparency about limitations enables informed risk decisions. A HIGH rating with no supporting evidence is a red flag, not a green light.

5. **Ratings are specific to implementation context.** The same technique (e.g., input validation) can be MODERATE when implemented with encoding normalization and LOW without it. Skills must specify the implementation requirements that justify the rating.
