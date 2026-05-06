# Threat Intelligence Sources and Verification Methodology

Trusted sources and verification procedures for LLM security threat intelligence. This document governs what sources are eligible for citation in `THREAT_BULLETIN.md` and how claims are verified before publication.

---

## Source Tiers

### Tier 1 — Authoritative

These sources have established credibility through rigorous methodology, peer review, or institutional accountability. Cite directly without additional corroboration (though corroboration is always preferred).

- **OWASP GenAI Project** — [genai.owasp.org](https://genai.owasp.org) — Community-driven, peer-reviewed threat taxonomy and mitigation guidance for generative AI applications
- **NIST AI Risk Management Framework** — [nist.gov/artificial-intelligence](https://www.nist.gov/artificial-intelligence) — Federal standards body; AI RMF provides structured risk assessment methodology
- **Peer-reviewed papers with reproducible results** — Published in recognized venues (IEEE S&P, USENIX Security, ACM CCS, NeurIPS, ICML) with code, data, or detailed methodology sufficient for independent reproduction
- **Anthropic research blog** — [anthropic.com/research](https://www.anthropic.com/research) — Primary research from a frontier lab with direct access to model internals
- **OpenAI research** — Published research and system cards from a frontier lab
- **Google DeepMind security research** — Published research on adversarial robustness, alignment, and model safety

### Tier 2 — Credible with Citation

These sources have demonstrated reliability but require explicit citation and, when possible, corroboration from a second source.

- **CVEs from NVD** — [nvd.nist.gov](https://nvd.nist.gov) — Standardized vulnerability identifiers with severity scoring; verify the CVE is confirmed (not disputed or rejected)
- **Responsible disclosures with PoCs** — Vulnerabilities reported through coordinated disclosure with a working proof-of-concept
- **Incident postmortems with technical detail** — Published by the affected organization or a credible third party, containing root cause analysis and timeline
- **Lakera blog and research** — [lakera.ai](https://www.lakera.ai) — Focused LLM security research with published testing methodology
- **Palo Alto Unit 42** — [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com) — Threat intelligence with detailed technical analysis and IOCs
- **CrowdStrike threat research** — Published adversary tracking and campaign analysis with attributed threat actors

### Tier 3 — Use Cautiously

These sources can inform threat awareness but should not be the sole basis for advisories. Cross-reference with Tier 1 or Tier 2 sources before citing.

- **Community-tested open-source tools** — Red-team frameworks and testing tools with published results, documented methodology, and community validation (e.g., garak, PyRIT)
- **Conference presentations** — DEF CON AI Village, Black Hat, IEEE workshops — but only when accompanied by a paper, technical report, or working proof-of-concept; slides alone are insufficient

### Disqualified Sources

Do not cite these in threat bulletins or advisories. If a claim originates exclusively from disqualified sources, it does not meet the publication threshold.

- **Vendor blogs selling their own product as the fix** — Inherent conflict of interest; the incentive is to amplify the threat to drive sales
- **Posts with no testing methodology** — Claims without described reproduction steps, test environment, or measurable results
- **AI-generated security advice without human verification** — LLM-generated content that has not been reviewed and validated by a named human expert
- **"Researchers found" articles with no named researchers or paper link** — Unattributable claims that cannot be traced to a primary source

---

## Verification Checklist

Use this checklist before publishing any advisory to `THREAT_BULLETIN.md`. All items must be evaluated; a "no" on any item requires documented justification for proceeding.

- [ ] Does the threat have a CVE number or reproducible proof-of-concept?
- [ ] Is it reported by 2+ independent sources?
- [ ] Are named researchers or organizations attached?
- [ ] Does the technical detail match the claimed impact?
- [ ] Is the source selling a fix for the problem they are describing?
- [ ] Have you verified the proposed solution is not snake oil? (Cross-reference with [`false-solution-patterns.md`](./false-solution-patterns.md))

---

## Red Flags for False Threats

The following patterns indicate a reported threat may be exaggerated, fabricated, or misunderstood. Any of these should trigger additional scrutiny before publication.

- **No CVE or PoC** — The threat is described in general terms with no concrete vulnerability identifier or demonstration
- **Single-vendor sourcing** — Only one organization reports the threat, especially if that organization sells mitigation for it
- **No named researchers** — The discovery is attributed vaguely ("security researchers," "experts") with no individuals or institutions identified
- **Breathless framing with no technical detail** — Urgent language ("critical," "devastating," "unprecedented") without corresponding technical specifics
- **"Researchers found" with no link to paper or disclosure** — A secondary report cites unnamed primary research that cannot be located

---

## Red Flags for False Solutions

The following patterns indicate a proposed mitigation may be ineffective or misleading. Cross-reference with [`false-solution-patterns.md`](./false-solution-patterns.md) for detailed analysis.

- **Claims to "solve" or "prevent" prompt injection** — Prompt injection is an unsolved problem; any claim of full prevention is a red flag
- **No published bypass testing or red-team results** — A defense that has not been adversarially tested has unknown effectiveness
- **Relies entirely on model behavior rather than architectural controls** — Telling the model to "refuse malicious requests" is not a security control
- **Single-layer defense presented as sufficient** — Any mitigation that does not acknowledge the need for defense-in-depth
- **Confuses detection with prevention** — Detecting an attack after it occurs is valuable but is not the same as preventing it; solutions that conflate the two are misleading
