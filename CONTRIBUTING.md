# Contributing to llm-secure-patterns

Thank you for your interest in improving LLM application security.

## How to Contribute

### Reporting security concerns
- Open a GitHub Issue describing the threat, including CVE or PoC if available
- The maintainer will verify and publish advisories — see Threat Bulletin Governance below

### Submitting pattern improvements
- Open a PR with changes to SKILL.md files or Python templates
- Include evidence for any new pattern (OWASP reference, research paper, CVE, or red-team result)
- Every pattern must include a confidence/limitation tag (HIGH/MODERATE/LOW)
- Use liability-safe language: "mitigates" not "prevents," "guidance" not "protection"

### TypeScript templates (welcome!)
- Python templates exist in `templates/python/`. TypeScript equivalents are a welcome first PR.
- Follow the same structure: standalone, runnable, type-annotated, with confidence tags in comments
- See existing Python templates for the pattern

## Threat Bulletin Governance

- `THREAT_BULLETIN.md` and `WATCHING.md` are maintained by the project maintainer only
- Community members submit concerns via GitHub Issues, not PRs to the bulletin
- All advisories are verified against the checklist in `references/threat-intel-sources.md` before publication
- This is a security project — the review process is the product

## What NOT to Submit

- Patterns that claim to "prevent" or "solve" prompt injection (nothing does — see `references/false-solution-patterns.md`)
- Vendor-specific product recommendations without independent evidence
- AI-generated security advice without human verification

## Code of Conduct

Be constructive. Security is a collaborative discipline.
