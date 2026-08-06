# Security Policy

## Reporting a Vulnerability

If you discover a security issue in `llm-secure-patterns` — whether in the plugin's own hooks and skills, in a recommended pattern that turns out to be bypassable in a way not already documented, or in a template — please report it privately rather than opening a public issue.

**Preferred channel:** [GitHub Private Vulnerability Reporting](https://github.com/wildblue-ai/llm-secure-patterns/security/advisories/new) for this repository.

**Alternative:** Email support@wildblue.ai with the subject line `[SECURITY] llm-secure-patterns`. Please include:

- The affected skill, hook, or template (file path if known)
- A description of the issue and its impact
- Reproduction steps or a proof-of-concept, if available
- Whether the issue is a flaw in the plugin itself or an undocumented bypass of a recommended pattern

## Response Commitment

- **Acknowledgment:** within 3 business days
- **Initial assessment:** within 10 business days
- **Fix or documented mitigation:** timeline shared in the assessment; documented bypasses are added to the relevant skill's "Known bypasses" section even when a full fix isn't possible

## Scope Notes

This project ships **security guidance, not security guarantees** (see [SCOPE.md](SCOPE.md)). A pattern failing to catch an attack it explicitly lists under "Known bypasses" is expected behavior, not a vulnerability. An undocumented bypass of a HIGH-confidence pattern, however, is exactly what we want reported — it will be triaged, documented, and credited.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.9.x (pre-release) | ✅ Current |
| < 0.9 | ❌ |

## Credit

Reporters of valid issues are credited in [CHANGELOG.md](CHANGELOG.md) unless they request otherwise.
