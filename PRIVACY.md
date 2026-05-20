# Privacy Policy — llm-secure-patterns

**Effective date:** 2026-05-20
**Plugin:** llm-secure-patterns
**Owner:** WildBlue Enterprises LLC
**Contact:** hello@wildblue.ai

## Scope

This privacy policy covers `llm-secure-patterns`, a Claude Code plugin published by WildBlue Enterprises LLC. It does NOT cover Claude Code itself or the Anthropic API — those have their own terms of service and privacy policies. See [Anthropic's Privacy Policy](https://www.anthropic.com/legal/privacy) for how the Claude API and Claude Code handle data.

## What the plugin does with user data

**The plugin does not collect, store, or transmit any user data.**

All operations happen locally on the user's machine:

- **Reading project code** — to detect security-relevant patterns and apply mitigations
- **Writing `# SECURITY:` annotations** — added inline to the user's source files
- **Generating reports** — `SECURITY_POSTURE.md` and `DEVELOPER_RECOMMENDATIONS.md` written to the project root
- **Reading `THREAT_BULLETIN.md`** — the SessionStart hook checks for security advisories in this local file

## What the plugin does NOT do

- No analytics
- No telemetry
- No phone-home behavior
- No user identification or tracking
- No transmission of code, annotations, or reports to any external service
- No third-party integrations beyond what the user has already configured in their own Claude Code environment

## Relationship to Claude Code and the Anthropic API

The plugin influences how Claude behaves within an existing Claude Code session. The user's normal Claude Code interactions — including their conversation, the code Claude reads, and the responses Claude generates — are processed by Claude Code and may be sent to Anthropic's API for inference. **That data flow is governed by Anthropic's privacy policy and Claude Code's terms of service, not by this plugin.**

## Open source verification

This plugin is distributed under the MIT License. The full source code is publicly available at [github.com/wildblue-ai/llm-secure-patterns](https://github.com/wildblue-ai/llm-secure-patterns). Anyone can verify the claims in this policy by reading the source — there are no hidden network calls, no obfuscated scripts, and no opaque binaries.

## Contact

Privacy questions or concerns: hello@wildblue.ai

## Changes to this policy

If the plugin's data-handling behavior changes in a future version, this policy will be updated in the repository and noted in the CHANGELOG.
