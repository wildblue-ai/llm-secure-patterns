# Scope & Limitations

## Intended Audience

This plugin is intended for software developers building LLM-powered applications who want to apply defense-in-depth mitigations at code-time. It is **NOT** a substitute for a full security program, such as:

- Penetration testing or offensive security assessment
- Formal threat modeling of a specific system
- Security audit or code review by qualified professionals
- Compliance certification (SOC 2, HIPAA, GDPR, etc.)
- Incident response or vulnerability management programs

Applications handling regulated data, safety-critical workloads, or high-value targets require engagement-based assessment in addition to the patterns in this plugin.

## What This Plugin Covers

This plugin provides development guidance for building secure LLM-powered applications, mapped to the [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/) (published November 2025).

### Skills included:
1. **Secure External Ingestion** — Mitigates risks when fetching URLs, scraping pages, calling external APIs, or building RAG pipelines (LLM01, LLM10)
2. **LLM Endpoint Hardening** — Mitigates risks when building web routes that forward user input to LLM APIs (LLM01, LLM10)
3. **Output Validation & Sanitization** — Mitigates risks when rendering, storing, or forwarding LLM responses (LLM05, LLM02)
4. **System Prompt Design** — Mitigates risks in system prompt authoring (LLM07, LLM01)
5. **Agent Action Surface Control** — Mitigates risks when wiring up tool_use, MCP, or multi-agent pipelines (LLM06, LLM01)

## What This Plugin Does NOT Cover

- **General application security** (SQL injection, CSRF, infrastructure hardening) — see [OWASP Top 10](https://owasp.org/www-project-top-10/) and plugins like [`security-guidance`](https://claude.com/plugins/security-guidance) (pre-tool hook covering command injection, XSS, `eval`, `pickle`, `os.system`) and `agamm/claude-code-owasp`
- **Runtime protection of Claude Code sessions** — see `lasso-security/claude-hooks`
- **Penetration testing or offensive security**
- **Compliance certification** (SOC 2, HIPAA, GDPR) — this plugin does not constitute compliance
- **Supply chain vulnerabilities** (OWASP LLM03) — risks from third-party models, training data, and dependencies. Requires organizational controls, not development-time guidance.
- **Data and model poisoning** (OWASP LLM04) — tampering with training data or model weights. Requires model-level controls outside the scope of application development.
- **Vector and embedding weaknesses** (OWASP LLM08) — vulnerabilities in vector databases and embedding pipelines. Planned for future coverage.

## Known Limitations Identified by Adversarial Review

The following threat categories were identified during cross-model adversarial review (Claude, GPT, Gemini — see `docs/adversarial-review/AUDIT_LOG.md`) and are documented here as out of scope for this plugin. They represent real risks but require controls outside of code-time development guidance.

### HTTP/Network-layer attacks (SSRF, header injection, redirect-based attacks)
Fetch-layer security — validating redirect targets, blocking internal IP ranges (169.254.169.254), and preventing header injection — is a pre-ingestion concern handled by HTTP client libraries and infrastructure controls, not by content sanitization at the application layer.

### Image-based / OCR injection
Image-to-text pipelines (OCR, vision models) can carry injection payloads in visual content. This is a specialized input modality not covered by the text-focused sanitization templates. Sanitize OCR output through the same patterns used for any external text.

### ASCII-art, leetspeak, and visual encoding bypasses
Instructions encoded visually (spaced-out text, leetspeak, ASCII art) pass all text-level filters. These are semantic/visual attacks that cannot be reliably detected with regex or character-level sanitization. Mitigation requires model-level defenses or classifier-based detection (Level C patterns).

### Polyglot / multi-encoding chains
Nested encodings (Base64 of ROT13 of homoglyph-substituted text) are not iteratively decoded by the sanitization pipeline. Fully solving nested encodings is an open research problem. The pipeline decodes one layer; additional layers may survive.

### Timing side-channels on validation/classification
Variable response latency from validation or classification steps can leak information about content (e.g., whether PII was detected). This is a niche but real threat requiring constant-time response paths, which is disproportionate for a code-pattern plugin.

### Cross-agent CSRF / replay attacks
Request signing, nonces, and replay protection between agents in multi-agent systems are infrastructure-level concerns beyond what prompt/pipeline design patterns can address.

### Multi-turn / conversation priming attacks
Attacks spanning multiple conversation turns (gradually normalizing the model toward policy violation) are not addressed by single-request patterns. Session-level monitoring and context window management are needed but are outside the scope of code-time guidance.

## Permanent Inherent Limitations

The following are **not bugs and will not be fixed** in any version. They are inherent properties of the techniques used and are documented here so they are not mistaken for gaps in coverage.

### Indirect prompt injection is a cross-skill dependency, not a single-skill fix
No single skill in this plugin eliminates indirect prompt injection (LLM01). Indirect injection — where tool outputs, RAG retrieval, or external API responses carry adversary-controlled instructions into the model's context — is the dominant real-world LLM01 vector. It requires layered mitigation across multiple skills: input sanitization (Secure External Ingestion), delimiter conventions (System Prompt Design), output validation (Output Validation), and action surface restriction (Agent Action Surface Control). Each skill contributes one layer; none is sufficient alone. This is by design, not an oversight — the OWASP LLM Top 10 explicitly recommends defense in depth.

### Heuristic encoding detection (ROT13, Base64) is illustrative, not comprehensive
The ROT13 and Base64 detection in `sanitize_web_content.py` is a best-effort heuristic that catches naive encoding-based injection attempts. It is trivially bypassable by rephrasing, using synonyms outside the detection word list, splitting encoded payloads below the minimum length threshold, or using alternative encodings (Base32, Base58, hex, gzip+Base64). This is inherent to regex-based detection of encoded content — there is no reliable way to distinguish "Base64-encoded injection" from "legitimate Base64 data" without semantic understanding. The templates are provided as a starting point, not as comprehensive detection.

### NFKC Unicode normalization has partial homoglyph coverage
The `normalize_encodings` function uses Unicode NFKC normalization to collapse homoglyphs (visually similar characters) to their canonical forms. NFKC handles a useful subset (e.g. fullwidth/halfwidth forms, many compatibility characters, and some mathematical alphanumeric symbol forms — though not all categories defined in TR15). It does **not** collapse the following categories that are routinely used in homoglyph-based prompt injection:

- **Enclosed Alphanumerics** — Ⓘ Ⓖ Ⓝ Ⓞ Ⓡ Ⓔ (block U+2460–U+24FF)
- **Mathematical Alphanumeric Symbols** — 𝐈𝐠𝐧𝐨𝐫𝐞 / 𝙸𝚐𝚗𝚘𝚛𝚎 (block U+1D400–U+1D7FF)
- **Braille patterns** — ⠊⠛⠝⠕⠗⠑ (block U+2800–U+28FF)
- **Cyrillic / Greek Latin-lookalikes** — е о а ѕ р с (Cyrillic small e, o, a, dze, er, es) and α ο ν (Greek alpha, omicron, nu)
- **CJK Latin-lookalikes** — fullwidth Latin and CJK punctuation that survive partial normalization
- **Regional Indicator Symbols** — 🇮🇬🇳🇴🇷🇪 (block U+1F1E6–U+1F1FF)
- **Unicode bidirectional override controls** — U+202A–U+202E, U+2066–U+2069 (these can make displayed text differ from tokenized text and are not removed by `remove_zero_width_chars` in v1.0.0)

Full homoglyph normalization would require a Unicode confusables mapping (TR39), which is not bundled. NFKC is the standard, widely-available first layer — it is not complete coverage. For higher-assurance handling, run an additional pass that confines input to a known-safe script set (e.g. ASCII or single-script + digits) and rejects mixed-script tokens.

### Token-estimation heuristic (`len/4`) undercounts non-Latin scripts
The `len(text) / 4` approximation used as the Level A/B token-estimation fallback systematically underestimates token counts for non-Latin scripts (CJK, Cyrillic, Arabic, Devanagari commonly average closer to 1–2 characters per token, not 4). This is inherent to any fixed character-count heuristic — no single divisor holds across scripts. Production deployments must switch to the model's real tokenizer (e.g. `client.messages.count_tokens()`) before the input-size cap is trustworthy for non-Latin input; this is documented as the production path in `llm-endpoint-hardening/SKILL.md`, not an unaddressed gap.

## Known Limitations — Reference Implementation Gaps (Planned)

Unlike the items above, these are gaps in the current reference implementation that a real fix can close. They are tracked on the roadmap (see `CHANGELOG.md` Roadmap), not permanent.

### In-memory rate-limiter and spend-monitor state does not survive multi-process deployment
The Level B/C reference implementation in `templates/python/token_budget_limiter.py` holds per-user budget counters, cumulative spend, and circuit-breaker state in an in-process `dict` guarded by an `asyncio.Lock` — demonstration-grade state, not a distributed store. Under any deployment with more than one process (PM2/Gunicorn/uWSGI worker pools, multiple Kubernetes pods), each process holds independent counters: a configured $5/day per-user budget effectively becomes $5/day *per worker*, silently, since nothing coordinates the count across processes. Closing this requires an atomic external store (Redis `INCRBY` + TTL, or a Lua check-and-reserve script) behind the interface the skill already documents (`check_and_reserve`, `record_actual_usage`, `is_circuit_breaker_open`). As of v1.0.0, the plugin does not ask which deployment topology applies during tier selection and does not ship a Redis-backed reference implementation — see `CHANGELOG.md` Roadmap (v1.0.1) for the planned fix: an explicit topology question during Level B/C selection plus a Redis-backed template offered when the answer is multi-process.

## Known Plugin Interactions

**Superpowers (subagent-driven development):** When using Superpowers' subagent-driven workflow, security skills may trigger during implementation but get flagged as "off-plan" by the spec reviewer, since security hardening wasn't in the original plan. Two workarounds:
1. **Recommended:** Include security requirements in your plan during the brainstorming/design phase, before implementation begins. This ensures subagents implement security patterns as part of the spec.
2. **Alternative:** Use inline execution (not subagent-driven) so skills trigger in-session without plan compliance conflicts.

This interaction is addressed in v1.0.1 by updating skill triggers to fire during design/planning phases (see CHANGELOG.md).

## Use of This Plugin

Use of this plugin does not create a consulting, advisory, or professional-services relationship between the user and WildBlue.AI, Cheryl Aday, or any contributor. This plugin is published as open-source guidance under the MIT License. For engagement-based AI security assessment, see "Professional Support" below.

## Limitations

- This plugin provides development guidance based on the [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/) (published November 2025). It does not guarantee security.
- No automated tool replaces security review by qualified professionals.
- LLM security is a rapidly evolving field. Patterns are current as of the version date and may not address threats discovered after publication.
- Threat advisories are published as they are verified. Skill and pattern updates are shipped in periodic releases. This project does not guarantee response times.
- This plugin is provided as-is. See LICENSE for full terms.

## Professional Support

For comprehensive AI security assessment, contact [WildBlue.AI](https://wildblue.ai) — hello@wildblue.ai
