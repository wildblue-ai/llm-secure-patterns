# OWASP LLM Top 10 (2025) — Plugin Skill Mapping

> This mapping references the [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/) (published November 2025). Descriptions are paraphrased — consult the original document for authoritative definitions.

## Summary Table

| Category | Name | Coverage | Skills | Confidence |
|----------|------|----------|--------|------------|
| LLM01 | Prompt Injection | Covered | 1, 2, 4, 5 | MODERATE |
| LLM02 | Sensitive Information Disclosure | Covered | 3, 4 | MODERATE |
| LLM03 | Supply Chain | Not covered | — | — |
| LLM04 | Data and Model Poisoning | Not covered | — | — |
| LLM05 | Improper Output Handling | Covered | 3 | MODERATE to HIGH |
| LLM06 | Excessive Agency | Covered | 5 | MODERATE |
| LLM07 | System Prompt Leakage | Covered | 4 | MODERATE |
| LLM08 | Vector and Embedding Weaknesses | Not covered | — | — |
| LLM09 | Misinformation | Partially addressed | 3 | LOW |
| LLM10 | Unbounded Consumption | Covered | 1, 2 | MODERATE to HIGH |

---

## LLM01: Prompt Injection

**Skills:** 1, 2, 4, 5 | **Confidence:** MODERATE

**What this risk means for developers:**
Prompt injection is the broadest and most critical risk facing LLM applications. It occurs when an attacker manipulates model behavior by embedding instructions in user input (direct injection) or in external content the model processes — documents, web pages, tool outputs (indirect injection). Because LLMs cannot reliably distinguish between instructions and data, any text the model ingests is a potential injection vector.

**What the plugin covers:**
- Skill 1: Input sanitization patterns, delimiter enforcement, content-length limits on external data
- Skill 2: Token-budget controls that limit the blast radius of injected content
- Skill 4: System prompt hardening that mitigates instruction-override attacks
- Skill 5: Pipeline isolation that constrains what an injected instruction can reach

**What the plugin does NOT cover:**
- Novel injection techniques not yet documented in public research
- Model-level defenses (fine-tuning, RLHF alignment against injection)
- Runtime detection systems that classify inputs as adversarial in real time
- Indirect injection through modalities the plugin does not address (images, audio)

Prompt injection is an unsolved problem. The plugin mitigates known attack vectors through layered architectural controls but cannot claim prevention.

---

## LLM02: Sensitive Information Disclosure

**Skills:** 3, 4 | **Confidence:** MODERATE

**What this risk means for developers:**
LLMs can leak sensitive data in their responses — system prompt contents, PII from context windows, API keys passed in prompts, and occasionally memorized training data. This risk is especially acute when models are connected to databases, internal documents, or user profiles, because the model may surface that information in response to cleverly worded queries.

**What the plugin covers:**
- Skill 4: Patterns for keeping credentials, internal identifiers, and sensitive configuration out of prompts entirely
- Skill 3: Output filtering that detects and redacts common sensitive data patterns (emails, keys, SSNs) before responses reach users

**What the plugin does NOT cover:**
- Training data memorization and extraction attacks
- Inference-time data leakage through statistical analysis of model outputs
- Cross-session information leakage in multi-tenant deployments
- DLP (Data Loss Prevention) integration at the infrastructure layer

---

## LLM03: Supply Chain

**Skills:** — | **Confidence:** —

**What this risk means for developers:**
Supply chain risk in LLM applications encompasses vulnerabilities introduced through third-party models, pre-trained weights, training datasets, plugins, and dependencies. A compromised model checkpoint, a poisoned fine-tuning dataset, or a malicious model marketplace listing can introduce backdoors that are nearly impossible to detect at inference time.

**What the plugin covers:**
Not covered. Supply chain security requires organizational controls — model provenance verification, dependency auditing, signed artifacts, and trusted registries. These are outside the scope of development-time guidance patterns.

---

## LLM04: Data and Model Poisoning

**Skills:** — | **Confidence:** —

**What this risk means for developers:**
Poisoning attacks target the training pipeline: an attacker injects malicious samples into training or fine-tuning data, causing the model to learn undesirable behaviors — backdoors that activate on specific triggers, biased outputs, or degraded performance on particular inputs. This can also include direct tampering with model weights.

**What the plugin covers:**
Not covered. Data and model poisoning requires controls at the training and fine-tuning stages — data provenance, anomaly detection in training metrics, and access controls on model artifacts. These are outside plugin scope.

---

## LLM05: Improper Output Handling

**Skills:** 3 | **Confidence:** MODERATE to HIGH (depends on pattern)

**What this risk means for developers:**
When applications trust model output without validation, they create injection points downstream. If model output is rendered as HTML, it can execute JavaScript. If it is interpolated into SQL queries, it enables SQL injection. If it is passed to a shell, it allows command injection. The model is an untrusted input source — its output must be validated and sanitized before use in any security-sensitive context.

**What the plugin covers:**
- Skill 3: Schema validation for structured model output (confidence: HIGH for well-defined schemas)
- Skill 3: HTML escaping patterns to mitigate XSS from model-generated content (confidence: MODERATE — context-dependent escaping is complex)
- Skill 3: URL and link validation to block malicious destinations in model output
- Skill 3: Patterns for safe interpolation of model output into downstream operations

**What the plugin does NOT cover:**
- Language-specific or framework-specific sanitization libraries (the plugin provides patterns, not implementations)
- Output validation for non-text modalities (generated images, audio)
- Content safety filtering (toxicity, harmful content) — distinct from security validation

---

## LLM06: Excessive Agency

**Skills:** 5 | **Confidence:** MODERATE

**What this risk means for developers:**
When an LLM-powered agent has access to tools, APIs, or system resources, the principle of least privilege becomes critical. Excessive agency means the model can take actions beyond what is necessary — write access when only read is needed, access to production systems during development, or the ability to chain tool calls without human oversight. A single successful prompt injection in an overprivileged agent can cause significant damage.

**What the plugin covers:**
- Skill 5: Least-privilege patterns for tool and API access
- Skill 5: Pipeline stage isolation — separating planning, execution, and verification stages with distinct permission boundaries
- Skill 5: Human-in-the-loop patterns for high-impact actions
- Skill 5: Guidance on scoping tool definitions to minimum required capabilities

**What the plugin does NOT cover:**
- Runtime permission enforcement (the plugin provides architectural patterns, not enforcement mechanisms)
- Platform-specific IAM or RBAC configuration
- Autonomous agent safety beyond permission scoping

---

## LLM07: System Prompt Leakage

**Skills:** 4 | **Confidence:** MODERATE

**What this risk means for developers:**
System prompts often contain business logic, behavioral instructions, safety rules, and sometimes credentials or internal identifiers. Attackers can extract these through crafted queries ("repeat your instructions," role-play scenarios, encoding tricks). Once leaked, attackers gain a roadmap for circumventing the application's controls.

**What the plugin covers:**
- Skill 4: Anti-leakage instruction patterns that mitigate common extraction techniques
- Skill 4: Canary token patterns that detect when a system prompt has been leaked
- Skill 4: Dual-prompt architecture — separating public-facing instructions from sensitive configuration
- Skill 4: Guidance on what should never appear in a system prompt

**What the plugin does NOT cover:**
- Guaranteed prevention of prompt leakage (no known technique fully prevents extraction by a determined attacker)
- Runtime monitoring for prompt leakage in production
- Model-level controls that restrict the model from repeating its instructions

---

## LLM08: Vector and Embedding Weaknesses

**Skills:** — | **Confidence:** —

**What this risk means for developers:**
RAG (Retrieval-Augmented Generation) pipelines depend on vector databases and embedding models. Attackers can manipulate embeddings to poison retrieval results, inject adversarial documents into the vector store, or exploit access control gaps where users retrieve documents they should not have access to. Embedding inversion attacks can also reconstruct sensitive source text from stored vectors.

**What the plugin covers:**
Not covered in v1.0.0. Vector and embedding security requires specialized controls at the retrieval layer — access control on vector stores, embedding integrity verification, and retrieval result filtering. This may be addressed in future versions.

---

## LLM09: Misinformation

**Skills:** 3 | **Confidence:** LOW

**What this risk means for developers:**
LLMs generate plausible-sounding but factually incorrect content (hallucinations). In high-stakes domains — medical, legal, financial — misinformation from an LLM can cause real harm. This risk extends beyond accidental hallucination to include cases where attackers deliberately induce false outputs through crafted inputs.

**What the plugin covers:**
- Skill 3: Output schema validation catches structural failures (missing required fields, wrong types) but cannot detect semantic misinformation

**What the plugin does NOT cover:**
- Factual accuracy verification or grounding
- Hallucination detection or mitigation
- Citation verification or source attribution
- Domain-specific correctness validation

The plugin's coverage of this category is minimal. Misinformation mitigation requires domain-specific grounding, retrieval-augmented generation with verified sources, and human review — none of which are in plugin scope.

---

## LLM10: Unbounded Consumption

**Skills:** 1, 2 | **Confidence:** MODERATE to HIGH (depends on pattern)

**What this risk means for developers:**
LLM APIs charge per token. Without controls, an attacker can trigger expensive operations — submitting massive inputs, requesting maximum-length outputs, or looping agent calls — to run up costs (denial-of-wallet). Resource exhaustion can also degrade service for other users in shared deployments.

**What the plugin covers:**
- Skill 1: Input length limits and token budget caps on external content ingestion (confidence: HIGH for enforced caps)
- Skill 2: Token-budget rate limiting patterns that cap per-request and per-session spend (confidence: MODERATE to HIGH depending on enforcement)
- Skill 2: Spend alerting patterns that detect anomalous consumption

**What the plugin does NOT cover:**
- Infrastructure-level rate limiting (API gateway configuration, cloud provider spending limits)
- Cost allocation and chargeback across multi-tenant deployments
- Automatic scaling controls
