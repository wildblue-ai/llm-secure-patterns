---
decision: 13
title: Stage 1 write-permission enforcement is an operator responsibility
triggers_when: Agent Action Surface Control skill fired (any LLM06 annotation from that skill)
type: advisory
---

## Stage 1 write-permission enforcement

`validate_pipeline()` **warns** when Stage 1 (the classification / reasoning stage that sees untrusted input) has write-capable tools attached. It **cannot prevent** a write-capable Stage 1 pipeline at runtime — the Python check happens inside the same process that wires up the pipeline.

**Two places to enforce:**

1. **Hard-fail in code:** call `validate_or_raise()` instead of `validate_pipeline()` during startup or CI. This raises `PipelineValidationError` on any Stage 1 write permission and stops the process from starting.

   ```python
   from isolated_pipeline import validate_or_raise
   validate_or_raise(pipeline_config)  # raises before serving traffic
   ```

2. **Enforce at the deployment layer.** The code-level check is defense in depth; the durable guarantee is infrastructure:
   - **IAM roles per stage** — Stage 1's service account has no write permissions on any resource Stage 2 can touch.
   - **API-key scoping** — Stage 1 uses a key that cannot call write-scoped MCP servers, write endpoints, or mutation APIs.
   - **Least-privilege service accounts** — the OS user running Stage 1 has no filesystem write access beyond its own temp dir.
   - **Network policy** — Stage 1 cannot reach the same egress destinations as Stage 2.

The skill's runtime check flags **honest mistakes in configuration**. The deployment layer mitigates **the case where an attacker who has compromised the model's context tries to escalate**. You want both.
