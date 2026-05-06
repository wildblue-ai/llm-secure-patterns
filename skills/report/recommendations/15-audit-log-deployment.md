---
decision: 15
title: Audit log deployment checklist — logs are an LLM02 surface
triggers_when: Agent Action Surface Control skill fired at Level C with audit logging (any LLM06 annotation referencing audit_log)
type: advisory
---

## Audit log deployment checklist

Logging "full context" creates an LLM02 (Sensitive Information Disclosure) surface. Logs become a new attack target — anyone who compromises log storage inherits your system prompts, user PII, and credentials captured from tool results.

The template's `redact_for_audit_log()` helper drops system-prompt contents (hash only), masks known credential patterns, and logs tool names + parameter schemas rather than parameter values. That covers the **code path**. The items below are the **deployment-layer controls** that the code cannot enforce.

**Review each item before enabling audit logging in production:**

- [ ] **Access controls on log storage.** Read access to the audit log is at least as sensitive as read access to production databases. Scope accordingly.
- [ ] **Retention limits.** Set a maximum retention window. Old logs that no one needs are a liability, not an asset. Align with your data-handling policy.
- [ ] **Storage encryption at rest.** Provider-managed KMS is the baseline. For high-sensitivity deployments, customer-managed keys.
- [ ] **Log destination trust review.** If logs ship to a SaaS aggregator, review that provider's SOC 2 / data-residency posture. Their breach is your breach.
- [ ] **Separation of audit from operational logs.** Audit logs should live in a different storage target than app debug logs. Different retention, different access, different alerting.
- [ ] **Alerting on log-read events.** Someone reading the audit log is a higher-severity signal than someone reading app logs. Instrument it.
- [ ] **Redact-on-write, not redact-on-read.** Use the template's redaction helper *before* the log line is emitted. Relying on downstream scrubbing fails the moment anyone clones the raw store.
- [ ] **Periodic sampling review.** Pull a sample quarterly and confirm nothing that should have been redacted slipped through. Regexes rot.

The helper reduces the surface. These controls reduce the blast radius when the surface is still reached.
