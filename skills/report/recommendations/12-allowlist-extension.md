---
decision: 12
title: Extend SAFE_READ_PREFIXES for your MCP tool set
triggers_when: Agent Action Surface Control skill fired (any LLM06 annotation from that skill)
type: advisory
---

## Review and extend `SAFE_READ_PREFIXES` for your environment

The Agent Action Surface template uses a **read-only allowlist** (`SAFE_READ_PREFIXES = {"get", "list", "read", "fetch", "search", "describe"}`). Any tool whose name does not match the allowlist is flagged as potentially destructive.

This is conservative by design — the cost of a false positive (annoying warning) is much lower than the cost of a false negative (silent destructive call).

**You need to tune the allowlist because:**

- MCP providers pick their own verb conventions. `query_*`, `view_*`, `show_*`, `inspect_*`, `diff_*` are common read-only verbs that the default list does not catch.
- Some providers prefix destructive tools with otherwise-safe verbs (`list_then_delete`, `get_and_archive`). Name-based allowlisting cannot catch these.

**Review each MCP server you use, then:**

1. List every tool the server exposes.
2. Classify each as read-only or side-effectful by **reading the tool's schema and provider docs**, not by verb alone.
3. Extend `SAFE_READ_PREFIXES` with the additional read-only verbs used by your providers.
4. For tools whose safety cannot be determined from the name, wrap them in an explicit `DESTRUCTIVE_TOOLS` override set that always triggers the destructive-path code regardless of prefix.
5. Re-review on every MCP server version bump — new tools appear quietly.

**Safe-verb lists drift.** Revisit this file on the same cadence as your dependency audits.
