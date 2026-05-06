---
decision: 14
title: MCP server trust — allowlist and hash-pinning scaffolds
triggers_when: Agent Action Surface Control skill fired at Level B or higher with MCP servers configured
type: scaffold
---

## MCP server trust (scaffolds)

MCP tool schemas influence model behavior **before any code runs**. A provider that changes a tool description mid-session can steer the model into unintended actions. Hash-pinning surfaces schema changes that would otherwise slip past normal code review — they don't break your code, so they don't show up in diffs.

**False-confidence warning:** these controls mitigate common MCP trust failures (rug-pulls, description injection, quiet schema changes). They do **not** eliminate risk from a deeply compromised server with valid credentials. A server that was trusted yesterday and is compromised today will pass the allowlist and hash check until the next pin update.

### Scaffold 1 — MCP server allowlist

```python
# mcp_allowlist.yaml
servers:
  - name: github-readonly
    url: https://mcp.github.example/v1
    allowed_verbs: [get, list, search]
  - name: internal-kb
    url: https://kb.internal/mcp
    allowed_verbs: [search, read, describe]
```

Reject any server whose name or URL is not in the allowlist at registration time. Log the rejection. An unexpected registration attempt is a signal, not noise.

### Scaffold 2 — schema hash pinning (SSH known_hosts pattern)

```python
# .mcp-pins.json  (checked in)
{
  "github-readonly": "sha256:4e0b...",
  "internal-kb":     "sha256:9a31..."
}
```

```python
import hashlib, json, sys

def pin_hash(schema: dict) -> str:
    canonical = json.dumps(schema, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()

def verify_or_prompt(server_name: str, live_schema: dict, pins: dict) -> None:
    expected = pins.get(server_name)
    actual = pin_hash(live_schema)
    if expected is None:
        sys.exit(f"[pin] No pin on record for {server_name}. Refusing to register.")
    if expected != actual:
        # Show the diff, require an explicit pin update to proceed.
        sys.exit(f"[pin] {server_name} schema changed.\n"
                 f"  expected {expected}\n  actual   {actual}\n"
                 f"  Run `./scripts/update-mcp-pin {server_name}` after reviewing the diff.")
```

**Pin-update workflow:** schema mismatch is never auto-resolved. A human reviews the diff, then runs an explicit update script that rewrites `.mcp-pins.json`. This mirrors SSH `known_hosts` prompting.

**MCP spec version:** pin the MCP protocol version alongside server hashes — new spec versions can change the shape of tool descriptions without any server-side change being visible.

### Additional controls from SKILL.md Level B

- Sanitize tool descriptions with the delimiter-escape helper before they enter a prompt.
- Bound-check schema structure at registration (tool count ceiling, description length ceiling).
- Log every registration event to the audit log.
- Apply least-privilege at the MCP boundary — the credential the agent uses to call the server should not grant more than the allowlisted verbs.
