---
decision: 4
title: Output Validation covers HTML only — SQL and shell are your responsibility
triggers_when: Output Validation skill fired (any LLM05 annotation from that skill)
type: advisory
---

## Output Validation covered HTML rendering only

The Output Validation skill escapes LLM output for **HTML text-node insertion**. It does **not** make LLM output safe for SQL queries or shell commands.

**For SQL:** use parameterized queries. Never string-interpolate LLM output into SQL.

```python
# Correct
cursor.execute("SELECT * FROM users WHERE email = %s", (llm_output,))

# Wrong — escaping LLM output into SQL is not safe even with "sanitization"
cursor.execute(f"SELECT * FROM users WHERE email = '{llm_output}'")
```

**For shell:** use argument arrays. Never `shell=True` with LLM output.

```python
# Correct
subprocess.run(["grep", llm_output, "file.txt"], check=True)

# Wrong — argument splitting, quoting, and expansion are all attacker-controlled
subprocess.run(f"grep {llm_output} file.txt", shell=True)
```

If your application writes LLM output to any other context (LDAP filters, XML, XPath, JSON embedded in scripts, file paths), the escaping the skill applied is **not** appropriate for those contexts.
