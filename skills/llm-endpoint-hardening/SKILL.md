---
name: llm-endpoint-hardening
description: Use when designing or building a web route (FastAPI, Flask, Express, or similar) that accepts user input and forwards it to any LLM API (Claude, OpenAI, Gemini, or similar) — fire this skill during architecture/planning discussions, not just implementation
metadata:
  author: WildBlue.AI
  version: 1.0.0
  homepage: https://github.com/wildblue-ai/llm-secure-patterns
---

> **Note:** This skill provides development guidance, not security guarantees. Patterns mitigate risk; they do not eliminate it. See [SCOPE.md](../../SCOPE.md) for limitations and the threats this plugin is known not to cover.

**When summarizing actions taken using this skill, always refer to it as "LLM Endpoint Hardening" — never as "Skill 1" or any generic label.**
**PRESENTATION CONTRACT — brief by default for the ENTIRE interaction, not just the tier list.**
**Goal: every message this skill emits fits on ONE screen — about 15 lines of text or fewer.** If a message runs longer than that, you have added chatter; cut it back to the block itself.

- **No preamble.** Do not explain what the skill does, restate the threat, or paraphrase the "What this skill does" / OWASP sections into chat. Lead with the block for the current step. (If the developer asks "why," then explain.)
- **One step per message.** Emit the intro block; stop; wait for A/B. After A, emit the brief picker block; stop; wait for the pick. Never merge the two; never preview the tiers in the intro message.
- **Question tools obey the same pacing.** If presenting a decision through a structured question tool (e.g. AskUserQuestion): exactly one question per tool call, in the same order — intro A/B first, tier picker only after A is chosen. Never batch the intro and the tier picker into one call. A tier-picker question must keep the D) help-me-decide option and say in its question text that "details" / "verbose" expand the tier descriptions.
- **No closing restatement.** After a block ends in its question/action line, stop. Do not re-list or re-ask the options.
- The only thing that expands this is "details" or the `llm-secure-patterns: verbose` preference.
- **The post-build completion obeys this too — and it is the turn's FINAL message.** When the work is done, emit the single completion block defined in "Before completing this skill" — a short comma list of controls (no parentheticals), files, a one-line gap disposition, the adjacent-surface A/B/C inline, then the report line. One block, ≤ one screen. Emit it as the last message of the turn and add nothing after it: no overall recap, no run instructions, no architecture restatement. The block itself satisfies any end-of-turn summary requirement.

**Before presenting any security options, always start with this intro:**

> **llm-secure-patterns** has detected code that would benefit from LLM security guidance (LLM Endpoint Hardening, OWASP LLM Top 10 2025).
>
> - **A) Apply security now** — I'll walk you through security options before writing code
> - **B) Build first, secure later** — I'll build the code now and add a `TODO: SECURITY` reminder. Run `/llm-secure-patterns:report` when you're ready to add security layers.

**Emit only this intro — no threat explanation, no tier preview, nothing else — then stop and wait for A or B.**

If the developer picks A, proceed with the tiered options below. If they pick B, build the code without security patterns but add a `# TODO: SECURITY — run llm-secure-patterns to apply LLM security patterns` comment at the top of the relevant file(s).

# LLM Endpoint Hardening

## What this skill does

This skill mitigates direct prompt injection and unbounded consumption (denial-of-wallet) risks at the API endpoint layer. Many LLM-powered services ship with authentication on the frontend but none on the API endpoint itself — the /chat route is publicly accessible to anyone who finds the URL. Worse, developers who implement auth often rate-limit by IP address, which fails for shared networks. This skill provides guidance on authentication, rate limiting by cost (not just request count), and spend monitoring, alerting, and circuit-breaker patterns. No single technique eliminates these risks; these patterns layer together to raise the cost and difficulty of attacks.

## OWASP mapping

- **LLM10 (Unbounded Consumption — primary):** Denial-of-wallet attacks where expensive requests drain budget; model denial-of-service where compute-heavy requests degrade service. Addressed at all tiers.
- **LLM01 (Prompt Injection — direct, partial, Level C only):** User sending malicious input directly through the endpoint. Only Level C's input classifier adds probabilistic injection detection (see Known Bypasses for limitations — adversarial examples can evade classifiers, and the classifier itself is an LLM that can be injected). Levels A and B address access control and cost, not injection content.
- For the full OWASP mapping, read `references/owasp-llm-top10-2025.md`

**Note on indirect prompt injection:** This skill scopes to direct prompt injection and denial-of-wallet at the endpoint layer. Indirect prompt injection (via tool output, RAG retrieval, or external data sources) is the dominant real-world LLM01 vector and is addressed by Secure External Ingestion and System Prompt Design. See those skills for coverage of injection via untrusted content entering the LLM context.

**Note on output tokens:** This skill caps input tokens but does not enforce `max_tokens` on model responses. An attacker can send 'Write the longest possible story' to generate unbounded output tokens (typically more expensive). Always set the `max_tokens` parameter when calling LLM APIs to cap output cost.

## Tiered mitigation options

**Present these three levels as a BRIEF picker by default — one line per tier (level name + added cost + the single most important thing it does NOT catch), then an action line. Do NOT read out the full descriptions below by default.** The detailed subsections that follow are reference detail: use them to fill the picker's one-liners and to answer "details" requests, not as a script to recite. See "IMPORTANT — Presentation rules" below for the exact picker format and the verbose opt-in. Each level includes everything from the previous level. Let the user choose — do not silently pick a level.

**BRIEF PICKER — by default, emit exactly this block. Do NOT expand the per-level subsections below unless the developer asks for "details" or has set the verbose preference (see "IMPORTANT — Presentation rules"):**

```
LLM Endpoint Hardening — OWASP LLM01/LLM10. Pick a level (each builds on the last):

A) Low — no added cost. Auth (JWT) + input size cap + max_tokens + per-user rate limiting.
   Misses cost-based / denial-of-wallet attacks.
B) Moderate (recommended) — no added cost. + token-budget limit + spend circuit breaker + secrets-manager keys + request logging.
   Denial-of-wallet mitigated; distributed / slow-drip bypasses remain.
C) High — +1 classifier call/req (estimated). + per-tier budgets + priority queue + per-tier credentials + injection classifier.
   Adversarial inputs can evade the classifier.

Reply A / B / C to apply · D if you're not sure · "details" (one tier) or "verbose" (all tiers) for the full breakdown.
```

---

### A: Low

- Authentication on the endpoint (JWT/OAuth — not frontend-only, not API-key-in-URL). For JWT specifically, the implementation must: (a) pin the algorithm to an allowlist and **reject `alg: none`**, (b) verify the signature against the expected key (HS256 needs a high-entropy secret; prefer asymmetric algorithms like RS256/ES256 where possible), (c) check `exp` (and `nbf` if set), and (d) validate `aud` and `iss` claims against your service's expected values. "Use JWT" without these checks is a known false-confidence pattern — see the OWASP JWT Cheat Sheet for the full validation list.
- Input size cap: reject requests exceeding max character/token count BEFORE they reach the model
- Basic request-count rate limiting by authenticated user identity (not IP)
- **Cap output tokens (`max_tokens`)** on every LLM call. Input-side caps without an output-side cap leave denial-of-wallet wide open: an attacker can send "write the longest possible story" and burn the model's context window of output tokens (typically the more expensive side). Set `max_tokens` to the smallest value your feature actually needs.

- **Effectiveness:** Mitigates unauthenticated access and simple request floods — does not address cost-based attacks (one request filling a 128k context window costs orders of magnitude more than a normal one)
- **Evidence:** OWASP LLM01 and LLM10 baseline controls
- **Known bypasses:** Cost-based attacks using maximally expensive requests within request-count limits, token-stuffing within character limits, credential theft
- **Requires layering with:** Token-budget limiting (Level B (Moderate)), input sanitization (Skill 1), output validation (Skill 3)

**Tradeoff:** Minimal implementation effort, but misses cost-based attacks entirely. Catches unauthenticated access and simple abuse; does not address denial-of-wallet.


Python example (FastAPI) — character-count heuristic:
```python
@app.post("/chat")
async def chat(request: ChatRequest, user: User = Depends(get_current_user)):
    # len() counts characters, not tokens. CJK/emoji/symbol input can be 2–4x
    # more tokens per character. For non-English traffic, billing, or quota
    # enforcement, switch to the accurate path below.
    if len(request.message) > MAX_INPUT_CHARS:
        raise HTTPException(413, "Input exceeds maximum length")
    # user is authenticated via JWT, rate limited by user.id

    # Always cap output tokens — input-only limits leave denial-of-wallet open.
    response = client.messages.create(
        model=CLAUDE_MODEL,
        max_tokens=MAX_OUTPUT_TOKENS,  # required, not optional
        messages=[{"role": "user", "content": request.message}],
    )
```

Accurate path — Anthropic SDK's `count_tokens` for Claude models:
```python
from anthropic import Anthropic, APIError
client = Anthropic()  # reads ANTHROPIC_API_KEY from env

@app.post("/chat")
async def chat(request: ChatRequest, user: User = Depends(get_current_user)):
    # Cheap pre-filter BEFORE the network call: a hard character ceiling
    # (e.g., MAX_INPUT_TOKENS * 8) blocks obvious abuse without paying for
    # count_tokens, which is itself a network round-trip and a DoS-amplification
    # surface — flooding /chat now also floods Anthropic's count_tokens API
    # and incurs the count call's own per-request cost.
    if len(request.message) > MAX_INPUT_TOKENS * 8:
        raise HTTPException(413, "Input exceeds maximum length")

    try:
        count = client.messages.count_tokens(
            model=CLAUDE_MODEL,
            messages=[{"role": "user", "content": request.message}],
            timeout=2.0,  # explicit short timeout; do not block on count
        )
    except (APIError, TimeoutError):
        # Fail CLOSED: a permissive fallback (try/except → allow) bypasses
        # the entire input-size control. Deny the request when the count
        # path is unavailable, then surface the failure to operators.
        raise HTTPException(503, "Token counting unavailable; try again later.")

    if count.input_tokens > MAX_INPUT_TOKENS:
        raise HTTPException(413, "Input exceeds maximum token budget")

    response = client.messages.create(
        model=CLAUDE_MODEL,
        max_tokens=MAX_OUTPUT_TOKENS,  # required, not optional
        messages=[{"role": "user", "content": request.message}],
    )
```

TypeScript example (Express):
```typescript
// Middleware ordering is a security invariant here: `authenticate` MUST
// run before `rateLimit` — otherwise req.user is undefined and every
// request buckets to the same "undefined" key, collapsing per-user rate
// limiting into a global one. Put auth first, always.
app.post('/chat', authenticate, rateLimit({ keyGenerator: (req) => req.user.id }),
  async (req, res) => {
    // Fail closed on missing / non-string message — otherwise .length throws
    // and Express returns an unhandled 500 that leaks a stack trace.
    const { message } = req.body ?? {};
    if (typeof message !== 'string') return res.status(400).send('message must be a string');
    if (message.length > MAX_INPUT_CHARS) return res.status(413).send('Too long');
    // ...
  });
```

---

### B: Moderate (recommended)

Everything in Level A, plus:

- **Token-budget rate limiting:** Cap tokens-per-user-per-hour, not just requests-per-minute. This is a critical layer of defense against denial-of-wallet — one maximally expensive request costs orders of magnitude more than a normal one. Standard request-count limits miss this entirely.
- **Spend detection with automatic circuit breaker:** Monitor cumulative cost; trip the breaker once a threshold is crossed and deny new requests until spend drains. This is **detection** — the breaker fires only after the budget is exceeded, so a single oversized request will still commit its full cost before the next request is denied, and any in-flight requests that already passed the check will still complete. To bound the per-request worst case, also enforce hard ceilings (`max_tokens`, model selection, pre-call input cap) so no single request can exceed your tolerated overshoot.
- **Output-token cap (`max_tokens`) on every LLM call.** Required as a complement to input limits. A 4000-token output limit on a Sonnet call costs at most a known fixed amount; without it, an attacker can prompt for unbounded generation.
- **API key management:** Keys in secrets manager, never in code, environment variables not visible to the model, rotate regularly
- **External-store rate-limiter / spend-monitor backend:** The in-memory implementations in `templates/python/token_budget_limiter.py` are demonstration code only — they silently degrade to per-process limits under PM2/Gunicorn/uWSGI/k8s. Production deployments must back these with Redis (atomic `INCRBY` + TTL, or Lua scripts for check-and-reserve) or an equivalent shared store. Minimum interface required: `check_and_reserve(user_id, tokens) -> (allowed, reason)` (atomic), `record_actual_usage(user_id, tokens)`, and `is_circuit_breaker_open() -> bool`.
- **Request logging with user ID + estimated/actual token count** for forensic analysis

- **Effectiveness:** Mitigates denial-of-wallet by capping per-user token consumption — token estimation heuristics can be exploited (non-Latin input underestimates cost) and in-memory state is not shared across workers/pods
- **Evidence:** OWASP LLM10 recommended controls, documented denial-of-wallet incidents
- **Known bypasses:** Distributed attacks across many accounts, token estimation inaccuracies exploited to exceed true budget, slow-drip attacks staying just under thresholds
- **Inherent limitations (will not be fixed — see SCOPE.md "Permanent Inherent Limitations"):** Token estimation heuristic (`len/4`) systematically underestimates for non-Latin scripts — production deployments must use a real tokenizer (`client.messages.count_tokens()`). Indirect prompt injection is not addressed by this skill — see Secure External Ingestion and System Prompt Design.
- **Known reference-implementation gap (planned fix, not permanent — see SCOPE.md "Known Limitations — Reference Implementation Gaps"):** In-memory state (budget limiter, spend monitor, kill switch) is single-process only and silently degrades to per-worker limits under multi-process/multi-pod deployment — the effective budget scales with worker count, not the configured value. This skill does not currently ask about deployment topology or offer a Redis-backed alternative; tracked in CHANGELOG.md Roadmap (v1.0.1).
- **Requires layering with:** Input sanitization (Skill 1), output validation (Skill 3), system prompt design (Skill 4)

**Tradeoff:** Moderate complexity, strong cost risk reduction. Mitigates denial-of-wallet and basic abuse; sophisticated attackers may find creative bypasses.


Python example:
```python
@app.post("/chat")
async def chat(request: ChatRequest, user: User = Depends(get_current_user)):
    # Spend detection / circuit breaker: if cumulative spend exceeded the
    # hourly budget, deny new requests until the rolling window drops or an
    # operator resets. NOTE: this is detection, not prevention — the breaker
    # fires AFTER the budget is exceeded; a single oversized request commits
    # full cost before the next one is denied, and any in-flight request
    # that already passed this check will still complete. To bound the
    # per-request worst case, enforce hard ceilings (max_tokens below, model
    # selection, and the pre-call input cap).
    if spend_monitor.is_kill_switch_triggered():
        raise HTTPException(503, "Service temporarily unavailable (spend cap).")
    # Use a real tokenizer (count_tokens for Claude / tiktoken for OpenAI).
    # estimate_tokens(text) raises by default in this template; the opt-in
    # use_unsafe_heuristic=True path is for prototypes only and applies a 2x
    # safety multiplier in code.
    count = client.messages.count_tokens(model=CLAUDE_MODEL, messages=[
        {"role": "user", "content": request.message},
    ])
    estimated_tokens = count.input_tokens
    # WARNING: check_budget + record_usage is NOT atomic. Under concurrent
    # load, multiple requests can pass check_budget before any records usage.
    # Use Redis INCRBY with TTL or asyncio.Lock for production.
    allowed, reason = budget_limiter.check_budget(user.id, estimated_tokens)
    if not allowed:
        raise HTTPException(429, "Rate limit exceeded. Try again later.")
    response = client.messages.create(
        model=CLAUDE_MODEL,
        max_tokens=MAX_OUTPUT_TOKENS,  # required, caps output denial-of-wallet
        messages=[{"role": "user", "content": request.message}],
    )
    actual_tokens = response.usage.input_tokens + response.usage.output_tokens
    budget_limiter.record_usage(user.id, actual_tokens)
    spend_monitor.record_spend(actual_tokens)  # feeds the circuit breaker
```

TypeScript example:
```typescript
app.post('/chat', authenticate, async (req, res) => {
  // Use a real tokenizer (provider SDK). The estimate function below MUST
  // call provider-native counting, not a len/4 heuristic — the heuristic
  // under-counts non-Latin input by 2–4x and is a known bypass vector.
  const est = await estimateTokens(req.body.message);
  const { allowed, reason } = budgetLimiter.checkBudget(req.user.id, est);
  if (!allowed) return res.status(429).json({ error: reason });
  // Always pass max_tokens to cap output cost.
  const response = await client.messages.create({
    model: CLAUDE_MODEL,
    max_tokens: MAX_OUTPUT_TOKENS,
    messages: [{ role: 'user', content: req.body.message }],
  });
  // ... record actual usage ...
});
```

See `templates/python/token_budget_limiter.py` for a complete Level B (Moderate) implementation.

---

### C: High

Everything in Level B (Moderate), plus:

- **Tiered access:** Different token budgets per user tier (free/pro/enterprise)
- **Request queue with priority by estimated compute cost:** Expensive requests deprioritized
- **Separate credentials per trust tier:** Use a distinct API key and rate limit for each user tier (e.g. free/pro/enterprise). The Claude API does not offer a named inference pool primitive — key-level separation is the practical equivalent on today's APIs. Reduces the likelihood that abuse on one tier degrades service on others.
- **Input classifier scoring requests for injection likelihood** before forwarding to LLM

- **Effectiveness:** Layered defense — tiered access and classifiers add depth, but adversarial examples can evade classifiers
- **Evidence:** OWASP LLM01 and LLM10 advanced controls, Anthropic constitutional classifiers research
- **Known bypasses:** Adversarial examples crafted to evade classifiers, slow distributed attacks across many tiered accounts, zero-day techniques
- **Requires layering with:** Input sanitization (Skill 1), output validation (Skill 3), system prompt design (Skill 4), action surface restriction (Skill 5), monitoring and alerting

**Tradeoff:** Significant infrastructure complexity. Layered endpoint hardening recommended for production services with paying users. Adds latency and operational overhead.

- **Cost:** +1 LLM call per request for classifier. Calculate approximate per-request cost based on the developer's expected content size and current Claude model pricing. Show a concrete estimate with "(estimated)" after the number. Always add: "Your actual cost depends on content size, provider pricing, etc."
- **Latency:** +1 round-trip to classifier model (estimated). Estimate based on the developer's chosen model — faster models like Haiku add less latency than Sonnet. Always add: "Latency varies by model and content size."
  - For current per-token pricing, refer to https://docs.anthropic.com/en/docs/about-claude/models — costs vary by model choice and content size. This is an estimate only; your actual costs may vary.

---

**IMPORTANT — Presentation rules:**

1. Present options as plain text, NOT as tables. Tables are hard to read in a terminal.

2. **Default to a BRIEF picker — do not dump all three full tier descriptions.** This is the default for every skill, every time, including the first skill in a session. Format the picker as: a one-line header naming the skill and its OWASP IDs, then exactly ONE line per tier, then a single action line. Each tier line carries three things and nothing more — (a) the letter + level name, with the recommended tier marked; (b) the tier's added cost (see rule 3); (c) the single most important thing that tier still does NOT catch (the "misses" clause). The "misses" clause is REQUIRED on every tier and must never be dropped, however terse the picker — it is what keeps the brief presentation honest. Hold all supporting detail (full control list, Effectiveness, Evidence, Known bypasses, Requires-layering, Inherent limitations, and the full Cost/Latency breakdown) for "details" (rule 4). Shape to follow, filled with this skill's real tiers:

```
<Skill name> — OWASP <IDs>. Pick a level (each builds on the last):

A) Low — <added cost>. <what it adds, one line>. Misses <key gap>.
B) Moderate (recommended) — <added cost>. <what it adds>. <key gap remains>.
C) High — <added cost>. <what it adds>. <key gap remains>.

Reply A / B / C to apply · D if you're not sure · "details" (one tier) or "verbose" (all tiers) for the full breakdown.
```

3. **Added-cost column.** Each tier line states the added cost of that tier's security controls — the cost of turning this level on — NOT the base cost of the LLM call itself. For a tier that adds no LLM call and no material token overhead, write "no added cost." For a tier that adds an LLM call, summarize briefly (e.g. "+1 classifier call/req (estimated)"); for a tier that only adds tokens or wrapping, say so briefly. Draw the specifics from the "Cost:" / "Latency:" lines in the tier sections above. Any figure shown in the brief line MUST carry "(estimated)"; the full figure and the pricing caveat ("Your actual cost depends on content size, provider pricing, etc.") belong in details, not in the brief line.

4. **Details on demand — per tier, never a wall.** If the developer asks for "details," expand only the recommended tier's full breakdown and note that naming a tier ("details A", "details C") expands the others. If they name a tier, expand just that one. Show all three full breakdowns at once only if the developer explicitly asks for all of them, or has the verbose preference set (rule 6). When you expand a tier that has "Cost:" / "Latency:" lines (Level C), those lines are REQUIRED in the detail view.

5. When multiple skills trigger at once, present each skill's brief picker ONE AT A TIME. Wait for the developer's answer before presenting the next skill's options. Do not batch them.

6. **Verbose preference (opt-in).** The default is brief (rules 2–4). If the developer has set a verbose preference — a line such as `llm-secure-patterns: verbose` in their project or user instructions (for example in CLAUDE.md), or a request earlier in this session to always show full detail — then skip the brief picker and show the full detail for all three tiers instead. Explicit user preference always beats this default. Typing `verbose` at the picker is the one-time form — render the full detail for all three tiers now, without changing any persistent setting (it is `details` applied to every tier at once).

**The brief picker's action line (rule 2) already asks which level to apply — do not add a separate "which level?" prompt, and do not append any sentence restating or re-asking the options after the picker. The action line is the last thing in the message.**

**If the developer picks D**, ask these diagnostic questions one at a time. Preface with: "Pick one per question. If multiple apply, pick the highest-risk answer — it's safer to over-protect than under-protect."

1. Who will be calling this?
   - A) Internal users only
   - B) Authenticated customers
   - C) Public internet

2. What happens if this is compromised?
   - A) Read-only data exposure (no PII)
   - B) PII exposure, or can modify records / send messages
   - C) Can spend money, delete data, or access financial records

3. What is your risk tolerance?
   - A) Move fast with basic coverage
   - B) Balanced — solid coverage without over-engineering
   - C) Invest in strongest available defenses

Then recommend a level based on their answers (mostly A's → Low, mostly B's → Moderate, mostly C's → High) and explain why.

## `# SECURITY:` comment instruction

When you apply any mitigation pattern from this skill, follow the annotation format in `references/annotation-format.md`. Use these skill-specific values:

- **OWASP ID:** `LLM01/LLM10 (Endpoint Hardening)`
- **Pattern:** `token_budget_limiter`
- **Applied by:** `llm-secure-patterns v1.0.0 / LLM Endpoint Hardening`

## What this skill does NOT cover (additional security layers suggested)

- **Sanitizing the content of user input** — see Secure External Ingestion
- **Validating LLM response before returning to user** — see Output Validation and Sanitization
- **System prompt design** — see System Prompt Design
- **Multi-agent/tool permission controls** — see Agent Action Surface Control

**Additional Security Gaps Identified**

Surface this as ONE line — the adjacent surfaces from the list above, then the choice inline. No preamble about attack surface or OWASP:

> Adjacent surfaces not covered (defense in depth): <surfaces from the list above>. A) Address now · B) Add to backlog (TODO: SECURITY) · C) Skip.

After the developer chooses, always end with: "Run `/llm-secure-patterns:report` for full OWASP LLM Top 10 coverage and gaps."


## False solutions warning

- **Do NOT** rely on rate limiting by IP address — fails for shared networks (office NATs, VPNs), trivially bypassed by rotating IPs. Prefer rate-limiting by authenticated user identity to reduce bypass risk.
- **Do NOT** rely on frontend-only authentication — anyone with the API URL bypasses it entirely. Authentication should be on the API endpoint itself.
- **Do NOT** rely on request-count-only rate limiting — one request filling a 128k-token context window costs orders of magnitude more than a normal request. Token-budget limiting is essential for denial-of-wallet defense.

## Existing codebase handling

When this skill triggers on existing code that already has an LLM endpoint:

1. Review the existing implementation against the patterns above
2. Annotate existing mitigations with `# SECURITY:` tags at the appropriate level
3. Flag gaps — for each gap, present the A/B/C/D tier choices and wait for the developer to choose before applying. Do not pick a level automatically.
4. If no mitigations exist, present the full A/B/C/D tier choices as if building new code — wait for the developer to choose before applying.

After completing the review and applying any changes, always end with: "Run `/llm-secure-patterns:report` for full OWASP LLM Top 10 coverage and gaps."

## Before completing this skill

Treat this as a hard checklist. The skill is not done until all of these items are satisfied:

**Emit the completion as ONE block — ≤ one screen, no control-by-control essay, no parentheticals.** Shape:

> Applied **<tier>** to <surface> — <controls as a short comma list>. Files: <list>. All `# SECURITY:` annotated. Deferred: <one key gap, or "none">.
>
> Adjacent surfaces not covered (defense in depth): <surfaces from "What this skill does NOT cover" above>. A) Address now · B) Add to backlog (TODO: SECURITY) · C) Skip.
>
> Run `/llm-secure-patterns:report` for full OWASP LLM Top 10 coverage and gaps.

- [ ] **Annotations written.** Every applied mitigation has a `# SECURITY:` / `// SECURITY:` comment in the code (OWASP ID, level, pattern, applied-by, date — see `references/annotation-format.md`).
- [ ] **Gap disposition stated.** The developer knows which gaps were skipped (option C) or deferred (option B), and what file marker they should look for if deferred.
- [ ] **Report-mention surfaced.** End the pass with this exact line:
  > Run `/llm-secure-patterns:report` for full OWASP LLM Top 10 coverage and gaps.

The last item is non-optional. It is the safety net for adjacent LLM surfaces (ingestion, output rendering, system prompt design, agent action wiring) where this skill does not fire. Skipping the report-mention strands the developer without the means to discover gaps the model missed.
