"""
token_budget_limiter.py — Token-budget rate limiting for LLM API endpoints
Part of llm-secure-patterns (https://github.com/wildblue-ai/llm-secure-patterns)

⚠️ SINGLE-PROCESS ONLY — DEMONSTRATION CODE
The TokenBudgetLimiter and SpendMonitor classes below hold state in
in-process Python dicts/lists. They silently degrade to per-worker limits
under PM2, Gunicorn, uWSGI, k8s, or any multi-process deployment, leaving
the configured limits ineffective at the service level. Use Redis (with
INCRBY + TTL or atomic Lua scripts) or an equivalent shared store for
production. See LLM Endpoint Hardening SKILL.md "Production deployment"
for the required external-store interface.

Effectiveness: MODERATE — mitigates denial-of-wallet and basic abuse by limiting
    per-user token consumption and total spend, but sophisticated attackers may
    find creative bypass patterns
Evidence: OWASP LLM10, documented denial-of-wallet attack patterns
Known bypasses: Distributed attacks across many accounts, token estimation
    inaccuracies exploited to exceed true budget
Requires layering with: Authentication (this template assumes authenticated user IDs),
    input sanitization (Skill 1), output validation (Skill 3)

This template implements Level B (Moderate) token-budget rate limiting
as DEMONSTRATION code only. Production deployments must use a shared,
persistent store (Redis, database) — see banner above.
Provided as-is — see SCOPE.md for limitations.
"""

from __future__ import annotations

import math
import time
from collections import OrderedDict
from typing import Dict, List, Optional, Tuple


def estimate_tokens(text: str, use_unsafe_heuristic: bool = False) -> int:
    """Rough token estimation based on character count.

    BY DEFAULT THIS RAISES NotImplementedError. The character-count heuristic
    systematically underestimates tokens for non-Latin scripts (CJK, emoji,
    symbol-heavy input) by 2–4x and is therefore a documented bypass vector
    for any budget enforcement built on top of it. Callers must either:

      1. (Preferred) Use the provider's real tokenizer:
         - Claude: client.messages.count_tokens() (Anthropic SDK).
           Do NOT use tiktoken for Claude — it is OpenAI's tokenizer and
           gives incorrect counts.
         - OpenAI: tiktoken.
         - Other providers: their native tokenizer.
      2. Opt in to the unsafe heuristic by passing
         use_unsafe_heuristic=True. When opted in, the function applies
         a 2x safety multiplier in code (i.e. it returns a deliberate
         overestimate) so a downstream budget check is less likely to
         miss a real overrun. Even with the multiplier, do not use this
         path on non-English traffic or for billing-grade enforcement.

    Args:
        text: Input text to estimate.
        use_unsafe_heuristic: Must be True to use the len/4 heuristic.

    Raises:
        NotImplementedError: when use_unsafe_heuristic is False (default).
    """
    if not use_unsafe_heuristic:
        raise NotImplementedError(
            "estimate_tokens: the len/4 heuristic is a documented bypass "
            "vector (CJK / emoji / symbol-heavy input under-counts by 2–4x). "
            "Use a real tokenizer (client.messages.count_tokens for Claude; "
            "tiktoken for OpenAI; provider-native otherwise) OR opt in by "
            "passing use_unsafe_heuristic=True to acknowledge the risk; the "
            "opt-in path applies a 2x safety multiplier to overestimate."
        )
    # 2x safety multiplier applied in code as the default for opt-in callers.
    return max(1, math.ceil(len(text) / 4) * 2)


# NOTE: This module caps input tokens but does not enforce max_tokens on
# model responses. Always set the max_tokens parameter when calling LLM APIs
# to cap output cost. An attacker can trigger unbounded output generation
# ("write the longest possible story") which costs more than the input.


class TokenBudgetLimiter:
    """Per-user token-budget rate limiter — DEMONSTRATION ONLY.

    Tracks token consumption per user over a rolling 1-hour window and
    request count over a rolling 1-minute window. Denies requests that
    would exceed either budget.

    ⚠️ SINGLE-PROCESS ONLY — see the file-level banner. This class
    holds state in a Python dict and is intended for demonstration,
    local development, and tests only. Production deployments must use
    a shared store (Redis, database).

    WARNING — KNOWN LIMITATIONS:
    - TOCTOU: check_budget and record_usage are not atomic. Under concurrent
      load, multiple requests can pass check_budget before any calls
      record_usage, allowing budget overruns. For production, use an atomic
      check-and-reserve pattern (e.g., Redis MULTI/EXEC or Lua scripting).
    - SINGLE-PROCESS ONLY: In-memory state is not shared across workers or
      pods. In multi-process deployments (gunicorn, k8s), each instance
      maintains independent state, rendering all budget controls ineffective.
      Use Redis or a shared database for production deployments.
    - MEMORY: Without a cap, the _usage dict can be grown without bound by
      an attacker spoofing many unique user_id values until OOM. This class
      defaults to a max_tracked_users LRU cap; eviction drops the oldest
      user's history, which means an evicted user starts a new rolling
      window on their next request. For production, prefer Redis with key
      expiration so eviction is time-based, not LRU-based.
    """

    def __init__(
        self,
        max_tokens_per_hour: int = 100_000,
        max_requests_per_minute: int = 20,
        max_tracked_users: int = 100_000,
    ) -> None:
        self.max_tokens_per_hour: int = max_tokens_per_hour
        self.max_requests_per_minute: int = max_requests_per_minute
        self.max_tracked_users: int = max_tracked_users
        # OrderedDict gives O(1) LRU eviction via move_to_end / popitem(last=False).
        # Maps user_id -> list of (timestamp, token_count) tuples.
        self._usage: "OrderedDict[str, List[Tuple[float, int]]]" = OrderedDict()

    def _touch(self, user_id: str) -> None:
        """Mark user_id as most-recently used and evict if over the cap.

        Cap-based eviction mitigates the unbounded-growth attack where a
        spoofed-id flood exhausts memory. See class docstring for tradeoffs.
        """
        if user_id in self._usage:
            self._usage.move_to_end(user_id)
        elif len(self._usage) >= self.max_tracked_users:
            self._usage.popitem(last=False)

    def _cleanup(self, user_id: str, now: float) -> None:
        """Remove entries older than 1 hour for the given user."""
        if user_id not in self._usage:
            return
        one_hour_ago = now - 3600
        self._usage[user_id] = [
            (ts, tokens)
            for ts, tokens in self._usage[user_id]
            if ts > one_hour_ago
        ]

    def check_budget(
        self, user_id: str, estimated_tokens: int
    ) -> Tuple[bool, str]:
        """Check if user has budget remaining for the estimated token count.

        Returns:
            (allowed, reason_if_denied) — allowed is True if the request
            should proceed, False with a reason string if denied.
        """
        now = time.time()
        self._touch(user_id)
        self._cleanup(user_id, now)

        entries = self._usage.get(user_id, [])

        # Check token budget (rolling 1-hour window)
        tokens_used = sum(tokens for _, tokens in entries)
        if tokens_used + estimated_tokens > self.max_tokens_per_hour:
            return (
                False,
                f"Token budget exceeded: {tokens_used}/{self.max_tokens_per_hour} "
                f"tokens used this hour, request needs ~{estimated_tokens} more",
            )

        # Check request count (rolling 1-minute window)
        one_minute_ago = now - 60
        requests_this_minute = sum(
            1 for ts, _ in entries if ts > one_minute_ago
        )
        if requests_this_minute >= self.max_requests_per_minute:
            return (
                False,
                f"Rate limit exceeded: {requests_this_minute}/{self.max_requests_per_minute} "
                f"requests this minute",
            )

        return (True, "")

    def record_usage(self, user_id: str, tokens_used: int) -> None:
        """Record actual token usage after an LLM call completes.

        Call this with the actual token count returned by the LLM API,
        not the estimate. This ensures budget tracking reflects real cost.
        """
        now = time.time()
        self._touch(user_id)
        self._cleanup(user_id, now)
        if user_id not in self._usage:
            self._usage[user_id] = []
        self._usage[user_id].append((now, tokens_used))

    def get_usage_summary(self, user_id: str) -> dict:
        """Return a summary of the user's current usage.

        Returns:
            dict with tokens_used_this_hour, requests_this_minute,
            and budget_remaining.
        """
        now = time.time()
        self._cleanup(user_id, now)

        entries = self._usage.get(user_id, [])
        tokens_used = sum(tokens for _, tokens in entries)

        one_minute_ago = now - 60
        requests_this_minute = sum(
            1 for ts, _ in entries if ts > one_minute_ago
        )

        return {
            "tokens_used_this_hour": tokens_used,
            "requests_this_minute": requests_this_minute,
            "budget_remaining": max(0, self.max_tokens_per_hour - tokens_used),
        }


class SpendMonitor:
    """Spend detection with an automatic circuit breaker — DEMONSTRATION ONLY.

    Tracks total token usage and estimated cost over a rolling 1-hour window.
    When cumulative spend exceeds the configured budget, the circuit breaker
    flips and subsequent requests should be denied at the call site.

    IMPORTANT — this is detection, not prevention:
    - The breaker fires AFTER the budget is exceeded. A single oversized
      request (e.g. one $500 call against a $100/hour cap) commits the
      full $500 of spend before the next request is denied.
    - In-flight requests that have already passed the breaker check are
      not cancelled. Under bursty concurrent load, many requests can
      pass is_kill_switch_triggered() returning False before any of them
      record spend, allowing 10x–100x budget overruns in a single second.
      This is the same TOCTOU race documented on TokenBudgetLimiter; for
      production, use atomic check-and-reserve (Redis MULTI/EXEC, Lua) and
      enforce hard per-request cost ceilings (max_tokens, model selection)
      so a single request cannot exceed the configured tolerance.

    ⚠️ SINGLE-PROCESS ONLY — see file-level banner. Production deployments
    must use a shared store (Redis, database) and integrate the breaker with
    your API gateway or load balancer.
    """

    def __init__(
        self,
        hourly_budget_usd: float = 100.0,
        cost_per_1k_tokens: Optional[float] = None,
    ) -> None:
        if cost_per_1k_tokens is None:
            raise ValueError(
                "SpendMonitor: cost_per_1k_tokens is required. LLM pricing varies "
                "by 100x+ across models — a silent default would guarantee wrong "
                "spend tracking. Look up the rate for your specific model "
                "(see https://docs.anthropic.com/en/docs/about-claude/models for "
                "Claude pricing) and pass it explicitly."
            )
        self.hourly_budget_usd: float = hourly_budget_usd
        self.cost_per_1k_tokens: float = cost_per_1k_tokens
        # List of (timestamp, token_count) tuples
        self._records: List[Tuple[float, int]] = []

    def _cleanup(self, now: float) -> None:
        """Remove entries older than 1 hour."""
        one_hour_ago = now - 3600
        self._records = [
            (ts, tokens)
            for ts, tokens in self._records
            if ts > one_hour_ago
        ]

    def record_spend(self, tokens: int) -> None:
        """Record token usage for spend tracking."""
        now = time.time()
        self._cleanup(now)
        self._records.append((now, tokens))

    def check_budget(self) -> Tuple[bool, float, float]:
        """Check if spend is within budget.

        Returns:
            (within_budget, spent_usd, limit_usd)
        """
        now = time.time()
        self._cleanup(now)

        total_tokens = sum(tokens for _, tokens in self._records)
        spent = (total_tokens / 1000) * self.cost_per_1k_tokens

        return (spent <= self.hourly_budget_usd, spent, self.hourly_budget_usd)

    def is_kill_switch_triggered(self) -> bool:
        """Return True if spend exceeds the hourly budget.

        When this returns True, the service should deny all new requests
        until spend drops back within budget (as old entries expire from
        the rolling window) or an operator manually resets the limit.

        This is the spend-detection / circuit-breaker check: callers will
        always have already overspent by some amount when it first returns
        True, and any in-flight request that already passed this check
        will still complete. See the SpendMonitor class docstring.
        """
        within_budget, _, _ = self.check_budget()
        return not within_budget


if __name__ == "__main__":
    print("=== Token Budget Limiter Demo ===\n")

    # Create a limiter with small limits for demonstration
    limiter = TokenBudgetLimiter(
        max_tokens_per_hour=1000,
        max_requests_per_minute=5,
    )

    user = "user-123"

    # 1. Show a request being allowed
    message = "What is the capital of France?"
    est = estimate_tokens(message, use_unsafe_heuristic=True)
    allowed, reason = limiter.check_budget(user, est)
    print(f"Request: '{message}'")
    print(f"  Estimated tokens: {est}")
    print(f"  Allowed: {allowed}")
    print(f"  Summary: {limiter.get_usage_summary(user)}")

    # Record usage (simulate LLM returning actual token count)
    actual_tokens = 150
    limiter.record_usage(user, actual_tokens)
    print(f"  Recorded {actual_tokens} actual tokens used")
    print(f"  Summary after: {limiter.get_usage_summary(user)}\n")

    # 2. Consume most of the budget
    print("--- Consuming budget with large requests ---")
    limiter.record_usage(user, 400)
    limiter.record_usage(user, 400)
    summary = limiter.get_usage_summary(user)
    print(f"  Summary: {summary}\n")

    # 3. Show a request being denied when budget is exceeded
    big_message = "x" * 400  # ~100 estimated tokens
    est = estimate_tokens(big_message, use_unsafe_heuristic=True)
    allowed, reason = limiter.check_budget(user, est)
    print(f"Request: (large message, ~{est} estimated tokens)")
    print(f"  Allowed: {allowed}")
    print(f"  Reason: {reason}\n")

    # 4. Show spend monitor detecting overspend
    print("=== Spend Monitor Demo ===\n")

    monitor = SpendMonitor(
        hourly_budget_usd=0.01,  # Very small budget for demo
        cost_per_1k_tokens=0.01,
    )

    # Record some spend
    monitor.record_spend(500)
    within, spent, limit = monitor.check_budget()
    print(f"After 500 tokens:")
    print(f"  Within budget: {within}")
    print(f"  Spent: ${spent:.4f} / ${limit:.4f}")
    print(f"  Kill switch: {monitor.is_kill_switch_triggered()}\n")

    # Push over budget
    monitor.record_spend(1500)
    within, spent, limit = monitor.check_budget()
    print(f"After 2000 total tokens:")
    print(f"  Within budget: {within}")
    print(f"  Spent: ${spent:.4f} / ${limit:.4f}")
    print(f"  Kill switch: {monitor.is_kill_switch_triggered()}")
