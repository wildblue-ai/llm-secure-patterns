"""
output_schema_validator.py — Output validation and sanitization for LLM responses
Part of llm-secure-patterns (https://github.com/wildblue-ai/llm-secure-patterns)

Effectiveness: MODERATE — flags known dangerous patterns (XSS, PII, URLs, schema violations),
    novel attack patterns and sophisticated exfiltration may evade detection
Evidence: OWASP LLM05, standard XSS prevention practices
Known bypasses: Novel encoding in output, semantic exfiltration that doesn't match patterns,
    polyglot payloads
Requires layering with: Input sanitization (Skill 1), system prompt design (Skill 4),
    Content Security Policy headers (Level C)

This template implements Level B (Moderate) output validation.
Provided as-is — see SCOPE.md for limitations.
"""

# SECURITY: LLM05 (Improper Output Handling) — Schema validation, HTML escaping, PII scanning, URL detection, prompt leakage detection
# OWASP: Top 10 for LLM Applications 2025 (v2025.1, published November 2025)
# Confidence: MODERATE — flags known dangerous patterns; novel attacks may evade detection
# Level: Standard
# Pattern: output_schema_validator
# Requires layering: Input sanitization (Skill 1), system prompt design (Skill 4), CSP headers (Level C)
# Applied by: llm-secure-patterns v0.9.0 / Output Validation and Sanitization
# Date applied: 2026-03-30

import html
import json
import re
from typing import Any, TypedDict


class Finding(TypedDict):
    """Structured result emitted by scan functions.

    type: stable identifier (e.g. "pii_ssn", "url_dangerous_scheme"). Callers
        should match on this field rather than on message text.
    severity: "critical" or "warning". Callers use this for fail-closed logic.
    match: the matched substring (may be truncated for credential-like matches).
    message: human-readable description for display/logging.
    """

    type: str
    severity: str
    match: str
    message: str


def validate_json_schema(
    response: str, schema: dict, allow_additional_properties: bool = False
) -> tuple[bool, Any, list[str]]:
    """Parse JSON response and validate against a schema dict.

    Checks required keys exist and are non-empty. Checks types match
    when 'properties' with 'type' mappings are provided in the schema.

    By default (`allow_additional_properties=False`), unknown top-level
    fields are REJECTED. This mitigates prototype-pollution / class-pollution
    style attacks where the model emits extra keys such as `__proto__`,
    `__class__`, `constructor`, or attacker-controlled keys that downstream
    code then dereferences. The previous starter accepted unknown keys —
    that behaviour is opt-in now via allow_additional_properties=True.

    Returns:
        (valid, parsed_data_or_None, error_list)
    """
    try:
        data = json.loads(response)
    except json.JSONDecodeError as e:
        return False, None, [f"Invalid JSON: {e}"]

    if not isinstance(data, dict):
        return False, None, ["Expected a JSON object at top level"]

    errors: list[str] = []

    # Check required keys
    for key in schema.get("required", []):
        if key not in data:
            errors.append(f"Missing required field: {key}")
        elif data[key] is None or data[key] == "":
            errors.append(f"Required field is null or empty: {key}")

    # Reject unknown top-level fields unless explicitly allowed.
    # Pollution-relevant keys (__proto__, __class__, constructor) and any
    # key not in the declared schema fail closed by default.
    properties = schema.get("properties", {})
    if not allow_additional_properties:
        declared_keys = set(properties.keys()) | set(schema.get("required", []))
        for key in data.keys():
            if key not in declared_keys:
                errors.append(
                    f"Unexpected top-level field: '{key}' "
                    f"(reject unknown keys; pass allow_additional_properties=True to disable)"
                )

    # Check types if properties are defined
    type_map = {
        "string": str,
        "number": (int, float),
        "integer": int,
        "boolean": bool,
        "array": list,
        "object": dict,
    }
    for key, prop_def in properties.items():
        if key in data and data[key] is not None:
            expected_type_name = prop_def.get("type")
            if expected_type_name and expected_type_name in type_map:
                expected_type = type_map[expected_type_name]
                if not isinstance(data[key], expected_type):
                    errors.append(
                        f"Field '{key}' expected type '{expected_type_name}', "
                        f"got '{type(data[key]).__name__}'"
                    )

    if errors:
        return False, None, errors
    return True, data, []


def escape_json_field_values(data: Any) -> Any:
    """Recursively HTML-escape string values inside a parsed JSON structure.

    Use this on parsed JSON BEFORE rendering individual field values into
    HTML text nodes. `validate_llm_output` returns a `sanitized` string that
    is the entire raw response HTML-escaped — but callers who follow the
    schema path use parsed `data["field"]` values, which are NOT escaped.
    Walking the structure with this helper closes that gap.

    Only escapes strings; preserves numbers, booleans, lists, and dicts
    (recurses into the latter two). Like `escape_html_text_node`, this is
    safe for HTML text-node insertion only — attribute, JS, CSS, and URL
    contexts require their own escaping.
    """
    if isinstance(data, str):
        return html.escape(data, quote=True)
    if isinstance(data, dict):
        return {k: escape_json_field_values(v) for k, v in data.items()}
    if isinstance(data, list):
        return [escape_json_field_values(item) for item in data]
    return data


def escape_html_text_node(text: str) -> str:
    """Escape HTML entities for safe insertion into an HTML text node.

    Escapes &, <, >, double quotes, and single quotes. Does NOT strip tags —
    escapes them so they display as text.

    Designed to mitigate XSS risk for HTML text-node insertion only. Not safe for attribute, JS, CSS, or URL
    contexts — those require context-specific escaping (e.g., attribute-value
    escaping, JS string escaping, CSS escaping, URL percent-encoding).
    """
    return html.escape(text, quote=True)


def scan_for_urls(text: str) -> list[Finding]:
    """Detect URLs in output.

    Emits findings with types:
        url_dangerous_scheme (critical) — javascript: or data: URIs
        url_http             (warning)  — http/https/ftp/blob URLs
        url_protocol_relative (warning) — //example.com/ style URLs
    """
    findings: list[Finding] = []

    url_pattern = re.compile(
        r"(?:https?://|ftp://|javascript:|data:|blob://)[^\s\)<>\"\'\]]+",
        re.IGNORECASE,
    )
    for url in url_pattern.findall(text):
        lower = url.lower()
        if lower.startswith("javascript:") or lower.startswith("data:"):
            finding_type = "url_dangerous_scheme"
            severity = "critical"
        else:
            finding_type = "url_http"
            severity = "warning"
        findings.append(Finding(
            type=finding_type,
            severity=severity,
            match=url,
            message=(
                f"URL detected in output: {url} "
                f"— verify before rendering as clickable link"
            ),
        ))

    # Protocol-relative URLs (//example.com/..., ///host/path, etc.)
    # Flag all `//`-prefixed URL-like strings uniformly. The previous
    # `///` skip incorrectly excluded triple-slash forms which can be
    # valid protocol-relative URLs (file:/// notation, server-relative
    # references in some contexts) and should be inspected, not skipped.
    for url in re.findall(r"//[^\s\)<>\"\'\]]+", text):
        findings.append(Finding(
            type="url_protocol_relative",
            severity="warning",
            match=url,
            message=(
                f"Protocol-relative URL detected in output: {url} "
                f"— verify before rendering as clickable link"
            ),
        ))

    return findings


def scan_for_pii(text: str) -> list[Finding]:
    """Detect PII patterns in LLM output.

    Scans for:
    - Email addresses (pii_email)
    - SSN patterns XXX-XX-XXXX (pii_ssn)
    - US phone number patterns (pii_phone)
    - Common API key patterns (api_key_openai, api_key_aws, api_key_generic)

    All emitted findings have severity="critical".
    """
    findings: list[Finding] = []

    # Email addresses
    for email in re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", text):
        findings.append(Finding(
            type="pii_email",
            severity="critical",
            match=email,
            message=f"Possible email address in output: {email}",
        ))

    # SSN pattern (XXX-XX-XXXX) — check before phone to avoid overlap
    for ssn in re.findall(r"\b\d{3}-\d{2}-\d{4}\b", text):
        findings.append(Finding(
            type="pii_ssn",
            severity="critical",
            match=ssn,
            message=f"Possible SSN pattern in output: {ssn}",
        ))

    # Phone numbers (US patterns)
    for phone in re.findall(
        r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", text
    ):
        if re.match(r"^\d{3}-\d{2}-\d{4}$", phone.strip()):
            continue
        findings.append(Finding(
            type="pii_phone",
            severity="critical",
            match=phone,
            message=f"Possible phone number in output: {phone}",
        ))

    # API key patterns. Patterns cover common shapes only — production
    # detection should delegate to a maintained scanner (detect-secrets,
    # gitleaks, truffleHog) with active detector sets. The lookarounds use
    # an explicit "non-key character" class instead of `\b` because `\b`
    # treats `-` as a word boundary and would silently miss formats like
    # `sk-ant-api03-...` and `sk-proj-...` which contain hyphens. Order
    # matters: more specific prefixes (sk-ant-) are matched before more
    # general ones (sk-) to attribute findings to the right provider.
    _LB = r"(?<![A-Za-z0-9_\-])"
    _LA = r"(?![A-Za-z0-9_\-])"
    api_key_patterns = [
        # Anthropic — sk-ant-api03-..., sk-ant-... (hyphens + underscores in body).
        (rf"{_LB}sk-ant-[A-Za-z0-9_\-]{{20,}}{_LA}", "api_key_anthropic", "Anthropic-style API key"),
        # OpenAI — sk-proj-..., sk-..., sk-svcacct-... (also hyphens in body).
        (rf"{_LB}sk-[A-Za-z0-9_\-]{{20,}}{_LA}", "api_key_openai", "OpenAI-style API key"),
        (r"\bAKIA[A-Z0-9]{16}\b", "api_key_aws", "AWS access key"),
        # Generic `key-...` pattern is illustrative only and will false-positive on
        # legitimate prose (`key-performance-indicators-...`). Keep it as a starter
        # signal; for production use a maintained scanner.
        (rf"{_LB}key-[A-Za-z0-9_\-]{{20,}}{_LA}", "api_key_generic", "Generic API key (false-positive prone)"),
    ]
    # Dedup across patterns by matched substring: an Anthropic key
    # (`sk-ant-...`) also matches the OpenAI pattern (`sk-...`); we want to
    # attribute it to the most specific match (Anthropic, listed first).
    seen_keys: set[str] = set()
    for pattern, finding_type, description in api_key_patterns:
        for key in re.findall(pattern, text):
            if key in seen_keys:
                continue
            seen_keys.add(key)
            findings.append(Finding(
                type=finding_type,
                severity="critical",
                match=key,
                message=f"Possible {description} in output: {key[:12]}...",
            ))

    return findings


def scan_for_prompt_leakage(
    text: str, prompt_fragments: list[str] | None = None
) -> list[Finding]:
    """Check if output contains system prompt fragments or leakage indicators.

    Emits findings with types:
        prompt_leakage_indicator (critical) — generic leakage phrases
        prompt_leakage_fragment  (critical) — caller-supplied prompt text

    Note: This is a low-fidelity heuristic based on keyword matching.
    Paraphrasing, encoding, translation, or obfuscation trivially bypasses
    these indicators. Use as one layer in defense-in-depth, not as a
    reliable control.
    """
    findings: list[Finding] = []
    text_lower = text.lower()

    leakage_indicators = [
        "my instructions are",
        "my system prompt is",
        "i was told to",
        "i was instructed to",
        "my original instructions",
        "here are my instructions",
        "my programming says",
        "my rules are",
        "i am programmed to",
        "my guidelines state",
        "the system message says",
        "according to my prompt",
    ]
    for indicator in leakage_indicators:
        if indicator in text_lower:
            findings.append(Finding(
                type="prompt_leakage_indicator",
                severity="critical",
                match=indicator,
                message=(
                    f"Possible prompt leakage detected — output contains: "
                    f"'{indicator}'"
                ),
            ))

    if prompt_fragments:
        for fragment in prompt_fragments:
            if fragment.lower() in text_lower:
                preview = f"{fragment[:50]}{'...' if len(fragment) > 50 else ''}"
                findings.append(Finding(
                    type="prompt_leakage_fragment",
                    severity="critical",
                    match=fragment,
                    message=(
                        f"System prompt fragment detected in output: "
                        f"'{preview}'"
                    ),
                ))

    return findings


def validate_llm_output(
    response: str,
    schema: dict | None = None,
    prompt_fragments: list[str] | None = None,
) -> tuple[bool, str, list[Finding] | list[str]]:
    """Full Level B output validation pipeline.

    Validates schema (if provided), sanitizes HTML, scans for PII,
    URLs, and prompt leakage.

    The returned `sanitized_output` is the entire raw response with HTML
    text-node escaping applied. It is intended for callers that render the
    response as a single text block. CALLERS THAT FOLLOW THE SCHEMA PATH
    (parsing JSON and using individual `data["field"]` values) MUST RUN
    `escape_json_field_values(data)` before rendering those values into
    HTML — `sanitized_output` does not transform the parsed structure.
    See SKILL.md "Escaping parsed field values" for the full pattern.

    Returns:
        (valid, sanitized_output, findings_or_schema_errors)

        On schema failure the third element is a list[str] of schema errors.
        Otherwise it is a list[Finding] of scan results (type/severity/match/
        message). When `schema` is None, schema validation is SKIPPED and
        an explicit `schema_validation_skipped` finding is emitted at
        severity="warning" so callers can detect the omission. Fail-closed
        triggers when any finding has severity="critical".
    """
    # Step 1: Schema validation (fail closed when supplied; warn when omitted).
    findings: list[Finding] = []
    if schema:
        valid, _data, errors = validate_json_schema(response, schema)
        if not valid:
            return False, "", errors
    else:
        findings.append(Finding(
            type="schema_validation_skipped",
            severity="warning",
            match="",
            message=(
                "Schema validation was skipped because no `schema` argument was "
                "supplied. The 'fail closed' framing only applies when a schema "
                "is provided; supply one or rely on output-shape constraints "
                "elsewhere in your pipeline."
            ),
        ))

    # Step 2: Scan raw output BEFORE HTML escaping (scanning escaped text
    # mangles PII/URL matches)
    findings.extend(scan_for_pii(response))
    findings.extend(scan_for_urls(response))
    findings.extend(scan_for_prompt_leakage(response, prompt_fragments))

    # Step 3: HTML sanitization for rendering. This produces a text-node
    # safe rendering of the WHOLE response. For schema-path callers, also
    # use escape_json_field_values() on the parsed dict.
    sanitized = escape_html_text_node(response)

    # Step 4: Fail closed if any finding is critical. Returns empty string
    # so callers cannot accidentally render or forward potentially
    # sensitive output through the success path.
    if any(f["severity"] == "critical" for f in findings):
        return False, "", findings

    return True, sanitized, findings


if __name__ == "__main__":
    print("=" * 60)
    print("Output Schema Validator — Demo")
    print("=" * 60)

    # --- Schema validation: passing ---
    print("\n--- Schema validation (pass) ---")
    good_response = '{"name": "Alice", "age": 30, "role": "engineer"}'
    schema = {
        "required": ["name", "age"],
        "properties": {
            "name": {"type": "string"},
            "age": {"type": "integer"},
            "role": {"type": "string"},
        },
    }
    valid, data, errors = validate_json_schema(good_response, schema)
    print(f"Input:  {good_response}")
    print(f"Valid:  {valid}")
    print(f"Data:   {data}")
    print(f"Errors: {errors}")

    # --- Schema validation: failing ---
    print("\n--- Schema validation (fail — missing field) ---")
    bad_response = '{"name": "Alice"}'
    valid, data, errors = validate_json_schema(bad_response, schema)
    print(f"Input:  {bad_response}")
    print(f"Valid:  {valid}")
    print(f"Errors: {errors}")

    print("\n--- Schema validation (fail — wrong type) ---")
    type_response = '{"name": "Alice", "age": "thirty"}'
    valid, data, errors = validate_json_schema(type_response, schema)
    print(f"Input:  {type_response}")
    print(f"Valid:  {valid}")
    print(f"Errors: {errors}")

    # --- HTML sanitization ---
    print("\n--- HTML sanitization ---")
    xss_output = 'Hello! <script>alert("xss")</script> How can I help?'
    sanitized = escape_html_text_node(xss_output)
    print(f"Input:    {xss_output}")
    print(f"Escaped:  {sanitized}")

    # --- PII detection ---
    print("\n--- PII detection ---")
    pii_output = (
        "The user's email is alice@example.com and their SSN is 123-45-6789. "
        "Their API key is sk-abc123def456ghi789jkl012mno345."
    )
    pii_findings = scan_for_pii(pii_output)
    print(f"Input: {pii_output}")
    for f in pii_findings:
        print(f"  [{f['severity']}] {f['type']}: {f['message']}")

    # --- URL detection ---
    print("\n--- URL detection ---")
    url_output = (
        "Check out https://example.com/safe and also "
        "https://evil.example.com/phish?steal=data for more info."
    )
    url_findings = scan_for_urls(url_output)
    print(f"Input: {url_output}")
    for f in url_findings:
        print(f"  [{f['severity']}] {f['type']}: {f['message']}")

    # --- Prompt leakage detection ---
    print("\n--- Prompt leakage detection ---")
    leaky_output = (
        "Sure! My instructions are to always be helpful. "
        "I was told to never reveal internal guidelines."
    )
    prompt_fragments = ["never reveal internal guidelines", "always be helpful"]
    leakage_findings = scan_for_prompt_leakage(leaky_output, prompt_fragments)
    print(f"Input: {leaky_output}")
    for f in leakage_findings:
        print(f"  [{f['severity']}] {f['type']}: {f['message']}")

    # --- Full pipeline ---
    print("\n--- Full Level B pipeline ---")
    full_response = (
        'Here is the result: {"status": "ok"}. '
        "Contact support@company.com or visit https://help.company.com. "
        "I was instructed to keep responses short."
    )
    valid, sanitized, results = validate_llm_output(
        full_response,
        prompt_fragments=["keep responses short"],
    )
    print(f"Input:     {full_response}")
    print(f"Valid:     {valid}")
    print(f"Sanitized: {sanitized}")
    for r in results:
        if isinstance(r, dict):
            print(f"  [{r['severity']}] {r['type']}: {r['message']}")
        else:
            print(f"  SCHEMA ERROR: {r}")

    print("\n" + "=" * 60)
    print("Demo complete.")
    print("=" * 60)
