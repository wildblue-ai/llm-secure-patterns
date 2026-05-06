#!/usr/bin/env bash
# llm-secure-patterns: Eval test runner
# Runs each prompt through Claude Code with the plugin loaded and checks
# if the expected skill was invoked.
#
# Usage: ./tests/run-tests.sh [path-to-plugin-dir]
#
# Requires: claude CLI with --plugin-dir and --dangerously-skip-permissions flags

set -euo pipefail

PLUGIN_DIR="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
PROMPTS_DIR="$(dirname "$0")/prompts"
PASS=0
FAIL=0
TOTAL=0

# Map prompt files to expected skill names
declare -A EXPECTED_SKILLS=(
  ["test-ingestion-trigger.txt"]="secure-external-ingestion"
  ["test-endpoint-trigger.txt"]="llm-endpoint-hardening"
  ["test-output-trigger.txt"]="output-validation"
  ["test-prompt-design-trigger.txt"]="system-prompt-design"
  ["test-agent-surface-trigger.txt"]="agent-action-surface"
)

echo "llm-secure-patterns eval tests"
echo "Plugin dir: ${PLUGIN_DIR}"
echo "================================"
echo ""

for prompt_file in "${PROMPTS_DIR}"/test-*-trigger.txt; do
  filename=$(basename "$prompt_file")
  expected_skill="${EXPECTED_SKILLS[$filename]:-unknown}"
  TOTAL=$((TOTAL + 1))

  echo "Testing: ${filename}"
  echo "  Expected skill: ${expected_skill}"

  # Run Claude Code with the prompt, capture output as stream-json
  prompt=$(cat "$prompt_file")
  output=$(claude -p "$prompt" \
    --plugin-dir "$PLUGIN_DIR" \
    --dangerously-skip-permissions \
    --max-turns 3 \
    --output-format stream-json 2>&1 || true)

  # Check if the expected skill was invoked (look for skill name in output)
  if echo "$output" | grep -q "\"name\":\"${expected_skill}\""; then
    echo "  PASS"
    PASS=$((PASS + 1))
  else
    echo "  FAIL — skill '${expected_skill}' not invoked"
    FAIL=$((FAIL + 1))
  fi
  echo ""
done

echo "================================"
echo "Results: ${PASS}/${TOTAL} passed, ${FAIL} failed"

if [[ "$FAIL" -gt 0 ]]; then
  exit 1
fi
