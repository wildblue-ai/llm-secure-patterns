#!/usr/bin/env bash
# llm-secure-patterns: Automated manual test runner
# Runs each skill test prompt through Claude Code with the plugin loaded,
# captures full output, and evaluates results.
#
# Usage: ./tests/run-manual-tests.sh [test-number]
#   No args: run all 5 tests
#   With arg: run only that test (e.g., ./tests/run-manual-tests.sh 3)
#
# Results saved to: tests/results/test-N-output.txt and tests/results/test-N-eval.txt

set -euo pipefail

PLUGIN_DIR="${PLUGIN_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
# Resolve to absolute path before any cd changes
RESULTS_DIR="$(cd "$(dirname "$0")" && pwd)/results"
TEST_BASE="${TEST_BASE:-/tmp/llm-sbd-test}"
SELECTED_TEST="${1:-all}"

mkdir -p "$RESULTS_DIR"

echo "============================================"
echo "llm-secure-patterns — Automated Test Runner"
echo "============================================"
echo "Plugin dir: ${PLUGIN_DIR}"
echo "Results dir: ${RESULTS_DIR}"
echo "Test base: ${TEST_BASE}"
echo ""

# Test prompts — include choices so non-interactive mode works
# All tests: Apply security now (A), Level C (High), Skip remaining gaps (C)
declare -a TEST_NAMES=(
  "Secure External Ingestion"
  "LLM Endpoint Hardening"
  "Output Validation"
  "System Prompt Design"
  "Agent Action Surface Control"
)

declare -a TEST_SKILLS=(
  "secure-external-ingestion"
  "llm-endpoint-hardening"
  "output-validation"
  "system-prompt-design"
  "agent-action-surface"
)

declare -a TEST_PROMPTS=(
  "Build a Python script that scrapes product reviews from e-commerce websites and feeds them to Claude API to summarize sentiment. For all llm-secure-patterns security skills: apply security now (option A), choose Level C (High) for all tiers, and skip remaining gaps (option C). After building, show me the # SECURITY: annotations in the code."
  "Build a FastAPI endpoint that forwards user questions to Claude API, deployed as a public API for a mobile app. For all llm-secure-patterns security skills: apply security now (option A), choose Level C (High) for all tiers, and skip remaining gaps (option C). After building, show me the # SECURITY: annotations in the code."
  "Build a web app where AI responses are rendered as HTML in the browser and saved to PostgreSQL. For all llm-secure-patterns security skills: apply security now (option A), choose Level C (High) for all tiers, and skip remaining gaps (option C). After building, show me the # SECURITY: annotations in the code."
  "Write a system prompt for a customer support chatbot that has access to a user database and needs a Stripe API key to process refunds. For all llm-secure-patterns security skills: apply security now (option A), choose Level C (High) for all tiers, and skip remaining gaps (option C). After building, show me the # SECURITY: annotations in the code."
  "Create a multi-agent system where Gemini 2.5 Flash analyzes product images for defects, then Claude processes the analysis to generate a quality report and update inventory via MCP server. For all llm-secure-patterns security skills: apply security now (option A), choose Level C (High) for all tiers, and skip remaining gaps (option C). After building, show me the # SECURITY: annotations in the code."
)

# Evaluation checks — what to look for in output
declare -a EVAL_CHECKS=(
  "SECURITY:|UNTRUSTED|sanitize|encoding|zero.width|token"
  "SECURITY:|JWT|rate.limit|token|kill.switch|budget"
  "SECURITY:|escap|XSS|schema|PII|sanitiz"
  "SECURITY:|credential|API.key|UNTRUSTED|extraction|canary|delimiter"
  "SECURITY:|UNTRUSTED|stage|credential|cross.model|MCP|privilege"
)

run_test() {
  local num=$1
  local idx=$((num - 1))
  local name="${TEST_NAMES[$idx]}"
  local skill="${TEST_SKILLS[$idx]}"
  local prompt="${TEST_PROMPTS[$idx]}"
  local checks="${EVAL_CHECKS[$idx]}"
  local test_dir="${TEST_BASE}/test-${num}"
  local output_file="${RESULTS_DIR}/test-${num}-output.txt"
  local eval_file="${RESULTS_DIR}/test-${num}-eval.txt"

  echo "--------------------------------------------"
  echo "TEST ${num}: ${name}"
  echo "Expected skill: ${skill}"
  echo "--------------------------------------------"

  # 1. Prepare test directory
  rm -rf "$test_dir"
  mkdir -p "$test_dir"
  cd "$test_dir"
  git init -q

  # 2. Run test prompt
  echo "Running prompt (this may take several minutes)..."
  local start_time=$(date +%s)

  claude -p "$prompt" \
    --plugin-dir "$PLUGIN_DIR" \
    --dangerously-skip-permissions \
    --max-turns 50 \
    --output-format text \
    > "$output_file" 2>&1 || true

  local end_time=$(date +%s)
  local duration=$((end_time - start_time))
  echo "Completed in ${duration}s"

  # 3. Evaluate output
  echo "" > "$eval_file"
  echo "TEST ${num}: ${name}" >> "$eval_file"
  echo "Date: $(date)" >> "$eval_file"
  echo "Duration: ${duration}s" >> "$eval_file"
  echo "Test dir: ${test_dir}" >> "$eval_file"
  echo "" >> "$eval_file"

  local pass=0
  local fail=0

  # Check: skill triggered — look for display name in Applied by: line of annotations
  # Also check output text for display name
  echo "--- Skill Triggering ---" >> "$eval_file"
  display_name="${TEST_NAMES[$idx]}"
  if grep -qi "Applied by:.*${display_name}" "$test_dir" -r 2>/dev/null \
     || grep -qi "${display_name}" "$output_file" 2>/dev/null \
     || grep -qi "${skill}" "$output_file" 2>/dev/null; then
    echo "PASS: Skill '${display_name}' invoked" >> "$eval_file"
    pass=$((pass + 1))
  else
    echo "FAIL: Skill '${display_name}' was NOT invoked" >> "$eval_file"
    fail=$((fail + 1))
  fi

  # Check: # SECURITY: annotations in output
  echo "" >> "$eval_file"
  echo "--- SECURITY Annotations ---" >> "$eval_file"
  local annotation_count=$(grep -c "SECURITY:" "$output_file" 2>/dev/null || echo 0)
  if [ "$annotation_count" -gt 0 ]; then
    echo "PASS: Found ${annotation_count} SECURITY annotation(s) in output" >> "$eval_file"
    grep "SECURITY:" "$output_file" >> "$eval_file" 2>/dev/null || true
    pass=$((pass + 1))
  else
    echo "FAIL: No SECURITY annotations found in output" >> "$eval_file"
    fail=$((fail + 1))
  fi

  # Check: # SECURITY: annotations in generated files
  echo "" >> "$eval_file"
  echo "--- SECURITY Annotations in Files ---" >> "$eval_file"
  local file_annotations=$(grep -rn "SECURITY:" "$test_dir" --include="*.py" --include="*.ts" --include="*.js" 2>/dev/null | wc -l || echo 0)
  if [ "$file_annotations" -gt 0 ]; then
    echo "PASS: Found ${file_annotations} SECURITY annotation(s) in generated files" >> "$eval_file"
    grep -rn "SECURITY:" "$test_dir" --include="*.py" --include="*.ts" --include="*.js" >> "$eval_file" 2>/dev/null || true
    pass=$((pass + 1))
  else
    echo "FAIL: No SECURITY annotations in generated files" >> "$eval_file"
    fail=$((fail + 1))
  fi

  # Check: skill-specific patterns in generated FILES (not just output text)
  # Output text may be truncated if max turns hit
  echo "" >> "$eval_file"
  echo "--- Skill-Specific Patterns (in generated files) ---" >> "$eval_file"
  IFS='|' read -ra patterns <<< "$checks"
  for pattern in "${patterns[@]}"; do
    if grep -qriE "$pattern" "$test_dir" --include="*.py" --include="*.ts" --include="*.js" 2>/dev/null; then
      echo "PASS: Found pattern '${pattern}'" >> "$eval_file"
      pass=$((pass + 1))
    else
      echo "FAIL: Missing pattern '${pattern}'" >> "$eval_file"
      fail=$((fail + 1))
    fi
  done

  # Check: report mentioned
  echo "" >> "$eval_file"
  echo "--- Report Mention ---" >> "$eval_file"
  if grep -qi "llm-secure-patterns:report" "$output_file"; then
    echo "PASS: Report command mentioned" >> "$eval_file"
    pass=$((pass + 1))
  else
    echo "FAIL: Report command NOT mentioned" >> "$eval_file"
    fail=$((fail + 1))
  fi

  # Check: skill display name used (not "Skill 1" etc)
  echo "" >> "$eval_file"
  echo "--- Display Name ---" >> "$eval_file"
  if grep -qiE "Skill [0-9]:" "$output_file"; then
    echo "FAIL: Generic 'Skill N:' label found (should use full name)" >> "$eval_file"
    fail=$((fail + 1))
  else
    echo "PASS: No generic 'Skill N:' labels" >> "$eval_file"
    pass=$((pass + 1))
  fi

  # Summary
  local total=$((pass + fail))
  echo "" >> "$eval_file"
  echo "--- SUMMARY ---" >> "$eval_file"
  echo "PASS: ${pass}/${total}" >> "$eval_file"
  echo "FAIL: ${fail}/${total}" >> "$eval_file"

  echo "Result: ${pass}/${total} passed (see ${eval_file})"
  echo ""

  return $fail
}

# Run tests
total_pass=0
total_fail=0

if [ "$SELECTED_TEST" = "all" ]; then
  for i in 1 2 3 4 5; do
    run_test $i || true
  done
else
  run_test "$SELECTED_TEST" || true
fi

# Final summary
echo "============================================"
echo "ALL RESULTS"
echo "============================================"
for i in 1 2 3 4 5; do
  eval_file="${RESULTS_DIR}/test-${i}-eval.txt"
  if [ -f "$eval_file" ]; then
    name="${TEST_NAMES[$((i-1))]}"
    summary=$(grep "^PASS:" "$eval_file" | tail -1)
    echo "Test ${i} (${name}): ${summary}"
  fi
done
echo ""
echo "Full output: ${RESULTS_DIR}/test-N-output.txt"
echo "Evaluations: ${RESULTS_DIR}/test-N-eval.txt"
