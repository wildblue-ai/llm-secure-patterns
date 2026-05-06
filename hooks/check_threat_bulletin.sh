#!/usr/bin/env bash
# llm-secure-patterns: SessionStart hook
# Checks THREAT_BULLETIN.md for new advisories and prints notifications.
# Read-only — no network calls, no dynamic execution, no untrusted input.

set -euo pipefail

BULLETIN_FILE="${CLAUDE_PLUGIN_ROOT}/THREAT_BULLETIN.md"

if [[ ! -f "$BULLETIN_FILE" ]]; then
  exit 0
fi

# Strip HTML comments before scanning (template entries live inside <!-- --> blocks)
CLEAN_CONTENT=$(sed '/<!--/,/-->/d' "$BULLETIN_FILE")

# Count entries tagged [ADVISORY] (unpatched) or [NEW] (recently patched)
ADVISORY_COUNT=$(echo "$CLEAN_CONTENT" | grep -c '^## \[ADVISORY\]' 2>/dev/null || true)
NEW_COUNT=$(echo "$CLEAN_CONTENT" | grep -c '^## \[NEW\]' 2>/dev/null || true)
ADVISORY_COUNT=${ADVISORY_COUNT:-0}
NEW_COUNT=${NEW_COUNT:-0}

TOTAL=$((ADVISORY_COUNT + NEW_COUNT))

if [[ "$TOTAL" -eq 0 ]]; then
  exit 0
fi

# Print summary
echo ""
echo "llm-secure-patterns: ${TOTAL} security advisory/advisories"

# Print each advisory/new entry summary
while IFS= read -r heading; do
  if echo "$heading" | grep -q '\[ADVISORY\]'; then
    tag="[ADVISORY]"
    title="${heading#*\[ADVISORY\] }"
  else
    tag="[NEW]"
    title="${heading#*\[NEW\] }"
  fi
  echo "  ${tag} ${title}"
done < <(echo "$CLEAN_CONTENT" | grep '^## \[\(ADVISORY\|NEW\)\]' 2>/dev/null)

echo ""
echo "Run /llm-secure-patterns:report to check if your project is affected."
echo ""
