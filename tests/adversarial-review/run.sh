#!/usr/bin/env bash
# Adversarial review harness wrapper.
#
# IMPORTANT: Always run from the project root or this directory.
# The script auto-navigates, but if the venv is missing it will
# be recreated here. Do NOT cd elsewhere before running.
#
#   From project root:
#     ./tests/adversarial-review/run.sh
#
#   From this directory:
#     cd tests/adversarial-review
#     ./run.sh
#
# Usage:
#   ./run.sh                              # all skills
#   ./run.sh secure-external-ingestion    # one skill
#   ./run.sh --skip-triage                # reviewers only
#
# First run (or after deleting .venv/) will create a venv and
# install deps (~30 seconds). If you see "[Errno 2] No such file
# or directory" errors, delete .venv/ and re-run — the venv may
# be corrupted or incomplete.
#
#   rm -rf tests/adversarial-review/.venv
#   ./tests/adversarial-review/run.sh

set -euo pipefail
cd "$(dirname "$0")"

VENV=".venv"
if [[ ! -d "$VENV" ]]; then
  echo "Creating venv and installing dependencies..."
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install --quiet --upgrade pip
  "$VENV/bin/pip" install --quiet -r requirements.txt
fi

exec "$VENV/bin/python" driver.py "$@"
