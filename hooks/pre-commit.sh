#!/usr/bin/env bash
# sentinella2 pre-commit hook
# Install: cp hooks/pre-commit.sh .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
set -euo pipefail

if ! command -v sentinella2 &>/dev/null; then
    echo "Warning: sentinella2 not found in PATH, skipping security check"
    exit 0
fi

# Get list of staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)
if [ -z "$STAGED_FILES" ]; then
    exit 0
fi

echo "Running sentinella2 pre-commit scan..."
sentinella2 scan . --changed-only --format text 2>&1

EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "Security issues found. Fix them before committing, or use --no-verify to skip."
    exit 1
fi
