#!/usr/bin/env bash
# sentinella2 pre-push hook
# Install: cp hooks/pre-push.sh .git/hooks/pre-push && chmod +x .git/hooks/pre-push
set -euo pipefail

if ! command -v sentinella2 &>/dev/null; then
    echo "Warning: sentinella2 not found in PATH, skipping security check"
    exit 0
fi

echo "Running sentinella2 pre-push scan..."
sentinella2 scan . --format text 2>&1

EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "Security issues found. Fix them before pushing, or use --no-verify to skip."
    exit 1
fi
