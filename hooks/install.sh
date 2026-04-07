#!/usr/bin/env bash
# sentinella2 Git hooks installer
# Usage: sentinella2 hooks install  OR  bash hooks/install.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GIT_DIR="$(git rev-parse --git-dir 2>/dev/null)" || {
    echo "Error: not a git repository" >&2
    exit 1
}

HOOKS_DIR="$GIT_DIR/hooks"

echo "Installing sentinella2 Git hooks..."

# Install pre-commit hook
cat > "$HOOKS_DIR/pre-commit" << 'HOOK'
#!/usr/bin/env bash
# sentinella2 pre-commit hook: quick scan of staged files
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
HOOK
chmod +x "$HOOKS_DIR/pre-commit"

# Install pre-push hook
cat > "$HOOKS_DIR/pre-push" << 'HOOK'
#!/usr/bin/env bash
# sentinella2 pre-push hook: full Tier 1 scan
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
HOOK
chmod +x "$HOOKS_DIR/pre-push"

echo "Hooks installed successfully:"
echo "  pre-commit: quick scan of staged files"
echo "  pre-push:   full Tier 1 scan"
