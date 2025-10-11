#!/bin/bash
#
# Install git hooks for lippycat development
#

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "Installing git hooks..."

# Install pre-commit hook
if [ -f "hooks/pre-commit" ]; then
    cp hooks/pre-commit .git/hooks/pre-commit
    chmod +x .git/hooks/pre-commit
    echo -e "${GREEN}✓ Installed pre-commit hook${NC}"
else
    echo -e "${YELLOW}⚠ hooks/pre-commit not found${NC}"
    exit 1
fi

# Check for gitleaks
if command -v gitleaks &> /dev/null; then
    echo -e "${GREEN}✓ gitleaks is installed${NC}"
else
    echo -e "${YELLOW}⚠ gitleaks not found - secret detection will be skipped${NC}"
    echo -e "${YELLOW}  Install from: https://github.com/gitleaks/gitleaks${NC}"
fi

echo ""
echo -e "${GREEN}Git hooks installed successfully!${NC}"
echo ""
echo "The pre-commit hook will:"
echo "  1. Check code formatting (gofmt)"
echo "  2. Scan for secrets (gitleaks)"
echo "  3. Run go vet"
echo ""
echo "To bypass the hook: git commit --no-verify"
