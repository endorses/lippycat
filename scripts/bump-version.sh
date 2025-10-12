#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Show usage
usage() {
    echo "Usage: $0 [flags] <new-version> [changelog-message]"
    echo ""
    echo "Flags:"
    echo "  -h, --help   Show this help message"
    echo "  -y, --yes    Skip all prompts and auto-confirm"
    echo "  -t, --tag    Create git tag (only with -y flag)"
    echo ""
    echo "Examples:"
    echo "  $0 0.2.6 'Bug fixes and improvements'"
    echo "  $0 -y 0.2.6 'Bug fixes and improvements'"
    echo "  $0 -y -t 0.3.0 'Major feature release'"
    echo ""
    echo "The script will:"
    echo "  1. Update VERSION file"
    echo "  2. Update README.md status line"
    echo "  3. Add basic changelog entry in README.md"
    echo "  4. Show diff and prompt for commit (or auto-commit with -y)"
    echo "  5. Optionally create git tag (with -t)"
    exit 1
}

# Parse flags
AUTO_YES=false
CREATE_TAG=false

while [[ "$1" =~ ^- ]]; do
    case "$1" in
        -h|--help)
            usage
            ;;
        -y|--yes)
            AUTO_YES=true
            shift
            ;;
        -t|--tag)
            CREATE_TAG=true
            shift
            ;;
        *)
            echo "Unknown flag: $1"
            exit 1
            ;;
    esac
done

# Check arguments
if [ -z "$1" ]; then
    usage
fi

NEW_VERSION="$1"
CHANGELOG_MSG="${2:-Update to version $NEW_VERSION}"
DATE=$(date +%Y-%m-%d)

# Validate version format
if ! [[ "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo -e "${RED}Error: Version must be in format X.Y.Z (e.g., 0.2.6)${NC}"
    exit 1
fi

# Get current version
CURRENT_VERSION=$(cat VERSION | tr -d '\n')
echo -e "${BLUE}Current version: $CURRENT_VERSION${NC}"
echo -e "${BLUE}New version:     $NEW_VERSION${NC}"
echo ""

# Confirm (unless auto-yes)
if [ "$AUTO_YES" = false ]; then
    read -p "Continue? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 0
    fi
fi

echo ""
echo -e "${YELLOW}Updating files...${NC}"

# Update VERSION file
echo "$NEW_VERSION" > VERSION
echo -e "${GREEN}✓${NC} Updated VERSION file"

# Update README.md status line
sed -i "s/^**Status:** v[0-9.]*/**Status:** v$NEW_VERSION/" README.md
echo -e "${GREEN}✓${NC} Updated README.md status line"

# Add changelog entry (user should edit this to add proper details)
# Find the line with "## Changelog" and add new version after it
sed -i "/## Changelog/a\\
\\
### v$NEW_VERSION ($DATE)\\
- $CHANGELOG_MSG\\
- TODO: Add detailed changelog entries" README.md
echo -e "${GREEN}✓${NC} Added changelog entry in README.md"

echo ""
echo -e "${YELLOW}⚠️  IMPORTANT: Edit README.md to add detailed changelog entries!${NC}"
echo ""

# Show diff
echo -e "${BLUE}Changes:${NC}"
echo "----------------------------------------"
git diff VERSION README.md
echo "----------------------------------------"
echo ""

# Prompt to commit (unless auto-yes)
if [ "$AUTO_YES" = false ]; then
    read -p "Commit these changes? (y/n) " -n 1 -r
    echo
    SHOULD_COMMIT=$REPLY
else
    SHOULD_COMMIT="y"
fi

if [[ $SHOULD_COMMIT =~ ^[Yy]$ ]]; then
    git add VERSION README.md
    git commit -m "chore: bump version to $NEW_VERSION

Release $NEW_VERSION includes:
- $CHANGELOG_MSG

🤖 Generated with [Claude Code](https://claude.com/claude-code)

Co-Authored-By: Claude <noreply@anthropic.com>"
    echo -e "${GREEN}✓${NC} Changes committed"

    # Create tag if requested
    if [ "$CREATE_TAG" = true ]; then
        git tag -a "v$NEW_VERSION" -m "Release version $NEW_VERSION"
        echo -e "${GREEN}✓${NC} Tag created: v$NEW_VERSION"
        echo ""
        echo -e "${YELLOW}Don't forget to push:${NC}"
        echo "  git push origin main"
        echo "  git push origin v$NEW_VERSION"
    elif [ "$AUTO_YES" = false ]; then
        # Interactive mode - ask about tag
        echo ""
        read -p "Create git tag v$NEW_VERSION? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            git tag -a "v$NEW_VERSION" -m "Release version $NEW_VERSION"
            echo -e "${GREEN}✓${NC} Tag created: v$NEW_VERSION"
            echo ""
            echo -e "${YELLOW}Don't forget to push:${NC}"
            echo "  git push origin main"
            echo "  git push origin v$NEW_VERSION"
        fi
    fi
else
    echo ""
    echo -e "${YELLOW}Changes not committed. You can review and commit manually:${NC}"
    echo "  git add VERSION README.md"
    echo "  git commit -m 'chore: bump version to $NEW_VERSION'"
    echo "  git tag -a v$NEW_VERSION -m 'Release version $NEW_VERSION'"
fi

echo ""
echo -e "${GREEN}✓ Version bump complete!${NC}"
