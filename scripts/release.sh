#!/bin/bash
set -e

# Usage: ./scripts/release.sh [patch|minor|major]

TYPE=$1
if [ -z "$TYPE" ]; then
    TYPE="patch"
fi

# Ensure clean state
if [ -n "$(git status --porcelain)" ]; then
    echo "❌ Error: Git working directory not clean."
    exit 1
fi

# Get current version from Cargo.toml
CURRENT_VERSION=$(grep "^version" Cargo.toml | head -n1 | cut -d '"' -f2)
echo "Current version: $CURRENT_VERSION"

# Calculate new version
IFS='.' read -r -a PARTS <<< "$CURRENT_VERSION"
MAJOR=${PARTS[0]}
MINOR=${PARTS[1]}
PATCH=${PARTS[2]}

if [ "$TYPE" == "major" ]; then
    MAJOR=$((MAJOR + 1))
    MINOR=0
    PATCH=0
elif [ "$TYPE" == "minor" ]; then
    MINOR=$((MINOR + 1))
    PATCH=0
else
    PATCH=$((PATCH + 1))
fi

NEW_VERSION="$MAJOR.$MINOR.$PATCH"
echo "New version: $NEW_VERSION"

# Update Cargo.toml
# Use sed generic compatible with both GNU and BSD (macOS)
sed -i.bak "s/^version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/" Cargo.toml
rm Cargo.toml.bak

# Update lockfile
cargo check > /dev/null 2>&1 || true

# Commit and Tag
git add Cargo.toml Cargo.lock
git commit -m "chore: release v$NEW_VERSION"
git tag "v$NEW_VERSION"

echo "✅ Release v$NEW_VERSION prepared."
echo "👉 Run 'git push --follow-tags' to trigger the release workflow."