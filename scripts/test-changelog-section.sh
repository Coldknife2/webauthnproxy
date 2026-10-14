#!/bin/sh
# Tests for changelog-section.sh. Run: scripts/test-changelog-section.sh
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/c.md" <<'MD'
# Changelog

## [Unreleased]

## [0.2.0] - 2026-11-01

### Added
- two

## [0.1.0] - 2026-10-14

### Added
- one
MD
fail() { echo "FAIL: $1" >&2; exit 1; }

out="$("$here/changelog-section.sh" 0.1.0 "$tmp/c.md")"
[ "$out" = "### Added
- one" ] || fail "0.1.0 section: $out"
out="$("$here/changelog-section.sh" v0.2.0 "$tmp/c.md")"
echo "$out" | grep -q '^- two$' || fail "v prefix not accepted"
echo "$out" | grep -q 'one' && fail "0.2.0 leaked into 0.1.0's text"
"$here/changelog-section.sh" 9.9.9 "$tmp/c.md" 2>/dev/null && fail "unknown version accepted"
"$here/changelog-section.sh" Unreleased "$tmp/c.md" 2>/dev/null && fail "empty section accepted"
# the real changelog has notes for the first release
"$here/changelog-section.sh" 0.1.0 "$here/../CHANGELOG.md" >/dev/null || fail "CHANGELOG.md has no 0.1.0 section"
echo "changelog-section: ok"
