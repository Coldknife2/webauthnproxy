#!/bin/sh
# Print the CHANGELOG section of a version (without the leading "v"): scripts/changelog-section.sh 0.1.0
# Fails when the version has no section or the section is empty, so a release cannot be cut without notes.
set -eu
v="${1#v}"
file="${2:-CHANGELOG.md}"
out="$(awk -v v="$v" '
  /^## \[/ { if (on) exit; on = (index($0, "## [" v "]") == 1); next }
  on { print }
' "$file" | sed -e '/./,$!d')"
[ -n "$out" ] || { echo "no CHANGELOG section for $v in $file" >&2; exit 1; }
printf '%s\n' "$out"
