#!/usr/bin/env bash
# Create the labels and issues listed in scripts/issues.json.
#
# Requires: gh (authenticated with write access to the repository) and jq.
# Usage:    scripts/create-issues.sh [owner/repo]
#
# Safe to re-run: labels are created with --force, and an issue is skipped
# if an issue with the same title already exists.
set -euo pipefail

repo="${1:-soroban-advisory-watch/soroban-advisory-watch}"
here="$(cd "$(dirname "$0")" && pwd)"
issues="$here/issues.json"

command -v gh >/dev/null || { echo "gh is required" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }

label() { gh label create "$1" --repo "$repo" --color "$2" --description "$3" --force >/dev/null; }

label "good first issue"   7057ff "Scoped for newcomers"
label "type: feature"      a2eeef "New capability"
label "type: bug"          d73a4a "Something is wrong"
label "type: docs"         0075ca "Documentation"
label "type: research"     fbca04 "Investigation before implementation"
label "type: test"         bfd4f2 "Tests and fuzzing"
label "type: ci"           ededed "CI, release and automation"
label "complexity: low"    c2e0c6 "A few hours"
label "complexity: medium" fef2c0 "A day or two"
label "complexity: high"   f9d0c4 "Several days, design needed"
label "area: core"         1d76db "crates/core"
label "area: cli"          5319e7 "crates/cli"
label "area: data"         0e8a16 "Advisory data, signals, inventories"
label "area: docs"         0052cc "docs/"
label "advisory-data"      0e8a16 "New or corrected advisory record"
label "bug"                d73a4a "Bug report from template"
label "enhancement"        a2eeef "Feature request from template"

existing="$(gh issue list --repo "$repo" --state all --limit 500 --json title --jq '.[].title')"

count="$(jq length "$issues")"
for i in $(seq 0 $((count - 1))); do
  title="$(jq -r ".[$i].title" "$issues")"
  if grep -Fxq "$title" <<<"$existing"; then
    echo "skip   $title"
    continue
  fi
  body="$(jq -r ".[$i].body" "$issues")"
  labels="$(jq -r ".[$i].labels | join(\",\")" "$issues")"
  gh issue create --repo "$repo" --title "$title" --body "$body" --label "$labels" >/dev/null
  echo "create $title"
done
