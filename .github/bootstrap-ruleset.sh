#!/usr/bin/env bash
#
# bootstrap-ruleset.sh — apply the canonical repository ruleset (.github/ruleset.json)
# to a GitHub repo via the rulesets API. Idempotent: updates an existing ruleset with
# the same name, otherwise creates it.
#
# Run this when creating a new repository or updating repository settings, e.g.:
#   .github/bootstrap-ruleset.sh                  # applies to the current repo
#   .github/bootstrap-ruleset.sh jverneuer/foo    # applies to a specific repo
#
# Requires: gh (authenticated) and jq.

set -euo pipefail

command -v gh >/dev/null 2>&1 || { echo "error: gh CLI is required" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "error: jq is required" >&2; exit 1; }

RULESET_FILE="$(cd "$(dirname "$0")" && pwd)/ruleset.json"
[ -f "$RULESET_FILE" ] || { echo "error: $RULESET_FILE not found" >&2; exit 1; }

REPO="${1:-}"
if [ -z "$REPO" ]; then
  REPO="$(gh repo view --json nameWithOwner -q .nameWithOwner)"
fi

NAME="$(jq -r .name "$RULESET_FILE")"
echo "Applying ruleset \"$NAME\" to $REPO…"

# Find an existing ruleset with this name (update) or create a new one.
EXISTING_ID="$(gh api "repos/$REPO/rulesets" --paginate -q ".[] | select(.name==\"$NAME\") | .id" 2>/dev/null | head -n1 || true)"

if [ -n "$EXISTING_ID" ]; then
  echo "  → updating existing ruleset (id=$EXISTING_ID)"
  gh api -X PUT "repos/$REPO/rulesets/$EXISTING_ID" --input "$RULESET_FILE" >/dev/null
else
  echo "  → creating new ruleset"
  gh api -X POST "repos/$REPO/rulesets" --input "$RULESET_FILE" >/dev/null
fi

echo "Done. \"$NAME\" is active on the default branch of $REPO."
