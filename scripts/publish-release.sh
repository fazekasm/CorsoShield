#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
[ -z "$(git status --porcelain)" ] || { echo 'Commit and push reviewed changes first.' >&2; exit 1; }
git fetch origin main
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] || { echo 'HEAD must match published main.' >&2; exit 1; }
version=$(python3 -c 'import json; print(json.load(open("Config/updates.json"))["version"])')
repo=$(python3 -c 'import json; print(json.load(open("Config/updates.json"))["repository"])')
folder="releases/v$version"
[ -f "$folder/appcast.xml" ] || { echo 'Run prepare-release.sh first.' >&2; exit 1; }
python3 scripts/verify-release.py "$folder"
gh release create "v$version" --repo "$repo" --target "$(git rev-parse HEAD)" --draft --title "Corso Shield $version" --notes-file "release-notes/$version.md" "$folder/CorsoShield-$version.zip" "$folder/appcast.xml"
# Publish only after both the signed feed and archive are attached to the draft.
gh release edit "v$version" --repo "$repo" --draft=false --latest
