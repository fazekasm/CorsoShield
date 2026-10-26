#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
bash scripts/fetch-sparkle.sh
version=$(python3 -c 'import json; print(json.load(open("Config/updates.json"))["version"])')
repo=$(python3 -c 'import json; print(json.load(open("Config/updates.json"))["repository"])')
account=$(python3 -c 'import json; print(json.load(open("Config/updates.json"))["keychainAccount"])')
# Keep the private key in Keychain. Refuse to publish an app with an unrelated key.
public=$(.build/sparkle/bin/generate_keys --account "$account" -p)
expected=$(python3 -c 'import json; print(json.load(open("Config/updates.json"))["publicKey"])')
[ "$public" = "$expected" ] || { echo 'Signing key does not match pinned public key' >&2; exit 1; }
ARCHS='arm64 x86_64' bash scripts/build.sh
bash scripts/test-safety.sh
bash scripts/test-core.sh
folder="$PWD/releases/v$version"
[ ! -e "$folder" ] || { echo 'Release staging directory already exists; inspect it before retrying.' >&2; exit 1; }
mkdir -p "$folder"
/usr/bin/ditto -c -k --sequesterRsrc --keepParent 'dist/Corso Shield.app' "$folder/CorsoShield-$version.zip"
.build/sparkle/bin/generate_appcast --account "$account" --maximum-deltas 0 --download-url-prefix "https://github.com/$repo/releases/download/v$version/" "$folder"
# Verify signatures using the same key; no key material is exported.
.build/sparkle/bin/sign_update --account "$account" --verify "$folder/appcast.xml"
python3 scripts/verify-release.py "$folder"
echo "Prepared signed release: $folder"
