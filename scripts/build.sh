#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
bash scripts/fetch-sparkle.sh
mkdir -p .build/release
archs=${ARCHS:-$(uname -m)}
for arch in $archs; do
  case "$arch" in arm64|x86_64) ;; *) echo 'Unsupported architecture' >&2; exit 1;; esac
  swiftc -O -parse-as-library -target "$arch-apple-macosx13.0" -module-cache-path .build/clang-cache -F .build/sparkle -framework Sparkle -Xlinker -rpath -Xlinker @executable_path/../Frameworks Sources/CorsoShield/*.swift -o ".build/release/CorsoShield-$arch"
done
APP="$PWD/dist/Corso Shield.app"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Frameworks"
inputs=()
for arch in $archs; do inputs+=(".build/release/CorsoShield-$arch"); done
lipo -create "${inputs[@]}" -output "$APP/Contents/MacOS/CorsoShield"
# ditto preserves Sparkle's required symlinks and helper executable permissions.
ditto .build/sparkle/Sparkle.framework "$APP/Contents/Frameworks/Sparkle.framework"
python3 - <<'PY'
import json, plistlib
from pathlib import Path
c=json.loads(Path('Config/updates.json').read_text())
assert len(__import__('base64').b64decode(c['publicKey'],validate=True)) == 32
assert c['feedURL'].startswith('https://github.com/' + c['repository'] + '/releases/')
p={'CFBundleExecutable':'CorsoShield','CFBundleIdentifier':'local.corso.shield','CFBundleName':'Corso Shield','CFBundlePackageType':'APPL','CFBundleShortVersionString':c['version'],'CFBundleVersion':c['build'],'LSMinimumSystemVersion':'13.0','NSHighResolutionCapable':True,'SUFeedURL':c['feedURL'],'SUPublicEDKey':c['publicKey'],'SUEnableAutomaticChecks':True,'SUAutomaticallyUpdate':False,'SUScheduledCheckInterval':86400,'SUEnableSystemProfiling':False,'SUVerifyUpdateBeforeExtraction':True,'SURequireSignedFeed':True}
with open('dist/Corso Shield.app/Contents/Info.plist','wb') as f: plistlib.dump(p,f)
PY
# Preserve upstream Sparkle helper signatures; sign our outer development bundle.
codesign --force --sign - "$APP"
codesign --verify --deep --strict "$APP"
echo "Built: $APP"
