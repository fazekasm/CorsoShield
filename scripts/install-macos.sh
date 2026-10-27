#!/bin/bash
# Per-user install; never modifies TCC, disables Gatekeeper, or enables scans without setup.
set -euo pipefail
source_app=${1:-"$(cd "$(dirname "$0")/.." && pwd)/dist/Corso Shield.app"}
parent="$HOME/Applications"
target="$parent/Corso Shield.app"
[ -d "$source_app/Contents" ] || { echo 'Provide the verified Corso Shield.app path.' >&2; exit 1; }
[ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$source_app/Contents/Info.plist")" = local.corso.shield ] || { echo 'Unexpected app identity' >&2; exit 1; }
/usr/bin/codesign --verify --deep --strict "$source_app"
[ ! -L "$parent" ] && [ ! -L "$target" ] || { echo 'Linked install paths are refused.' >&2; exit 1; }
mkdir -p "$parent"
# Stop only the registered background service; do not kill a foreground operation.
/bin/launchctl bootout "gui/$(id -u)/local.corso.shield.background" 2>/dev/null || true
if /usr/bin/pgrep -u "$(id -u)" -x CorsoShield >/dev/null; then
  echo 'Quit all Corso Shield app windows/processes, then run this installer again. The background service was stopped; re-enable it after setup.' >&2
  exit 1
fi
stage=$(mktemp -d "$parent/.corso-install.XXXXXX")
trap 'rmdir "$stage" 2>/dev/null || true' EXIT
/usr/bin/ditto "$source_app" "$stage/Corso Shield.app"
/usr/bin/codesign --verify --deep --strict "$stage/Corso Shield.app"
if [ -e "$target" ]; then
  backup="$parent/Corso Shield backup-$(date +%Y%m%d-%H%M%S).app"
  [ ! -e "$backup" ] || { echo 'Backup already exists; retry after reviewing it.' >&2; exit 1; }
  mv "$target" "$backup"
fi
if ! mv "$stage/Corso Shield.app" "$target"; then
  if [ -n "${backup:-}" ] && [ ! -e "$target" ]; then mv "$backup" "$target"; fi
  echo 'Install failed; previous app restored if available.' >&2; exit 1
fi
/usr/bin/open "$target"
echo 'Installed. Complete Permission setup in the app. Full Disk Access requires your approval in System Settings. No background scanning is enabled until the exact installed build has a saved permission review and passes its checks, or you explicitly accept limited coverage.'
