#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
archive=.build/Sparkle-2.10.1.tar.xz
expected=1a856d2a9edb8e628de88121d7be04cf0e2167f8641650b78fca00b14244cf27
mkdir -p .build/sparkle
if [ ! -f "$archive" ]; then
  curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 'https://github.com/sparkle-project/Sparkle/releases/download/2.10.1/Sparkle-2.10.1.tar.xz' -o "$archive"
fi
actual=$(shasum -a 256 "$archive" | cut -d ' ' -f 1)
[ "$actual" = "$expected" ] || { echo 'Sparkle checksum mismatch; refusing build.' >&2; exit 1; }
# Re-extract from verified archive rather than trusting a cached framework.
tar -xf "$archive" -C .build/sparkle
