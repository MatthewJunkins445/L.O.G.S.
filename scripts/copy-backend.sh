#!/bin/bash
set -e

# Copy the built binary to where Tauri expects it
mkdir -p src-tauri/binaries

target_triple="${1:-}"
if [ -z "$target_triple" ] && command -v rustc >/dev/null 2>&1; then
    target_triple="$(rustc -vV | awk '/^host:/ { print $2 }')"
fi

if [ -z "$target_triple" ]; then
    cp python-backend/dist/secureshield-backend src-tauri/binaries/
else
    cp python-backend/dist/secureshield-backend "src-tauri/binaries/secureshield-backend-$target_triple"
fi

echo "Backend copied to src-tauri/binaries/"
