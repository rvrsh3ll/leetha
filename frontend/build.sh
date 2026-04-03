#!/usr/bin/env bash
# Build the React frontend and copy to the Python package dist directory.
set -euo pipefail

cd "$(dirname "$0")"

echo "Installing dependencies..."
bun install

echo "Building React frontend..."
bun run build

echo ""
echo "Build complete. Output: src/leetha/ui/web/dist/"
ls -lh ../src/leetha/ui/web/dist/index.html
echo ""
echo "Assets:"
ls -lh ../src/leetha/ui/web/dist/assets/ | head -10
